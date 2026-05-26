from __future__ import annotations

from typing import Any

from fuzzer.ga.chromosome import QueryShape
from fuzzer.graphql.schema_types import Operation


def _var_type(type_name: str, required: bool) -> str:
    return f"{type_name}{'!' if required else ''}"


def _selection(operation: Operation, shape: QueryShape, operation_map: dict[str, Operation] | None = None) -> str:
    fields = list(operation.selectable_fields) or ["__typename"]
    if shape.duplicate_fields > 0:
        fields.extend(fields[:1] * shape.duplicate_fields)
    parts = fields[: max(1, len(fields))]
    if shape.depth > 1 and operation.nested_fields:
        nested_name, nested_type = next(iter(operation.nested_fields.items()))
        nested_op = operation_map.get(nested_type) if operation_map else None
        nested_fields = (nested_op.selectable_fields if nested_op else None) or ["__typename"]
        parts.append(f"{nested_name} {{ {' '.join(nested_fields[:3])} }}")
    return "{ " + " ".join(parts) + " }"


def _single_document(operation: Operation, payload: dict[str, Any], shape: QueryShape, alias_index: int | None = None) -> tuple[str, dict[str, Any]]:
    var_defs = []
    arg_calls = []
    variables: dict[str, Any] = {}
    suffix = "" if alias_index is None else f"_{alias_index}"
    for arg in operation.args:
        var_name = f"{arg.name}{suffix}"
        var_defs.append(f"${var_name}: {_var_type(arg.type_name, arg.required)}")
        arg_calls.append(f"{arg.name}: ${var_name}")
        variables[var_name] = payload.get(arg.name)
    op_kw = operation.operation_type
    var_block = f"({', '.join(var_defs)})" if var_defs else ""
    args_block = f"({', '.join(arg_calls)})" if arg_calls else ""
    alias = f"a{alias_index}: " if alias_index is not None else ""
    selection = "" if operation.return_type in {"String", "Int", "Float", "Boolean", "ID"} else " " + _selection(operation, shape)
    return f"{op_kw} Fuzz{suffix}{var_block} {{ {alias}{operation.name}{args_block}{selection} }}", variables


def build_graphql_document(
    operation: Operation,
    payload: dict[str, Any],
    query_shape: QueryShape,
    operation_map: dict[str, Operation] | None = None,
) -> tuple[str | list[dict[str, Any]], dict[str, Any]]:
    alias_count = max(0, query_shape.alias_count)
    if query_shape.batch:
        batch = []
        for idx in range(max(1, query_shape.batch_size)):
            query, variables = _single_document(operation, payload, query_shape, idx if alias_count else None)
            batch.append({"query": query, "variables": variables})
        return batch, {}
    if alias_count <= 0:
        return _single_document(operation, payload, query_shape)
    queries = []
    variables: dict[str, Any] = {}
    for idx in range(alias_count):
        query, vars_part = _single_document(operation, payload, query_shape, idx)
        inner = query.split("{", 1)[1].rsplit("}", 1)[0].strip()
        queries.append(inner)
        variables.update(vars_part)
    var_defs = []
    for arg in operation.args:
        for idx in range(alias_count):
            var_defs.append(f"${arg.name}_{idx}: {_var_type(arg.type_name, arg.required)}")
    var_block = f"({', '.join(var_defs)})" if var_defs else ""
    return f"{operation.operation_type} FuzzAliases{var_block} {{ {' '.join(queries)} }}", variables
