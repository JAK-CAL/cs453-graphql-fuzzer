from __future__ import annotations

from fuzzer.graphql.schema_types import SENSITIVE_KEYWORDS, Argument, Operation

SCALAR_KINDS = {"SCALAR", "ENUM"}
SCALAR_NAMES = {"ID", "String", "Int", "Float", "Boolean"}


def unwrap_type(type_obj: dict | None) -> tuple[str | None, bool]:
    required = False
    current = type_obj
    name = None
    while current:
        if current.get("kind") == "NON_NULL":
            required = True
        if current.get("name"):
            name = current.get("name")
        current = current.get("ofType")
    return name, required


def build_type_map(schema: dict) -> dict[str, dict]:
    return {t["name"]: t for t in schema.get("types", []) if t.get("name")}


def selectable_fields_for_type(type_map: dict[str, dict], type_name: str | None) -> tuple[list[str], dict[str, str]]:
    if not type_name or type_name in SCALAR_NAMES:
        return [], {}
    type_def = type_map.get(type_name) or {}
    scalars: list[str] = []
    nested: dict[str, str] = {}
    for field in type_def.get("fields") or []:
        child_name, _ = unwrap_type(field.get("type"))
        child_def = type_map.get(child_name, {})
        if child_name in SCALAR_NAMES or child_def.get("kind") in SCALAR_KINDS:
            scalars.append(field["name"])
        elif child_name:
            nested[field["name"]] = child_name
    return scalars, nested


def _contains_sensitive(values: list[str]) -> bool:
    haystack = " ".join(values).lower()
    return any(keyword in haystack for keyword in SENSITIVE_KEYWORDS)


def guess_auth_required(operation: Operation) -> bool:
    return _contains_sensitive([operation.name, operation.return_type or "", *operation.selectable_fields])


def build_operation_pool(schema: dict) -> list[Operation]:
    if not schema or schema.get("probe_only"):
        return []
    type_map = build_type_map(schema)
    roots = [
        ("query", (schema.get("queryType") or {}).get("name")),
        ("mutation", (schema.get("mutationType") or {}).get("name")),
    ]
    operations: list[Operation] = []
    for operation_type, root_name in roots:
        root = type_map.get(root_name or "", {})
        for field in root.get("fields") or []:
            return_type, _ = unwrap_type(field.get("type"))
            selectable, nested = selectable_fields_for_type(type_map, return_type)
            args = []
            for arg in field.get("args") or []:
                type_name, required = unwrap_type(arg.get("type"))
                args.append(Argument(arg["name"], type_name or "String", required, arg.get("type")))
            op = Operation(
                name=field["name"],
                operation_type=operation_type,
                args=args,
                return_type=return_type,
                selectable_fields=selectable,
                nested_fields=nested,
            )
            op.sensitive_field_guess = _contains_sensitive([op.name, *(op.selectable_fields or [])])
            op.auth_required_guess = guess_auth_required(op)
            operations.append(op)
    return operations
