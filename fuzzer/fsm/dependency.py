from __future__ import annotations

from fuzzer.fsm.storage import DependencyEdge
from fuzzer.graphql.schema_types import Operation


SCALAR_TYPES = {"ID", "String", "Int", "Float", "Boolean", "JSON"}


def _clean_type(type_name: str | None) -> str | None:
    if not type_name:
        return None
    return type_name.replace("[", "").replace("]", "").replace("!", "")


def _names_related(type_name: str | None, operation_name: str) -> bool:
    if not type_name:
        return False
    lowered_type = type_name.lower()
    lowered_op = operation_name.lower()
    singular = lowered_type[:-1] if lowered_type.endswith("s") else lowered_type
    return lowered_type in lowered_op or singular in lowered_op


def build_dependency_edges(operation_pool: list[Operation]) -> list[DependencyEdge]:
    """Infer operation producer/consumer edges from GraphQL return and argument types."""
    edges: list[DependencyEdge] = []
    for producer in operation_pool:
        produced_type = _clean_type(producer.return_type)
        if not produced_type or produced_type in SCALAR_TYPES:
            continue
        for consumer in operation_pool:
            if producer.name == consumer.name:
                continue
            for arg in consumer.args:
                if _clean_type(arg.type_name) != "ID":
                    continue
                if _names_related(produced_type, consumer.name) or consumer.operation_type == "mutation":
                    edges.append(
                        DependencyEdge(
                            producer=producer.name,
                            consumer=consumer.name,
                            produced_type=produced_type,
                            required_arg=arg.name,
                        )
                    )
    return edges


def operation_score_for_transition(transition: str, operation: Operation) -> int:
    name = operation.name.lower()
    score = 0
    if "login" in transition:
        score += 10 if any(key in name for key in ["login", "token", "auth", "signin"]) else 0
    if "create" in transition:
        score += 10 if operation.operation_type == "mutation" and any(key in name for key in ["create", "add", "new", "register"]) else 0
    if "update" in transition:
        score += 10 if operation.operation_type == "mutation" and any(key in name for key in ["update", "edit", "change"]) else 0
    if "delete" in transition:
        score += 10 if operation.operation_type == "mutation" and any(key in name for key in ["delete", "remove", "destroy"]) else 0
    if "query" in transition or "resource" in transition:
        score += 4 if operation.operation_type == "query" else 0
    if "protected" in transition:
        score += 6 if operation.auth_required_guess or operation.sensitive_field_guess else 0
    if "injection" in transition:
        score += 6 if operation.args else 0
        score += 4 if any(arg.type_name in {"String", "ID"} for arg in operation.args) else 0
    if "alias" in transition or "nested" in transition or "batch" in transition:
        score += 5 if operation.selectable_fields or operation.nested_fields else 0
    return score
