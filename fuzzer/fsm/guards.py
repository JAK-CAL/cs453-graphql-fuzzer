from __future__ import annotations

from fuzzer.fsm.capabilities import missing_capabilities
from fuzzer.fsm.storage import FSMStorage
from fuzzer.fsm.transitions import TransitionName
from fuzzer.ga.chromosome import Gene
from fuzzer.graphql.schema_types import Operation

RESOURCE_TRANSITIONS = {
    TransitionName.QUERY_OWN_RESOURCE.value,
    TransitionName.QUERY_OTHER_RESOURCE.value,
    TransitionName.UPDATE_OWN_RESOURCE.value,
    TransitionName.UPDATE_OTHER_RESOURCE.value,
    TransitionName.DELETE_OWN_RESOURCE.value,
    TransitionName.DELETE_OTHER_RESOURCE.value,
}


def _operation_by_name(operation_pool: list[Operation], name: str | None) -> Operation | None:
    return next((op for op in operation_pool if op.name == name), None)


def _has_string_or_id_arg(op: Operation | None) -> bool:
    return bool(op and any(arg.type_name in {"String", "ID"} for arg in op.args))


def _has_nested_shape_surface(op: Operation | None) -> bool:
    return bool(op and (op.selectable_fields or op.nested_fields))


def can_execute_transition(transition: str, gene: Gene, storage: FSMStorage, operation_pool: list[Operation]) -> bool:
    if not operation_pool:
        return False
    if gene.operation_name and gene.operation_name not in {op.name for op in operation_pool}:
        return False
    op = _operation_by_name(operation_pool, gene.operation_name)
    # Storage-derived prerequisites: single source of truth shared with the planner.
    if missing_capabilities(transition, storage):
        return False
    # Operation-surface prerequisites: cannot be synthesized, so they stay inline.
    if transition == TransitionName.INJECTION_PAYLOAD_QUERY.value:
        return _has_string_or_id_arg(op)
    if transition in {TransitionName.ALIAS_AMPLIFIED_QUERY.value, TransitionName.DEEPLY_NESTED_QUERY.value}:
        return _has_nested_shape_surface(op)
    if transition == TransitionName.BATCH_QUERY.value:
        return op is not None
    if transition == TransitionName.METAMORPHIC_COMPARE_AUTH_MODES.value:
        return op is not None and (op.auth_required_guess or op.sensitive_field_guess or bool(storage.known_ids))
    return True
