from __future__ import annotations

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


def can_execute_transition(transition: str, gene: Gene, storage: FSMStorage, operation_pool: list[Operation]) -> bool:
    if not operation_pool:
        return False
    if gene.operation_name and gene.operation_name not in {op.name for op in operation_pool}:
        return False
    if transition == TransitionName.PROTECTED_QUERY_WITH_VALID_TOKEN.value and not storage.get_token():
        return False
    if transition in RESOURCE_TRANSITIONS and not storage.get_resource(state="active"):
        return False
    if transition == TransitionName.QUERY_DELETED_RESOURCE.value and not storage.get_resource(state="deleted"):
        return False
    if transition == TransitionName.INJECTION_PAYLOAD_QUERY.value:
        op = next((op for op in operation_pool if op.name == gene.operation_name), None)
        return bool(op and op.args)
    return True
