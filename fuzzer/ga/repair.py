from __future__ import annotations

import copy

from fuzzer.fsm.transitions import TransitionName
from fuzzer.ga.chromosome import Chromosome, Gene
from fuzzer.graphql.schema_types import Operation

RESOURCE_TRANSITIONS = {
    TransitionName.QUERY_OWN_RESOURCE.value,
    TransitionName.QUERY_OTHER_RESOURCE.value,
    TransitionName.UPDATE_OWN_RESOURCE.value,
    TransitionName.UPDATE_OTHER_RESOURCE.value,
    TransitionName.DELETE_OWN_RESOURCE.value,
    TransitionName.DELETE_OTHER_RESOURCE.value,
    TransitionName.QUERY_DELETED_RESOURCE.value,
}


def _find_login_operation(operation_pool: list[Operation]) -> str | None:
    for op in operation_pool:
        if any(key in op.name.lower() for key in ["login", "token", "auth"]):
            return op.name
    return operation_pool[0].name if operation_pool else None


def _find_create_operation(operation_pool: list[Operation]) -> str | None:
    for op in operation_pool:
        if op.operation_type == "mutation" and any(key in op.name.lower() for key in ["create", "add", "new"]):
            return op.name
    for op in operation_pool:
        if op.operation_type == "mutation":
            return op.name
    return operation_pool[0].name if operation_pool else None


def repair_chromosome(chromosome: Chromosome, operation_pool: list[Operation], max_sequence_length: int) -> Chromosome:
    repaired = copy.deepcopy(chromosome)
    has_login = any(g.transition == TransitionName.LOGIN_OR_GET_TOKEN.value for g in repaired.genes)
    needs_login = any(g.auth_mode == "valid_token" for g in repaired.genes)
    if needs_login and not has_login and len(repaired.genes) < max_sequence_length:
        login_op = _find_login_operation(operation_pool)
        repaired.genes.insert(0, Gene(TransitionName.LOGIN_OR_GET_TOKEN.value, login_op, "no_token"))
    has_create = any(g.transition == TransitionName.SETUP_CREATE_RESOURCE.value for g in repaired.genes)
    needs_resource = any(g.transition in RESOURCE_TRANSITIONS for g in repaired.genes)
    if needs_resource and not has_create and len(repaired.genes) < max_sequence_length:
        create_op = _find_create_operation(operation_pool)
        insert_at = 1 if repaired.genes and repaired.genes[0].transition == TransitionName.LOGIN_OR_GET_TOKEN.value else 0
        repaired.genes.insert(insert_at, Gene(TransitionName.SETUP_CREATE_RESOURCE.value, create_op, "valid_token"))
    if len(repaired.genes) > max_sequence_length:
        repaired.genes = repaired.genes[:max_sequence_length]
        repaired.unrepaired_invalid_sequence_count += 1
    return repaired
