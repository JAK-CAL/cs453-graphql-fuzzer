from __future__ import annotations

from fuzzer.fsm.dependency import operation_score_for_transition
from fuzzer.fsm.transitions import TransitionName
from fuzzer.graphql.schema_types import Operation


def choose_operation_for_transition(transition: str, operation_pool: list[Operation], server_model=None) -> Operation | None:
    if not operation_pool:
        return None
    # Drop operations the server has shown to be non-productive (e.g. a `login`
    # that always errors) so selection adapts to observed behaviour.
    if server_model is not None:
        filtered = [op for op in operation_pool if not server_model.is_nonproductive(op.name)]
        operation_pool = filtered or operation_pool
    if transition == TransitionName.LOGIN_OR_GET_TOKEN.value:
        for op in operation_pool:
            if any(key in op.name.lower() for key in ["login", "token", "auth"]):
                return op
    if transition == TransitionName.SETUP_CREATE_RESOURCE.value:
        for op in operation_pool:
            if op.operation_type == "mutation" and any(key in op.name.lower() for key in ["create", "add", "new"]):
                return op
    if "protected" in transition:
        for op in operation_pool:
            if op.auth_required_guess or op.sensitive_field_guess:
                return op
    if "injection" in transition:
        for op in operation_pool:
            if any(arg.type_name in {"String", "ID"} for arg in op.args):
                return op
    ranked = sorted(operation_pool, key=lambda op: operation_score_for_transition(transition, op), reverse=True)
    if ranked and operation_score_for_transition(transition, ranked[0]) > 0:
        return ranked[0]
    return None
