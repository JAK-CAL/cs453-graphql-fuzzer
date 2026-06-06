from __future__ import annotations

from typing import Any

from fuzzer.config import AppConfig
from fuzzer.fsm.server_model import ServerModel
from fuzzer.fsm.storage import FSMStorage
from fuzzer.fsm.transition_mapper import choose_operation_for_transition
from fuzzer.fsm.transitions import TransitionName
from fuzzer.ga.budget import RequestBudget
from fuzzer.ga.chromosome import QueryShape
from fuzzer.graphql.client import GraphQLClient
from fuzzer.graphql.payloads import payload_for_operation
from fuzzer.graphql.query_builder import build_graphql_document
from fuzzer.graphql.schema_types import Operation


def _first_id(body: Any) -> str | None:
    if isinstance(body, dict):
        for key, value in body.items():
            if key.lower() in {"id", "_id", "uuid"} and value is not None and not isinstance(value, (dict, list)):
                return str(value)
            found = _first_id(value)
            if found:
                return found
    elif isinstance(body, list):
        for item in body:
            found = _first_id(item)
            if found:
                return found
    return None


def bootstrap_surface(
    client: GraphQLClient,
    operations: list[Operation],
    server_model: ServerModel,
    budget: RequestBudget | None,
    config: AppConfig,
    storage: FSMStorage | None = None,
) -> None:
    """Actively probe the live endpoint to seed the observation model.

    Sends a small bounded set of real requests so the FSM bootstraps S1/S2/S3
    from observed behaviour: two distinct sessions (for IDOR / other-resource),
    harvested ids, an owned resource, and learning that a broken op (e.g.
    ``login``) is non-productive. All requests count against ``budget``.
    """
    if not config.ga.surface_probe_enabled or not operations:
        return
    storage = storage or client.storage
    storage.ensure_default_actors()
    type_map = {op.return_type: op for op in operations if op.return_type}
    cap = config.ga.surface_probe_max_requests
    sent = {"n": 0}

    def probe(op: Operation | None, auth_mode: str, actor: str) -> Any:
        if op is None or sent["n"] >= cap:
            return None
        if budget is not None and not budget.can_spend():
            return None
        storage.active_actor = actor
        payload = payload_for_operation(op, storage, None)
        query, variables = build_graphql_document(op, payload, QueryShape(), type_map)
        response = client.execute(query, variables, auth_mode)
        if budget is not None:
            budget.spend()
        sent["n"] += 1
        storage.mark_session_established(actor)
        server_model.observe(response, op.name, auth_mode, actor)
        storage.extract_ids_from_response(response.body)
        return response

    query_op = choose_operation_for_transition(TransitionName.PUBLIC_QUERY.value, operations)
    create_op = choose_operation_for_transition(TransitionName.SETUP_CREATE_RESOURCE.value, operations)
    login_op = choose_operation_for_transition(TransitionName.LOGIN_OR_GET_TOKEN.value, operations)

    # Two distinct sessions -> two auto-assigned identities (IDOR foundation).
    probe(query_op, "valid_token", "default")
    probe(query_op, "low_privilege", "low_privilege")

    # Learn whether a login-style op is productive (it errors twice -> dropped).
    probe(login_op, "no_token", "anonymous")
    probe(login_op, "no_token", "anonymous")

    # Seed an owned resource for the primary session.
    create_resp = probe(create_op, "valid_token", "default")
    if create_resp is not None and create_op is not None:
        resource_id = _first_id(create_resp.body)
        if resource_id:
            server_model.note_resource(create_op.return_type or create_op.name, resource_id, "default")
