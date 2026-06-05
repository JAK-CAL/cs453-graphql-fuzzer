from __future__ import annotations

import re
import time

from fuzzer.config import AppConfig
from fuzzer.fsm.dependency import build_dependency_edges
from fuzzer.fsm.guards import can_execute_transition
from fuzzer.fsm.planner import build_prerequisite_genes
from fuzzer.fsm.states import FSMState
from fuzzer.fsm.storage import FSMStorage, ResourceRef
from fuzzer.fsm.transition_mapper import choose_operation_for_transition
from fuzzer.fsm.transitions import TransitionName
from fuzzer.ga.chromosome import Chromosome, Gene
from fuzzer.ga.fitness import get_fitness_function
from fuzzer.graphql.client import GraphQLClient
from fuzzer.graphql.payloads import payload_for_operation
from fuzzer.graphql.query_builder import build_graphql_document
from fuzzer.graphql.schema_types import Operation
from fuzzer.oracle.auth import detect_auth_bypass
from fuzzer.oracle.dos import detect_dos
from fuzzer.oracle.error_leakage import detect_error_leakage
from fuzzer.oracle.injection import detect_injection
from fuzzer.security.stateful_oracle import classify_stateful_findings


def _extract_first_id(response_body) -> str | None:
    if isinstance(response_body, dict):
        for key, value in response_body.items():
            if key.lower() in {"id", "_id", "uuid"} and value is not None:
                return str(value)
            found = _extract_first_id(value)
            if found:
                return found
    elif isinstance(response_body, list):
        for item in response_body:
            found = _extract_first_id(item)
            if found:
                return found
    return None


def _resource_payload_override(transition: str, payload: dict, storage: FSMStorage) -> ResourceRef | None:
    resource = None
    if transition in {TransitionName.QUERY_DELETED_RESOURCE.value}:
        resource = storage.get_resource(state="deleted")
    elif transition in {
        TransitionName.QUERY_OTHER_RESOURCE.value,
        TransitionName.UPDATE_OTHER_RESOURCE.value,
        TransitionName.DELETE_OTHER_RESOURCE.value,
    }:
        resource = storage.get_other_resource(storage.active_actor, state="active")
    elif transition in {
        TransitionName.QUERY_OWN_RESOURCE.value,
        TransitionName.UPDATE_OWN_RESOURCE.value,
        TransitionName.DELETE_OWN_RESOURCE.value,
    }:
        resource = storage.get_resource(owner_actor=storage.active_actor, state="active")

    if resource is None:
        return None
    for key in list(payload):
        if "id" in key.lower():
            payload[key] = resource.id
    return resource


def _error_signature(text: str) -> str | None:
    match = re.search(r'"message"\s*:\s*"([^"]+)"', text)
    if match:
        return match.group(1)[:120]
    return None


def _has_data_key(body) -> bool:
    return isinstance(body, dict) and "data" in body


def _resolver_reached(body) -> bool:
    if not isinstance(body, dict):
        return False
    if _has_data_key(body):
        return True
    errors = body.get("errors")
    if isinstance(errors, list):
        return any(isinstance(error, dict) and error.get("path") for error in errors)
    return False


def _run_gene(
    chromosome: Chromosome,
    gene: Gene,
    operation: Operation,
    client: GraphQLClient,
    storage: FSMStorage,
    type_map: dict,
    config: AppConfig,
    generation: int,
    sequence_id: str,
    run_oracles: bool,
    server_model=None,
    budget=None,
) -> None:
    """Execute a single gene as a GraphQL request and update storage.

    When ``run_oracles`` is False the gene is treated as a positive setup step:
    it still updates storage (ids, sessions, resources) but is not classified by
    the oracles. The caller is responsible for setting ``storage.active_actor``.
    A ``budget`` (if given) bounds the total requests; an exhausted budget makes
    this a no-op. ``server_model`` accumulates run-scoped observations.
    """
    if budget is not None and not budget.can_spend():
        return
    chromosome.visit_state(FSMState.S4_OPERATION_SELECTED.value)
    chromosome.visit_state(FSMState.S5_INPUT_SPACE_PREPARED.value)
    security_payload = gene.payload.get("__security_payload__")
    payload = payload_for_operation(operation, storage, security_payload if isinstance(security_payload, str) else None)
    selected_resource = _resource_payload_override(gene.transition, payload, storage)
    payload.update({k: v for k, v in gene.payload.items() if not k.startswith("__")})
    query_or_batch, variables = build_graphql_document(operation, payload, gene.query_shape, type_map)
    response = client.execute(query_or_batch, variables, gene.auth_mode)
    if budget is not None:
        budget.spend()
    chromosome.total_request_count += 1
    chromosome.visit_state(FSMState.S6_REQUEST_EXECUTED.value)
    chromosome.visited_transitions.add(gene.transition)
    # Any request establishes a session for the active actor (the target assigns
    # an auto-identity via session cookie), so record it as authenticated context.
    storage.mark_session_established(storage.active_actor)
    if server_model is not None:
        server_model.observe(response, operation.name, gene.auth_mode, storage.active_actor)
    chromosome.execution_trace.append(
        {
            "actor": storage.active_actor,
            "operation": operation.name,
            "transition": gene.transition,
            "auth_mode": gene.auth_mode,
            "expected_negative": gene.expected_negative,
            "status_code": response.status_code,
            "timeout": response.timeout,
            "has_data_key": _has_data_key(response.body),
            "resolver_reached": _resolver_reached(response.body),
            "selected_resource": {
                "resource_type": selected_resource.resource_type,
                "id": selected_resource.id,
                "owner_actor": selected_resource.owner_actor,
                "state": selected_resource.state,
            }
            if selected_resource
            else None,
            "body": response.body,
        }
    )
    if response.status_code and response.status_code < 500 and not response.timeout:
        chromosome.valid_request_count += 1
    sig = _error_signature(response.text)
    if sig:
        chromosome.unique_error_patterns.add(sig)
    storage.extract_ids_from_response(response.body)
    if gene.transition == TransitionName.LOGIN_OR_GET_TOKEN.value:
        storage.ensure_default_actors()
    if gene.transition == TransitionName.SETUP_CREATE_RESOURCE.value and storage.known_ids:
        resource_id = _extract_first_id(response.body) or next(iter(storage.known_ids))
        storage.add_resource(ResourceRef(operation.return_type or operation.name, resource_id, storage.active_actor))
        if server_model is not None:
            server_model.note_resource(operation.return_type or operation.name, resource_id, storage.active_actor)
    if gene.transition.startswith("delete"):
        storage.mark_resource_deleted(selected_resource)
    if run_oracles:
        findings: list[dict] = []
        findings.extend(detect_auth_bypass(response, sequence_id, generation, operation.name, gene.transition, gene.auth_mode, gene.expected_negative))
        findings.extend(detect_error_leakage(response, sequence_id, generation, operation.name, gene.transition, gene.auth_mode))
        findings.extend(detect_injection(response, payload, sequence_id, generation, operation.name, gene.transition, gene.auth_mode))
        findings.extend(detect_dos(response, gene.query_shape, sequence_id, generation, operation.name, gene.transition, gene.auth_mode))
        chromosome.findings.extend(findings)
        chromosome.visit_state(FSMState.S7_RESPONSE_CLASSIFIED.value)
        if findings and (budget is None or budget.can_spend()):
            chromosome.visit_state(FSMState.S8_INTERESTING_BEHAVIOR_FOUND.value)
            replay = client.execute(query_or_batch, variables, gene.auth_mode)
            if budget is not None:
                budget.spend()
            replay_findings: list[dict] = []
            replay_findings.extend(detect_auth_bypass(replay, sequence_id, generation, operation.name, gene.transition, gene.auth_mode, gene.expected_negative))
            replay_findings.extend(detect_error_leakage(replay, sequence_id, generation, operation.name, gene.transition, gene.auth_mode))
            replay_findings.extend(detect_injection(replay, payload, sequence_id, generation, operation.name, gene.transition, gene.auth_mode))
            replay_findings.extend(detect_dos(replay, gene.query_shape, sequence_id, generation, operation.name, gene.transition, gene.auth_mode))
            if replay_findings:
                chromosome.visit_state(FSMState.S9_REPRODUCIBLE_FINDING.value)
                for finding in findings:
                    finding["reproduced"] = True
    if config.execution.request_delay_ms > 0:
        time.sleep(config.execution.request_delay_ms / 1000)


def _fill_prerequisites(
    chromosome: Chromosome,
    transition: str,
    operation_pool: list[Operation],
    op_map: dict,
    client: GraphQLClient,
    storage: FSMStorage,
    type_map: dict,
    config: AppConfig,
    generation: int,
    sequence_id: str,
    fill_cap: int,
    target_actor: str,
    server_model=None,
    budget=None,
) -> None:
    """Run positive transitions that establish the capabilities ``transition`` needs."""
    steps = build_prerequisite_genes(transition, storage, operation_pool, target_actor)
    for step in steps:
        if chromosome.positive_fill_count >= fill_cap:
            break
        if budget is not None and budget.exhausted:
            break
        pre_op = op_map.get(step.gene.operation_name or "") or choose_operation_for_transition(
            step.gene.transition, operation_pool, server_model
        )
        if pre_op is None:
            continue
        step.gene.operation_name = pre_op.name
        storage.ensure_default_actors()
        storage.active_actor = step.owner_actor
        _run_gene(
            chromosome, step.gene, pre_op, client, storage, type_map, config, generation, sequence_id,
            run_oracles=False, server_model=server_model, budget=budget,
        )
        chromosome.positive_fill_count += 1


def execute_chromosome(
    chromosome: Chromosome,
    client: GraphQLClient,
    operation_pool: list[Operation],
    storage: FSMStorage,
    config: AppConfig,
    generation: int = 0,
    sequence_id: str = "seq_0000",
    server_model=None,
    budget=None,
) -> Chromosome:
    op_map = {op.name: op for op in operation_pool}
    type_map = {op.return_type: op for op in operation_pool if op.return_type}
    storage.ensure_default_actors()
    if not storage.dependency_edges:
        storage.set_dependency_edges(build_dependency_edges(operation_pool))
    if server_model is not None:
        server_model.seed_storage(storage, allow_instance=not config.execution.reset_between_chromosomes)
    chromosome.visit_state(FSMState.S0_START.value)
    chromosome.visit_state(FSMState.S1_SCHEMA_KNOWN.value)
    chromosome.visit_state(FSMState.S2_SURFACE_MAPPED.value)
    chromosome.visit_state(FSMState.S3_AUTH_CONTEXT_AVAILABLE.value)
    fill_cap = config.limits.max_sequence_length
    for gene in chromosome.genes:
        if budget is not None and budget.exhausted:
            break
        operation = op_map.get(gene.operation_name or "") or choose_operation_for_transition(gene.transition, operation_pool, server_model)
        if operation is None:
            chromosome.skipped_transition_count += 1
            continue
        gene.operation_name = operation.name
        storage.active_actor = storage.actor_for_auth_mode(gene.auth_mode)
        target_actor = storage.active_actor
        if not can_execute_transition(gene.transition, gene, storage, operation_pool):
            # Blocked: synthesize and run the positive transitions that build the
            # missing capabilities, then retry the original attack.
            _fill_prerequisites(
                chromosome, gene.transition, operation_pool, op_map, client, storage,
                type_map, config, generation, sequence_id, fill_cap, target_actor,
                server_model=server_model, budget=budget,
            )
            # Filling mutated active_actor; restore the original gene's actor.
            storage.active_actor = target_actor
            if not can_execute_transition(gene.transition, gene, storage, operation_pool):
                chromosome.skipped_transition_count += 1
                continue
        _run_gene(
            chromosome, gene, operation, client, storage, type_map, config, generation, sequence_id,
            run_oracles=True, server_model=server_model, budget=budget,
        )
    chromosome.findings.extend(classify_stateful_findings(chromosome, sequence_id, generation))
    fitness_fn = get_fitness_function(config.ga.fitness_function)
    fitness_fn(chromosome)
    return chromosome
