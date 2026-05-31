from __future__ import annotations

import re
import time

from fuzzer.config import AppConfig
from fuzzer.fsm.guards import can_execute_transition
from fuzzer.fsm.states import FSMState
from fuzzer.fsm.storage import FSMStorage, ResourceRef
from fuzzer.fsm.transition_mapper import choose_operation_for_transition
from fuzzer.fsm.transitions import TransitionName
from fuzzer.ga.chromosome import Chromosome
from fuzzer.ga.fitness import calculate_fitness
from fuzzer.graphql.client import GraphQLClient
from fuzzer.graphql.payloads import payload_for_operation
from fuzzer.graphql.query_builder import build_graphql_document
from fuzzer.graphql.schema_types import Operation
from fuzzer.oracle.auth import detect_auth_bypass
from fuzzer.oracle.dos import detect_dos
from fuzzer.oracle.error_leakage import detect_error_leakage
from fuzzer.oracle.injection import detect_injection


def _error_signature(text: str) -> str | None:
    match = re.search(r'"message"\s*:\s*"([^"]+)"', text)
    if match:
        return match.group(1)[:120]
    return None


def execute_chromosome(
    chromosome: Chromosome,
    client: GraphQLClient,
    operation_pool: list[Operation],
    storage: FSMStorage,
    config: AppConfig,
    generation: int = 0,
    sequence_id: str = "seq_0000",
) -> Chromosome:
    op_map = {op.name: op for op in operation_pool}
    type_map = {op.return_type: op for op in operation_pool if op.return_type}
    chromosome.visited_states.update({FSMState.S0_START.value, FSMState.S2_SURFACE_MAPPED.value})
    for gene in chromosome.genes:
        operation = op_map.get(gene.operation_name or "") or choose_operation_for_transition(gene.transition, operation_pool)
        if operation is None:
            chromosome.skipped_transition_count += 1
            continue
        gene.operation_name = operation.name
        if not can_execute_transition(gene.transition, gene, storage, operation_pool):
            chromosome.skipped_transition_count += 1
            continue
        chromosome.visited_states.update({FSMState.S4_OPERATION_SELECTED.value, FSMState.S5_INPUT_SPACE_PREPARED.value})
        security_payload = gene.payload.get("__security_payload__")
        payload = payload_for_operation(operation, storage, security_payload if isinstance(security_payload, str) else None)
        payload.update({k: v for k, v in gene.payload.items() if not k.startswith("__")})
        query_or_batch, variables = build_graphql_document(operation, payload, gene.query_shape, type_map)
        response = client.execute(query_or_batch, variables, gene.auth_mode)
        chromosome.total_request_count += 1
        chromosome.visited_states.add(FSMState.S6_REQUEST_EXECUTED.value)
        chromosome.visited_transitions.add(gene.transition)
        if response.status_code and response.status_code < 500 and not response.timeout:
            chromosome.valid_request_count += 1
        sig = _error_signature(response.text)
        if sig:
            chromosome.unique_error_patterns.add(sig)
        storage.extract_ids_from_response(response.body)
        if gene.transition == TransitionName.LOGIN_OR_GET_TOKEN.value and storage.valid_tokens == []:
            storage.add_token("default", "placeholder-token")
        if gene.transition == TransitionName.SETUP_CREATE_RESOURCE.value and storage.known_ids:
            storage.add_resource(ResourceRef(operation.return_type or operation.name, next(iter(storage.known_ids)), storage.active_actor))
        if gene.transition.startswith("delete"):
            resource = storage.get_resource()
            if resource:
                resource.state = "deleted"
        findings: list[dict] = []
        findings.extend(detect_auth_bypass(response, sequence_id, generation, operation.name, gene.transition, gene.auth_mode, gene.expected_negative))
        findings.extend(detect_error_leakage(response, sequence_id, generation, operation.name, gene.transition, gene.auth_mode))
        findings.extend(detect_injection(response, payload, sequence_id, generation, operation.name, gene.transition, gene.auth_mode))
        findings.extend(detect_dos(response, gene.query_shape, sequence_id, generation, operation.name, gene.transition, gene.auth_mode))
        chromosome.findings.extend(findings)
        chromosome.visited_states.add(FSMState.S7_RESPONSE_CLASSIFIED.value)
        if findings:
            chromosome.visited_states.add(FSMState.S8_INTERESTING_BEHAVIOR_FOUND.value)
        if config.execution.request_delay_ms > 0:
            time.sleep(config.execution.request_delay_ms / 1000)
    calculate_fitness(chromosome)
    return chromosome
