from __future__ import annotations

from typing import Callable

from fuzzer.fsm.states import FSMState
from fuzzer.ga.chromosome import Chromosome


STATE_WEIGHTS: dict[str, float] = {
    FSMState.S0_START.value: 0.0,
    FSMState.S1_SCHEMA_KNOWN.value: 1.0,
    FSMState.S2_SURFACE_MAPPED.value: 2.0,
    FSMState.S3_AUTH_CONTEXT_AVAILABLE.value: 4.0,
    FSMState.S4_OPERATION_SELECTED.value: 3.0,
    FSMState.S5_INPUT_SPACE_PREPARED.value: 4.0,
    FSMState.S6_REQUEST_EXECUTED.value: 6.0,
    FSMState.S7_RESPONSE_CLASSIFIED.value: 7.0,
    FSMState.S8_INTERESTING_BEHAVIOR_FOUND.value: 12.0,
    FSMState.S9_REPRODUCIBLE_FINDING.value: 14.0,
    FSMState.S10_MUTATION_PLANNED.value: 5.0,
    FSMState.S11_RESET.value: 1.0,
}


def _finding_key(finding: dict) -> tuple:
    return (
        finding.get("finding_type"),
        finding.get("target_id"),
        finding.get("operation"),
        _resource_type(finding),
        finding.get("confidence"),
    )


def _resource_type(finding: dict) -> str | None:
    selected = (finding.get("evidence") or {}).get("selected_resource")
    if isinstance(selected, dict):
        return selected.get("resource_type")
    return None


def _repeated_gene_penalty(chromosome: Chromosome) -> float:
    seen: dict[tuple, int] = {}
    for gene in chromosome.genes:
        key = (gene.transition, gene.operation_name, gene.auth_mode)
        seen[key] = seen.get(key, 0) + 1
    repeats = sum(count - 1 for count in seen.values() if count > 1)
    return float(repeats)


def fitness_default(chromosome: Chromosome) -> float:
    """Default fitness function: balanced coverage + findings weighting."""
    total = max(1, chromosome.total_request_count)
    valid_ratio = chromosome.valid_request_count / total
    unique_findings = {_finding_key(f) for f in chromosome.findings}
    auth = sum(1 for f in unique_findings if "AUTH" in str(f[0]))
    injection = sum(1 for f in unique_findings if "INJECTION" in str(f[0]))
    cost = sum(1 for f in unique_findings if "DOS" in str(f[0]) or "COST" in str(f[0]))
    operation_count = len({gene.operation_name for gene in chromosome.genes if gene.operation_name})
    score = (
        1.0 * len(chromosome.visited_states)
        + 1.0 * len(chromosome.visited_transitions)
        + 1.5 * operation_count
        + 0.5 * valid_ratio
        + 3.0 * len(chromosome.unique_error_patterns)
        + 8.0 * auth
        + 6.0 * injection
        + 6.0 * cost
        + 10.0 * len(unique_findings)
        - 2.0 * chromosome.skipped_transition_count
        - 3.0 * chromosome.unrepaired_invalid_sequence_count
    )
    chromosome.fitness = score
    return score


def fitness_coverage_only(chromosome: Chromosome) -> float:
    """Alternative fitness function: prioritize coverage over findings."""
    total = max(1, chromosome.total_request_count)
    valid_ratio = chromosome.valid_request_count / total
    unique_findings = {_finding_key(f) for f in chromosome.findings}
    operation_count = len({gene.operation_name for gene in chromosome.genes if gene.operation_name})
    score = (
        2.0 * len(chromosome.visited_states)
        + 2.0 * len(chromosome.visited_transitions)
        + 2.0 * operation_count
        + 1.0 * valid_ratio
        + 2.0 * len(chromosome.unique_error_patterns)
        + 3.0 * len(unique_findings)
        - 1.0 * chromosome.skipped_transition_count
        - 1.0 * chromosome.unrepaired_invalid_sequence_count
    )
    chromosome.fitness = score
    return score


def fitness_state_weight_average(chromosome: Chromosome) -> float:
    """Average the configured weights of every visited state, including repeats."""
    visits = chromosome.state_visit_history or sorted(chromosome.visited_states)
    if not visits:
        chromosome.fitness = 0.0
        return 0.0
    score = sum(STATE_WEIGHTS.get(state, 0.0) for state in visits) / len(visits)
    chromosome.fitness = score
    return score


def fitness_security_schedule(chromosome: Chromosome) -> float:
    """Fitness for FSM-guided GraphQL security schedule fuzzing.

    This rewards sequences that make stateful security oracles meaningful even
    before they produce a confirmed finding.
    """
    total = max(1, chromosome.total_request_count)
    valid_ratio = chromosome.valid_request_count / total
    unique_findings = {_finding_key(f) for f in chromosome.findings}
    confirmed = sum(1 for f in chromosome.findings if f.get("confidence") == "confirmed")
    probable = sum(1 for f in chromosome.findings if f.get("confidence") == "probable")
    weak = sum(1 for f in chromosome.findings if f.get("confidence") == "weak")
    operations = {gene.operation_name for gene in chromosome.genes if gene.operation_name}
    auth_modes = {gene.auth_mode for gene in chromosome.genes}
    negative_steps = sum(1 for gene in chromosome.genes if gene.expected_negative or gene.auth_mode in {"no_token", "bad_token", "low_privilege"})
    resource_steps = sum(1 for trace in chromosome.execution_trace if trace.get("selected_resource"))
    resolver_reached = sum(1 for trace in chromosome.execution_trace if trace.get("resolver_reached"))
    data_observed = sum(1 for trace in chromosome.execution_trace if trace.get("has_data_key"))
    stateful_findings = sum(1 for f in chromosome.findings if str(f.get("finding_type", "")).startswith("STATEFUL_"))
    target_bonus = 4.0 if chromosome.target_id else 0.0
    repeated_gene_penalty = _repeated_gene_penalty(chromosome)
    score = (
        target_bonus
        + 1.2 * len(chromosome.visited_states)
        + 1.4 * len(chromosome.visited_transitions)
        + 1.5 * len(operations)
        + 1.0 * len(auth_modes)
        + 4.0 * valid_ratio
        + 2.0 * chromosome.positive_fill_count
        + 2.5 * resource_steps
        + 1.5 * resolver_reached
        + 1.0 * data_observed
        + 2.0 * negative_steps
        + 8.0 * len(unique_findings)
        + 12.0 * stateful_findings
        + 10.0 * confirmed
        + 5.0 * probable
        + 1.0 * weak
        - 8.0 * repeated_gene_penalty
        - 2.5 * chromosome.skipped_transition_count
        - 4.0 * chromosome.unrepaired_invalid_sequence_count
    )
    chromosome.fitness = score
    return score


# Registry of available fitness functions
FITNESS_FUNCTIONS: dict[str, Callable[[Chromosome], float]] = {
    "default": fitness_default,
    "coverage-only": fitness_coverage_only,
    "state-weight-average": fitness_state_weight_average,
    "security-schedule": fitness_security_schedule,
}


def get_fitness_function(name: str) -> Callable[[Chromosome], float]:
    """Look up a fitness function by name. Defaults to 'default' if not found."""
    return FITNESS_FUNCTIONS.get(name, FITNESS_FUNCTIONS["default"])


# Backward compatibility
def calculate_fitness(chromosome: Chromosome) -> float:
    """Deprecated: use get_fitness_function(name)(chromosome) instead."""
    return fitness_default(chromosome)
