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
        finding.get("operation"),
        finding.get("transition"),
        finding.get("auth_mode"),
    )


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


# Registry of available fitness functions
FITNESS_FUNCTIONS: dict[str, Callable[[Chromosome], float]] = {
    "default": fitness_default,
    "coverage-only": fitness_coverage_only,
    "state-weight-average": fitness_state_weight_average,
}


def get_fitness_function(name: str) -> Callable[[Chromosome], float]:
    """Look up a fitness function by name. Defaults to 'default' if not found."""
    return FITNESS_FUNCTIONS.get(name, FITNESS_FUNCTIONS["default"])


# Backward compatibility
def calculate_fitness(chromosome: Chromosome) -> float:
    """Deprecated: use get_fitness_function(name)(chromosome) instead."""
    return fitness_default(chromosome)
