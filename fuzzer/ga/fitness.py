from __future__ import annotations

from fuzzer.ga.chromosome import Chromosome


def calculate_fitness(chromosome: Chromosome) -> float:
    total = max(1, chromosome.total_request_count)
    valid_ratio = chromosome.valid_request_count / total
    auth = sum(1 for f in chromosome.findings if "AUTH" in f.get("finding_type", ""))
    injection = sum(1 for f in chromosome.findings if "INJECTION" in f.get("finding_type", ""))
    cost = sum(1 for f in chromosome.findings if "DOS" in f.get("finding_type", "") or "COST" in f.get("finding_type", ""))
    score = (
        1.0 * len(chromosome.visited_states)
        + 1.0 * len(chromosome.visited_transitions)
        + 0.5 * valid_ratio
        + 3.0 * len(chromosome.unique_error_patterns)
        + 8.0 * auth
        + 6.0 * injection
        + 6.0 * cost
        + 10.0 * len(chromosome.findings)
        - 2.0 * chromosome.skipped_transition_count
        - 3.0 * chromosome.unrepaired_invalid_sequence_count
    )
    chromosome.fitness = score
    return score
