from __future__ import annotations

from fuzzer.ga.chromosome import Chromosome


def _finding_key(finding: dict) -> tuple:
    return (
        finding.get("finding_type"),
        finding.get("operation"),
        finding.get("transition"),
        finding.get("auth_mode"),
    )


def calculate_fitness(chromosome: Chromosome) -> float:
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
