from __future__ import annotations

from fuzzer.ga.chromosome import Chromosome


def coverage_summary(chromosomes: list[Chromosome], operation_names: set[str] | None = None) -> dict:
    states: set[str] = set()
    transitions: set[str] = set()
    operations = set(operation_names or set())
    for chrom in chromosomes:
        states.update(chrom.visited_states)
        transitions.update(chrom.visited_transitions)
        operations.update(g.operation_name for g in chrom.genes if g.operation_name)
    return {
        "state_coverage": len(states),
        "transition_coverage": len(transitions),
        "visited_states": sorted(states),
        "visited_transitions": sorted(transitions),
        "operation_coverage": len(operations),
        "visited_operations": sorted(operations),
    }
