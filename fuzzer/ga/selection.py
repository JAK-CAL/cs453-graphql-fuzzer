from __future__ import annotations

import random

from fuzzer.ga.chromosome import Chromosome


def select_parent(population: list[Chromosome], tournament_size: int) -> Chromosome:
    competitors = random.sample(population, k=min(max(1, tournament_size), len(population)))
    return max(competitors, key=lambda c: c.fitness)
