from __future__ import annotations

import random

from fuzzer.ga.chromosome import Chromosome


def crossover(parent_a: Chromosome, parent_b: Chromosome, max_len: int) -> Chromosome:
    if not parent_a.genes:
        return Chromosome(parent_b.genes[:max_len])
    if not parent_b.genes:
        return Chromosome(parent_a.genes[:max_len])
    cut_a = random.randint(1, len(parent_a.genes))
    cut_b = random.randint(0, len(parent_b.genes) - 1)
    child = Chromosome((parent_a.genes[:cut_a] + parent_b.genes[cut_b:])[:max_len])
    source = parent_a if parent_a.target_id else parent_b
    child.target_id = source.target_id
    child.target_category = source.target_category
    child.schedule_path = source.schedule_path
    return child
