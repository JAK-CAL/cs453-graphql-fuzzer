from __future__ import annotations

import random

from fuzzer.ga.chromosome import Chromosome


def crossover(parent_a: Chromosome, parent_b: Chromosome, max_len: int) -> Chromosome:
    if not parent_a.genes:
        return _inherit_metadata(Chromosome(parent_b.genes[:max_len]), parent_b)
    if not parent_b.genes:
        return _inherit_metadata(Chromosome(parent_a.genes[:max_len]), parent_a)
    cut_a = random.randint(1, len(parent_a.genes))
    cut_b = random.randint(0, len(parent_b.genes) - 1)
    child = Chromosome((parent_a.genes[:cut_a] + parent_b.genes[cut_b:])[:max_len])
    if parent_a.target_id == parent_b.target_id:
        return _inherit_metadata(child, parent_a)
    return child


def _inherit_metadata(child: Chromosome, parent: Chromosome) -> Chromosome:
    child.target_id = parent.target_id
    child.target_category = parent.target_category
    child.schedule_path = parent.schedule_path
    return child
