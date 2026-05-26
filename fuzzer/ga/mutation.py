from __future__ import annotations

import copy
import random

from fuzzer.ga.chromosome import Chromosome
from fuzzer.ga.population import AUTH_MODES, random_gene
from fuzzer.graphql.payloads import SECURITY_PAYLOADS
from fuzzer.graphql.schema_types import Operation


def mutate_chromosome(chromosome: Chromosome, operation_pool: list[Operation], max_len: int, limits=None) -> Chromosome:
    mutated = copy.deepcopy(chromosome)
    if not mutated.genes:
        mutated.genes.append(random_gene(operation_pool))
        return mutated
    actions = ["sequence", "auth", "payload", "shape"]
    action = random.choice(actions)
    idx = random.randrange(len(mutated.genes))
    if action == "sequence":
        op = random.choice(["insert", "delete", "replace", "duplicate", "reorder"])
        if op == "insert" and len(mutated.genes) < max_len:
            mutated.genes.insert(idx, random_gene(operation_pool))
        elif op == "delete" and len(mutated.genes) > 1:
            del mutated.genes[idx]
        elif op == "replace":
            mutated.genes[idx] = random_gene(operation_pool)
        elif op == "duplicate" and len(mutated.genes) < max_len:
            mutated.genes.insert(idx, copy.deepcopy(mutated.genes[idx]))
        elif op == "reorder" and len(mutated.genes) > 2:
            window = mutated.genes[max(0, idx - 1) : min(len(mutated.genes), idx + 2)]
            random.shuffle(window)
            mutated.genes[max(0, idx - 1) : max(0, idx - 1) + len(window)] = window
    elif action == "auth":
        current = mutated.genes[idx].auth_mode
        choices = [mode for mode in AUTH_MODES if mode != current]
        mutated.genes[idx].auth_mode = random.choice(choices)
    elif action == "payload":
        mutated.genes[idx].payload["__security_payload__"] = random.choice(SECURITY_PAYLOADS + [None, 12345, False])
    elif action == "shape":
        shape = mutated.genes[idx].query_shape
        max_depth = getattr(limits, "max_query_depth", 4)
        max_alias = getattr(limits, "max_alias_count", 10)
        max_dup = getattr(limits, "max_duplicate_fields", 5)
        max_batch = getattr(limits, "max_batch_size", 3)
        shape.depth = min(max_depth, shape.depth + random.randint(0, 1))
        shape.alias_count = min(max_alias, max(1, shape.alias_count + 1))
        shape.duplicate_fields = min(max_dup, shape.duplicate_fields + 1)
        if random.random() < 0.5:
            shape.batch = True
            shape.batch_size = min(max_batch, max(2, shape.batch_size + 1))
    return mutated
