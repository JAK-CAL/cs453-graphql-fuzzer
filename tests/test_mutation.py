import random

from fuzzer.ga.chromosome import Chromosome, Gene
from fuzzer.ga.mutation import mutate_chromosome
from fuzzer.graphql.schema_types import Operation


def test_mutation_changes_chromosome_eventually():
    random.seed(2)
    op = Operation("user", "query", [], "User", ["id"])
    original = Chromosome([Gene("public_query", "user", "no_token")])
    mutated = mutate_chromosome(original, [op], 5)
    assert mutated.genes
    assert mutated is not original
    assert mutated.genes != original.genes or mutated.genes[0].query_shape != original.genes[0].query_shape
