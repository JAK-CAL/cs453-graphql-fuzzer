from fuzzer.ga.chromosome import Chromosome, Gene
from fuzzer.runners.fsm_ga import _diverse_survivors, _execution_order


def _chromosome(target_id: str, fitness: float) -> Chromosome:
    chromosome = Chromosome([Gene("public_query", "me", "valid_token")])
    chromosome.target_id = target_id
    chromosome.fitness = fitness
    return chromosome


def test_diverse_survivors_limits_duplicate_targets():
    population = [
        _chromosome("BOLA_UPDATE_DELETE:Post:createPost:updatePost", 100),
        _chromosome("BOLA_UPDATE_DELETE:Post:createPost:updatePost", 99),
        _chromosome("BOLA_UPDATE_DELETE:Comment:createComment:updateComment", 80),
        _chromosome("BOLA_READ:Post:createPost:post", 70),
    ]

    survivors = _diverse_survivors(population, 3)

    assert [chrom.target_id for chrom in survivors] == [
        "BOLA_UPDATE_DELETE:Post:createPost:updatePost",
        "BOLA_UPDATE_DELETE:Comment:createComment:updateComment",
        "BOLA_READ:Post:createPost:post",
    ]


def test_execution_order_prioritizes_unfound_targets():
    found = _chromosome("INJECTION:Post:search", 100)
    unfound = _chromosome("BOPLA_SENSITIVE_FIELD_READ:Post:post:internalNote", 10)

    ordered = _execution_order([found, unfound], {"INJECTION:Post:search"})

    assert [chrom.target_id for chrom in ordered] == [
        "BOPLA_SENSITIVE_FIELD_READ:Post:post:internalNote",
        "INJECTION:Post:search",
    ]


def test_diverse_survivors_keeps_unfound_targets_first():
    found = _chromosome("INJECTION:Post:search", 100)
    unfound = _chromosome("BOPLA_SENSITIVE_FIELD_READ:Post:post:internalNote", 10)

    survivors = _diverse_survivors([found, unfound], 1, {"INJECTION:Post:search"})

    assert [chrom.target_id for chrom in survivors] == [
        "BOPLA_SENSITIVE_FIELD_READ:Post:post:internalNote",
    ]
