from fuzzer.fsm.transitions import TransitionName
from fuzzer.ga.chromosome import Chromosome, Gene
from fuzzer.ga.repair import repair_chromosome
from fuzzer.graphql.schema_types import Operation


def test_valid_token_gene_gets_login_inserted():
    ops = [Operation("login", "mutation"), Operation("me", "query")]
    chrom = Chromosome([Gene(TransitionName.PROTECTED_QUERY_WITH_VALID_TOKEN.value, "me", "valid_token")])
    repaired = repair_chromosome(chrom, ops, 4)
    assert repaired.genes[0].transition == TransitionName.LOGIN_OR_GET_TOKEN.value


def test_resource_transition_gets_setup_create_inserted():
    ops = [Operation("createPost", "mutation"), Operation("post", "query")]
    chrom = Chromosome([Gene(TransitionName.UPDATE_OWN_RESOURCE.value, "post", "valid_token")])
    repaired = repair_chromosome(chrom, ops, 4)
    assert any(g.transition == TransitionName.SETUP_CREATE_RESOURCE.value for g in repaired.genes)


def test_negative_intent_is_preserved():
    ops = [Operation("me", "query")]
    chrom = Chromosome([Gene(TransitionName.PROTECTED_QUERY_WITHOUT_TOKEN.value, "me", "no_token", expected_negative=True)])
    repaired = repair_chromosome(chrom, ops, 4)
    assert repaired.genes[-1].expected_negative is True


def test_duplicate_genes_are_removed_before_execution():
    ops = [Operation("me", "query")]
    gene = Gene(TransitionName.PROTECTED_QUERY_WITHOUT_TOKEN.value, "me", "no_token", expected_negative=True)
    chrom = Chromosome([gene, gene])

    repaired = repair_chromosome(chrom, ops, 4)

    assert len(repaired.genes) == 1
