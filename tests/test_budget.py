from fuzzer.fsm.executor import execute_chromosome
from fuzzer.fsm.storage import FSMStorage
from fuzzer.fsm.transitions import TransitionName
from fuzzer.ga.budget import RequestBudget
from fuzzer.ga.chromosome import Chromosome, Gene

from tests.test_attacker_fsm_integration import FakeClient, _config, _resource_pool


def test_budget_unbounded_by_default():
    budget = RequestBudget()
    assert not budget.exhausted
    assert budget.can_spend(1000)
    budget.spend(5)
    assert budget.remaining() == float("inf")


def test_budget_caps_spending():
    budget = RequestBudget(total=2)
    assert budget.can_spend()
    budget.spend()
    assert budget.can_spend()
    budget.spend()
    assert budget.exhausted
    assert not budget.can_spend()


def test_executor_stops_at_request_budget():
    pool = _resource_pool()
    genes = [Gene(TransitionName.PUBLIC_QUERY.value, "post", "no_token") for _ in range(5)]
    chrom = Chromosome(genes)
    budget = RequestBudget(total=2)

    execute_chromosome(chrom, FakeClient(), pool, FSMStorage(), _config(), budget=budget)

    assert chrom.total_request_count <= 2
    assert budget.spent <= 2
