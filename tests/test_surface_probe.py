from fuzzer.fsm.server_model import ServerModel
from fuzzer.fsm.storage import FSMStorage
from fuzzer.fsm.surface_probe import bootstrap_surface
from fuzzer.ga.budget import RequestBudget

from tests.test_attacker_fsm_integration import FakeClient, _config, _resource_pool


def test_bootstrap_populates_observation_model():
    model = ServerModel()
    storage = FSMStorage()
    client = FakeClient()

    bootstrap_surface(client, _resource_pool(), model, RequestBudget(), _config(), storage)

    assert client.calls > 0
    assert model.responsive_operations
    assert model.harvested_ids


def test_bootstrap_respects_budget():
    model = ServerModel()
    client = FakeClient()
    budget = RequestBudget(total=3)

    bootstrap_surface(client, _resource_pool(), model, budget, _config(), FSMStorage())

    assert client.calls <= 3
    assert budget.spent <= 3


def test_bootstrap_disabled_sends_nothing():
    model = ServerModel()
    client = FakeClient()
    config = _config()
    config.ga.surface_probe_enabled = False

    bootstrap_surface(client, _resource_pool(), model, RequestBudget(), config, FSMStorage())

    assert client.calls == 0
