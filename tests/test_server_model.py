from fuzzer.fsm.server_model import ServerModel
from fuzzer.fsm.storage import FSMStorage
from fuzzer.graphql.client import GraphQLResponse


def _resp(status, body):
    return GraphQLResponse(status, body, str(body), 1.0, 64, False)


def test_observe_learns_public_operation_returns_data():
    model = ServerModel()
    model.observe(_resp(200, {"data": {"me": {"id": "7"}}}), "me", "no_token", "anonymous")
    assert "me" in model.responsive_operations
    assert model.is_auth_required("me") is False
    assert "7" in model.harvested_ids


def test_observe_learns_auth_required_when_anonymous_errors():
    model = ServerModel()
    model.observe(_resp(200, {"errors": [{"message": "must be logged in"}]}), "secret", "no_token", "anonymous")
    assert model.is_auth_required("secret") is True


def test_repeated_errors_mark_operation_nonproductive():
    model = ServerModel()
    err = {"errors": [{"message": "Given username does not exist"}]}
    model.observe(_resp(200, err), "login", "no_token", "anonymous")
    assert not model.is_nonproductive("login")
    model.observe(_resp(200, err), "login", "no_token", "anonymous")
    assert model.is_nonproductive("login")


def test_data_response_rescues_from_nonproductive():
    model = ServerModel()
    err = {"errors": [{"message": "x"}]}
    model.observe(_resp(200, err), "post", "no_token", "anonymous")
    model.observe(_resp(200, err), "post", "no_token", "anonymous")
    assert model.is_nonproductive("post")
    model.observe(_resp(200, {"data": {"post": {"id": "1"}}}), "post", "valid_token", "default")
    assert not model.is_nonproductive("post")


def test_null_data_with_errors_is_not_productive():
    # GraphQL returns data:{field:null} alongside errors when a resolver throws
    # (e.g. the broken `login`); this must not count as productive data.
    model = ServerModel()
    body = {"data": {"login": None}, "errors": [{"message": "Given username does not exist"}]}
    model.observe(_resp(200, body), "login", "no_token", "anonymous")
    model.observe(_resp(200, body), "login", "no_token", "anonymous")
    assert "login" not in model.responsive_operations
    assert model.is_nonproductive("login")


def test_rate_limit_observed():
    model = ServerModel()
    model.observe(_resp(429, None), "anything", "no_token", "anonymous")
    assert model.rate_limited is True


def test_seed_storage_carries_resources_only_when_allowed():
    model = ServerModel()
    model.note_resource("Post", "42", "default")

    blocked = FSMStorage()
    model.seed_storage(blocked, allow_instance=False)
    assert blocked.known_ids == set()

    allowed = FSMStorage(active_actor="default")
    model.seed_storage(allowed, allow_instance=True)
    assert "42" in allowed.known_ids
    assert allowed.get_resource(owner_actor="default", state="active") is not None
