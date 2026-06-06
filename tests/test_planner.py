from fuzzer.fsm.planner import build_prerequisite_genes
from fuzzer.fsm.storage import FSMStorage
from fuzzer.fsm.transitions import TransitionName
from fuzzer.graphql.schema_types import Argument, Operation


def _pool():
    return [
        Operation("login", "mutation", [Argument("password", "String")], return_type="AuthPayload"),
        Operation("createPost", "mutation", [Argument("title", "String")], return_type="Post"),
        Operation("deletePost", "mutation", [Argument("id", "ID")], return_type="Post"),
        Operation("post", "query", [Argument("id", "ID")], "Post"),
    ]


def _transitions(steps):
    return [step.gene.transition for step in steps]


def test_session_prerequisite_establishes_session_not_login():
    storage = FSMStorage()
    steps = build_prerequisite_genes(TransitionName.PROTECTED_QUERY_WITH_VALID_TOKEN.value, storage, _pool())
    transitions = _transitions(steps)
    assert TransitionName.PUBLIC_QUERY.value in transitions
    assert TransitionName.LOGIN_OR_GET_TOKEN.value not in transitions


def test_own_resource_prerequisite_inserts_session_then_create():
    storage = FSMStorage(active_actor="default")
    steps = build_prerequisite_genes(TransitionName.QUERY_OWN_RESOURCE.value, storage, _pool())
    transitions = _transitions(steps)
    assert TransitionName.SETUP_CREATE_RESOURCE.value in transitions
    assert transitions.index(TransitionName.PUBLIC_QUERY.value) < transitions.index(
        TransitionName.SETUP_CREATE_RESOURCE.value
    )
    create = next(s for s in steps if s.gene.transition == TransitionName.SETUP_CREATE_RESOURCE.value)
    assert create.owner_actor == "default"


def test_other_resource_prerequisite_uses_different_owner():
    storage = FSMStorage(active_actor="default")
    steps = build_prerequisite_genes(TransitionName.QUERY_OTHER_RESOURCE.value, storage, _pool())
    create = next(s for s in steps if s.gene.transition == TransitionName.SETUP_CREATE_RESOURCE.value)
    assert create.owner_actor != "default"


def test_deleted_resource_prerequisite_creates_then_deletes():
    storage = FSMStorage(active_actor="default")
    steps = build_prerequisite_genes(TransitionName.QUERY_DELETED_RESOURCE.value, storage, _pool())
    transitions = _transitions(steps)
    assert TransitionName.SETUP_CREATE_RESOURCE.value in transitions
    assert TransitionName.DELETE_OWN_RESOURCE.value in transitions
    assert transitions.index(TransitionName.SETUP_CREATE_RESOURCE.value) < transitions.index(
        TransitionName.DELETE_OWN_RESOURCE.value
    )


def test_no_prerequisites_when_session_present():
    storage = FSMStorage(active_actor="default")
    storage.mark_session_established("default")
    steps = build_prerequisite_genes(TransitionName.PROTECTED_QUERY_WITH_VALID_TOKEN.value, storage, _pool())
    assert steps == []
