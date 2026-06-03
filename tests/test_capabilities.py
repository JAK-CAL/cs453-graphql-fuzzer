from fuzzer.fsm.capabilities import (
    Capability,
    derive_capabilities,
    missing_capabilities,
)
from fuzzer.fsm.storage import Actor, FSMStorage, ResourceRef
from fuzzer.fsm.transitions import TransitionName


def test_empty_storage_has_no_capabilities():
    assert derive_capabilities(FSMStorage()) == set()


def test_session_capability_after_request():
    storage = FSMStorage(active_actor="default")
    storage.mark_session_established("default")

    assert Capability.SESSION in derive_capabilities(storage)


def test_secondary_session_capability_with_two_sessions():
    storage = FSMStorage(active_actor="default")
    storage.mark_session_established("default")
    assert Capability.SECONDARY_SESSION not in derive_capabilities(storage)

    storage.mark_session_established("low_privilege")
    assert Capability.SECONDARY_SESSION in derive_capabilities(storage)


def test_own_and_other_resource_capabilities():
    storage = FSMStorage(active_actor="userA")
    storage.actors["userA"] = Actor("userA")
    storage.add_resource(ResourceRef("Post", "1", owner_actor="userA"))

    caps = derive_capabilities(storage)
    assert Capability.OWN_RESOURCE in caps
    assert Capability.OTHER_RESOURCE not in caps

    storage.add_resource(ResourceRef("Post", "2", owner_actor="userB"))
    assert Capability.OTHER_RESOURCE in derive_capabilities(storage)


def test_deleted_resource_capability():
    storage = FSMStorage(active_actor="userA")
    storage.add_resource(ResourceRef("Post", "1", owner_actor="userA"))
    assert Capability.DELETED_RESOURCE not in derive_capabilities(storage)

    storage.mark_resource_deleted()
    assert Capability.DELETED_RESOURCE in derive_capabilities(storage)


def test_missing_capabilities_for_own_resource_query():
    missing = missing_capabilities(TransitionName.QUERY_OWN_RESOURCE.value, FSMStorage())
    assert missing == {Capability.OWN_RESOURCE}


def test_no_requirements_for_public_query():
    assert missing_capabilities(TransitionName.PUBLIC_QUERY.value, FSMStorage()) == set()
