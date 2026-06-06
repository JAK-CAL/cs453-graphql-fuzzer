from __future__ import annotations

from enum import Enum

from fuzzer.fsm.storage import FSMStorage
from fuzzer.fsm.transitions import TransitionName


class Capability(str, Enum):
    """A storage-derived attacker capability: something the attacker can currently do.

    The target authenticates via session cookies (a request establishes an
    auto-assigned user), not bearer tokens, so identity is modelled as a
    *session* per actor rather than a token.
    """

    SESSION = "session"                    # the active actor has an established session
    SECONDARY_SESSION = "secondary_session"  # a second, distinct actor session exists
    OWN_RESOURCE = "own_resource"          # the active actor owns an active resource
    OTHER_RESOURCE = "other_resource"      # a different actor owns an active resource
    DELETED_RESOURCE = "deleted_resource"  # a resource in the deleted state exists
    KNOWN_ID = "known_id"                  # at least one id has been observed


# Storage-derived prerequisites per transition. Operation-surface requirements
# (string/ID arg presence, nested-field surface, batch) are NOT modeled here —
# they cannot be synthesized and remain inline in guards.py.
TRANSITION_REQUIREMENTS: dict[str, frozenset[Capability]] = {
    TransitionName.PROTECTED_QUERY_WITH_VALID_TOKEN.value: frozenset({Capability.SESSION}),
    TransitionName.PROTECTED_QUERY_WITH_LOW_PRIVILEGE.value: frozenset({Capability.SECONDARY_SESSION}),
    TransitionName.QUERY_OWN_RESOURCE.value: frozenset({Capability.OWN_RESOURCE}),
    TransitionName.UPDATE_OWN_RESOURCE.value: frozenset({Capability.OWN_RESOURCE}),
    TransitionName.DELETE_OWN_RESOURCE.value: frozenset({Capability.OWN_RESOURCE}),
    TransitionName.QUERY_OTHER_RESOURCE.value: frozenset({Capability.OTHER_RESOURCE}),
    TransitionName.UPDATE_OTHER_RESOURCE.value: frozenset({Capability.OTHER_RESOURCE}),
    TransitionName.DELETE_OTHER_RESOURCE.value: frozenset({Capability.OTHER_RESOURCE}),
    TransitionName.QUERY_DELETED_RESOURCE.value: frozenset({Capability.DELETED_RESOURCE}),
}


def derive_capabilities(storage: FSMStorage) -> set[Capability]:
    """Compute the set of capabilities currently available from storage state."""
    caps: set[Capability] = set()
    if storage.has_session(storage.active_actor):
        caps.add(Capability.SESSION)
    if storage.session_count() >= 2:
        caps.add(Capability.SECONDARY_SESSION)
    if storage.get_resource(owner_actor=storage.active_actor, state="active"):
        caps.add(Capability.OWN_RESOURCE)
    if storage.get_other_resource(storage.active_actor, state="active"):
        caps.add(Capability.OTHER_RESOURCE)
    if storage.get_resource(state="deleted"):
        caps.add(Capability.DELETED_RESOURCE)
    if storage.known_ids:
        caps.add(Capability.KNOWN_ID)
    return caps


def required_capabilities(transition: str) -> frozenset[Capability]:
    return TRANSITION_REQUIREMENTS.get(transition, frozenset())


def missing_capabilities(transition: str, storage: FSMStorage) -> set[Capability]:
    """Capabilities the transition needs but storage does not yet provide."""
    return set(required_capabilities(transition)) - derive_capabilities(storage)
