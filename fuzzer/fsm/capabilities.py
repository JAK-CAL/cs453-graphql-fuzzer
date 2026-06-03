from __future__ import annotations

from enum import Enum

from fuzzer.fsm.storage import FSMStorage
from fuzzer.fsm.transitions import TransitionName


class Capability(str, Enum):
    """A storage-derived attacker capability: something the attacker can currently do."""

    VALID_TOKEN = "valid_token"          # a valid auth token is held by some actor
    LOW_PRIV_TOKEN = "low_priv_token"    # a low-privilege actor/token is available
    OWN_RESOURCE = "own_resource"        # the active actor owns an active resource
    OTHER_RESOURCE = "other_resource"    # a different actor owns an active resource
    DELETED_RESOURCE = "deleted_resource"  # a resource in the deleted state exists
    KNOWN_ID = "known_id"                # at least one id has been extracted
    MULTIPLE_ACTORS = "multiple_actors"  # two or more actors are known


# Storage-derived prerequisites per transition. Operation-surface requirements
# (string/ID arg presence, nested-field surface, batch) are NOT modeled here —
# they cannot be synthesized and remain inline in guards.py.
TRANSITION_REQUIREMENTS: dict[str, frozenset[Capability]] = {
    TransitionName.PROTECTED_QUERY_WITH_VALID_TOKEN.value: frozenset({Capability.VALID_TOKEN}),
    TransitionName.PROTECTED_QUERY_WITH_LOW_PRIVILEGE.value: frozenset({Capability.LOW_PRIV_TOKEN}),
    TransitionName.QUERY_OWN_RESOURCE.value: frozenset({Capability.OWN_RESOURCE}),
    TransitionName.UPDATE_OWN_RESOURCE.value: frozenset({Capability.OWN_RESOURCE}),
    TransitionName.DELETE_OWN_RESOURCE.value: frozenset({Capability.OWN_RESOURCE}),
    TransitionName.QUERY_OTHER_RESOURCE.value: frozenset({Capability.OTHER_RESOURCE}),
    TransitionName.UPDATE_OTHER_RESOURCE.value: frozenset({Capability.OTHER_RESOURCE}),
    TransitionName.DELETE_OTHER_RESOURCE.value: frozenset({Capability.OTHER_RESOURCE}),
    TransitionName.QUERY_DELETED_RESOURCE.value: frozenset({Capability.DELETED_RESOURCE}),
}


# Each fillable capability maps to the positive transition that establishes it.
CAPABILITY_PRODUCERS: dict[Capability, str] = {
    Capability.VALID_TOKEN: TransitionName.LOGIN_OR_GET_TOKEN.value,
    Capability.LOW_PRIV_TOKEN: TransitionName.LOGIN_OR_GET_TOKEN.value,
    Capability.KNOWN_ID: TransitionName.SETUP_CREATE_RESOURCE.value,
    Capability.OWN_RESOURCE: TransitionName.SETUP_CREATE_RESOURCE.value,
    Capability.OTHER_RESOURCE: TransitionName.SETUP_CREATE_RESOURCE.value,
    Capability.DELETED_RESOURCE: TransitionName.DELETE_OWN_RESOURCE.value,
}


def derive_capabilities(storage: FSMStorage) -> set[Capability]:
    """Compute the set of capabilities currently available from storage state."""
    caps: set[Capability] = set()
    if storage.get_token() or storage.valid_tokens:
        caps.add(Capability.VALID_TOKEN)
    if storage.get_token("low_privilege") or len(storage.actors) >= 2:
        caps.add(Capability.LOW_PRIV_TOKEN)
    if storage.get_resource(owner_actor=storage.active_actor, state="active"):
        caps.add(Capability.OWN_RESOURCE)
    if storage.get_other_resource(storage.active_actor, state="active"):
        caps.add(Capability.OTHER_RESOURCE)
    if storage.get_resource(state="deleted"):
        caps.add(Capability.DELETED_RESOURCE)
    if storage.known_ids:
        caps.add(Capability.KNOWN_ID)
    if len(storage.actors) >= 2:
        caps.add(Capability.MULTIPLE_ACTORS)
    return caps


def required_capabilities(transition: str) -> frozenset[Capability]:
    return TRANSITION_REQUIREMENTS.get(transition, frozenset())


def missing_capabilities(transition: str, storage: FSMStorage) -> set[Capability]:
    """Capabilities the transition needs but storage does not yet provide."""
    return set(required_capabilities(transition)) - derive_capabilities(storage)
