from __future__ import annotations

from dataclasses import dataclass

from fuzzer.fsm.capabilities import CAPABILITY_PRODUCERS, Capability, missing_capabilities
from fuzzer.fsm.storage import FSMStorage
from fuzzer.fsm.transition_mapper import choose_operation_for_transition
from fuzzer.fsm.transitions import TransitionName
from fuzzer.ga.chromosome import Gene
from fuzzer.graphql.schema_types import Operation

MAX_FILL_DEPTH = 3


@dataclass
class PrereqStep:
    """A synthesized positive transition to run, with the actor that should own its effect."""

    gene: Gene
    owner_actor: str


def _auth_mode_for_owner(owner_actor: str) -> str:
    """Pick an auth mode that deterministically resolves to ``owner_actor``.

    ``actor_for_auth_mode`` maps ``low_privilege`` -> ``low_privilege`` and, for
    ``valid_token``, preserves a non-anonymous active actor (falling back to
    ``default``). Choosing the mode by owner keeps ownership stable even though
    the GraphQL client re-derives the active actor on each request.
    """
    if owner_actor == "low_privilege":
        return "low_privilege"
    return "valid_token"


def _other_owner(target_actor: str) -> str:
    """Pick an actor distinct from the target so created resources are 'other-owned'."""
    return "default" if target_actor == "low_privilege" else "low_privilege"


def _make_step(transition: str, owner_actor: str, auth_mode: str, operation_pool: list[Operation]) -> PrereqStep | None:
    op: Operation | None = choose_operation_for_transition(transition, operation_pool)
    if op is None:
        return None
    return PrereqStep(gene=Gene(transition, op.name, auth_mode), owner_actor=owner_actor)


def _resolve_capability(
    capability: Capability,
    target_actor: str,
    operation_pool: list[Operation],
    depth: int,
) -> list[PrereqStep]:
    """Build the ordered prerequisite steps that establish a single capability."""
    if depth >= MAX_FILL_DEPTH:
        return []
    producer = CAPABILITY_PRODUCERS.get(capability)
    if producer is None:
        return []

    if capability is Capability.VALID_TOKEN:
        step = _make_step(producer, "default", "no_token", operation_pool)
        return [step] if step else []

    if capability is Capability.LOW_PRIV_TOKEN:
        step = _make_step(producer, "low_privilege", "low_privilege", operation_pool)
        return [step] if step else []

    if capability is Capability.OTHER_RESOURCE:
        owner = _other_owner(target_actor)
        step = _make_step(producer, owner, _auth_mode_for_owner(owner), operation_pool)
        return [step] if step else []

    if capability is Capability.DELETED_RESOURCE:
        # Need an owned active resource first, then delete it.
        steps = _resolve_capability(Capability.OWN_RESOURCE, target_actor, operation_pool, depth + 1)
        delete_step = _make_step(producer, target_actor, _auth_mode_for_owner(target_actor), operation_pool)
        if delete_step:
            steps.append(delete_step)
        return steps

    # OWN_RESOURCE, KNOWN_ID
    step = _make_step(producer, target_actor, _auth_mode_for_owner(target_actor), operation_pool)
    return [step] if step else []


def build_prerequisite_genes(
    transition: str,
    storage: FSMStorage,
    operation_pool: list[Operation],
    target_actor: str | None = None,
    depth: int = 0,
) -> list[PrereqStep]:
    """Synthesize the positive-transition steps needed to unblock ``transition``.

    Returns an ordered list (earliest prerequisite first). Steps fill the
    capabilities that ``transition`` requires but storage does not yet provide.
    """
    target = target_actor or storage.active_actor or "default"
    steps: list[PrereqStep] = []
    for capability in sorted(missing_capabilities(transition, storage), key=lambda c: c.value):
        steps.extend(_resolve_capability(capability, target, operation_pool, depth))
    return steps
