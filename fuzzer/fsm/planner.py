from __future__ import annotations

from dataclasses import dataclass

from fuzzer.fsm.capabilities import Capability, missing_capabilities
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

    Auth is cookie/session based on the target, so the auth mode merely selects
    which actor's session (cookie jar) the request runs under.
    """
    if owner_actor == "low_privilege":
        return "low_privilege"
    return "valid_token"


def _other_owner(target_actor: str) -> str:
    """Pick an actor distinct from the target so created resources are 'other-owned'."""
    return "default" if target_actor == "low_privilege" else "low_privilege"


def _step(transition: str, owner_actor: str, operation_pool: list[Operation]) -> PrereqStep | None:
    op: Operation | None = choose_operation_for_transition(transition, operation_pool)
    if op is None:
        return None
    return PrereqStep(gene=Gene(transition, op.name, _auth_mode_for_owner(owner_actor)), owner_actor=owner_actor)


def _session_then_create(owner_actor: str, operation_pool: list[Operation]) -> list[PrereqStep]:
    """Establish a session for ``owner_actor`` (a public query yields a cookie),
    then create a resource owned by it."""
    steps: list[PrereqStep] = []
    session = _step(TransitionName.PUBLIC_QUERY.value, owner_actor, operation_pool)
    if session:
        steps.append(session)
    create = _step(TransitionName.SETUP_CREATE_RESOURCE.value, owner_actor, operation_pool)
    if create:
        steps.append(create)
    return steps


def _resolve_capability(
    capability: Capability,
    target_actor: str,
    operation_pool: list[Operation],
    depth: int,
) -> list[PrereqStep]:
    """Build the ordered prerequisite steps that establish a single capability."""
    if depth >= MAX_FILL_DEPTH:
        return []

    if capability is Capability.SESSION:
        step = _step(TransitionName.PUBLIC_QUERY.value, target_actor, operation_pool)
        return [step] if step else []

    if capability is Capability.SECONDARY_SESSION:
        step = _step(TransitionName.PUBLIC_QUERY.value, _other_owner(target_actor), operation_pool)
        return [step] if step else []

    if capability in {Capability.OWN_RESOURCE, Capability.KNOWN_ID}:
        return _session_then_create(target_actor, operation_pool)

    if capability is Capability.OTHER_RESOURCE:
        return _session_then_create(_other_owner(target_actor), operation_pool)

    if capability is Capability.DELETED_RESOURCE:
        steps = _session_then_create(target_actor, operation_pool)
        delete = _step(TransitionName.DELETE_OWN_RESOURCE.value, target_actor, operation_pool)
        if delete:
            steps.append(delete)
        return steps

    return []


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
