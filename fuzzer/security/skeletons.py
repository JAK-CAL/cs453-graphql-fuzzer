from __future__ import annotations

from fuzzer.fsm.transitions import TransitionName
from fuzzer.ga.chromosome import Chromosome, Gene, QueryShape
from fuzzer.ga.population import create_initial_population
from fuzzer.graphql.schema_types import Operation
from fuzzer.security.targets import (
    AUTH_BYPASS,
    BFLA_ADMIN_LIKE_OP,
    BOLA_READ,
    BOLA_UPDATE_DELETE,
    BOPLA_SENSITIVE_FIELD_READ,
    COST_ANOMALY,
    INJECTION,
    STALE_OBJECT_ACCESS,
    SecurityTarget,
)


def chromosome_for_target(target: SecurityTarget) -> Chromosome:
    genes: list[Gene]
    if target.category == BOLA_READ:
        genes = [
            Gene(TransitionName.SETUP_CREATE_RESOURCE.value, target.setup_operation, "valid_token"),
            Gene(TransitionName.QUERY_OTHER_RESOURCE.value, target.target_operation, "low_privilege", expected_negative=True),
        ]
    elif target.category == BOLA_UPDATE_DELETE:
        transition = TransitionName.DELETE_OTHER_RESOURCE.value if _looks_delete(target.target_operation) else TransitionName.UPDATE_OTHER_RESOURCE.value
        genes = [
            Gene(TransitionName.SETUP_CREATE_RESOURCE.value, target.setup_operation, "valid_token"),
            Gene(transition, target.target_operation, "low_privilege", expected_negative=True),
        ]
        if target.verify_operation:
            genes.append(Gene(TransitionName.QUERY_OWN_RESOURCE.value, target.verify_operation, "valid_token"))
    elif target.category == STALE_OBJECT_ACCESS:
        delete_op = target.target_id.split(":")[3] if len(target.target_id.split(":")) > 3 else None
        genes = [
            Gene(TransitionName.SETUP_CREATE_RESOURCE.value, target.setup_operation, "valid_token"),
            Gene(TransitionName.DELETE_OWN_RESOURCE.value, delete_op, "valid_token"),
            Gene(TransitionName.QUERY_DELETED_RESOURCE.value, target.target_operation, "valid_token", expected_negative=True),
        ]
    elif target.category == BFLA_ADMIN_LIKE_OP:
        genes = [
            Gene(TransitionName.PROTECTED_QUERY_WITH_LOW_PRIVILEGE.value, target.target_operation, "low_privilege", expected_negative=True),
            Gene(TransitionName.PROTECTED_QUERY_WITH_BAD_TOKEN.value, target.target_operation, "bad_token", expected_negative=True),
        ]
    elif target.category in {AUTH_BYPASS, BOPLA_SENSITIVE_FIELD_READ}:
        genes = [
            Gene(TransitionName.PROTECTED_QUERY_WITHOUT_TOKEN.value, target.target_operation, "no_token", expected_negative=True),
            Gene(TransitionName.PROTECTED_QUERY_WITH_LOW_PRIVILEGE.value, target.target_operation, "low_privilege", expected_negative=True),
        ]
    elif target.category == INJECTION:
        genes = [
            Gene(TransitionName.INJECTION_PAYLOAD_QUERY.value, target.target_operation, "no_token", {"__security_payload__": "injection"})
        ]
    elif target.category == COST_ANOMALY:
        genes = [
            Gene(TransitionName.ALIAS_AMPLIFIED_QUERY.value, target.target_operation, "no_token", query_shape=QueryShape(alias_count=5)),
            Gene(TransitionName.DEEPLY_NESTED_QUERY.value, target.target_operation, "no_token", query_shape=QueryShape(depth=4)),
        ]
    else:
        genes = [Gene(TransitionName.PUBLIC_QUERY.value, target.target_operation, "no_token")]

    chromosome = Chromosome(genes)
    chromosome.target_id = target.target_id
    chromosome.target_category = target.category
    chromosome.schedule_path = " > ".join(f"{gene.auth_mode}.{gene.operation_name or gene.transition}" for gene in genes)
    return chromosome


def create_security_guided_population(
    operation_pool: list[Operation],
    targets: list[SecurityTarget],
    population_size: int,
    max_len: int,
) -> list[Chromosome]:
    seeds = [chromosome_for_target(target) for target in _balanced_targets(targets, population_size)]
    if len(seeds) < population_size:
        seeds.extend(create_initial_population(operation_pool, population_size - len(seeds), max_len))
    return seeds[:population_size]


def _looks_delete(operation_name: str | None) -> bool:
    return "delete" in (operation_name or "").lower() or "remove" in (operation_name or "").lower()


def _balanced_targets(targets: list[SecurityTarget], population_size: int) -> list[SecurityTarget]:
    """Pick initial targets by category instead of taking the schema order.

    Schema order tends to put shallow auth/injection targets first. A balanced
    seed set gives BOLA/BFLA/lifecycle templates an early budget slice.
    """
    if population_size <= 0:
        return []
    priority = [
        BOLA_READ,
        BOLA_UPDATE_DELETE,
        STALE_OBJECT_ACCESS,
        BFLA_ADMIN_LIKE_OP,
        BOPLA_SENSITIVE_FIELD_READ,
        AUTH_BYPASS,
        INJECTION,
        COST_ANOMALY,
    ]
    buckets: dict[str, list[SecurityTarget]] = {category: [] for category in priority}
    extras: list[SecurityTarget] = []
    for target in targets:
        if target.category in buckets:
            buckets[target.category].append(target)
        else:
            extras.append(target)

    selected: list[SecurityTarget] = []
    seen: set[str] = set()
    while len(selected) < population_size:
        progressed = False
        for category in priority:
            bucket = buckets.get(category, [])
            if not bucket:
                continue
            target = bucket.pop(0)
            if target.target_id in seen:
                continue
            selected.append(target)
            seen.add(target.target_id)
            progressed = True
            if len(selected) >= population_size:
                break
        if not progressed:
            break
    for target in extras + targets:
        if len(selected) >= population_size:
            break
        if target.target_id not in seen:
            selected.append(target)
            seen.add(target.target_id)
    return selected

