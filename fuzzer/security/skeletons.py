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

CATEGORY_ORDER = [
    BOLA_UPDATE_DELETE,
    BFLA_ADMIN_LIKE_OP,
    INJECTION,
    STALE_OBJECT_ACCESS,
    BOPLA_SENSITIVE_FIELD_READ,
    BOLA_READ,
    AUTH_BYPASS,
    COST_ANOMALY,
]


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
            verify_transition = TransitionName.QUERY_DELETED_RESOURCE.value if transition == TransitionName.DELETE_OTHER_RESOURCE.value else TransitionName.QUERY_OWN_RESOURCE.value
            genes.append(Gene(verify_transition, target.verify_operation, "valid_token"))
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

    genes = _with_parent_resource_setup(target, genes)
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
    seeds = [chromosome_for_target(target) for target in _stratified_targets(targets, population_size)]
    if len(seeds) < population_size:
        seeds.extend(create_initial_population(operation_pool, population_size - len(seeds), max_len))
    return seeds[:population_size]


def _stratified_targets(targets: list[SecurityTarget], limit: int) -> list[SecurityTarget]:
    if limit <= 0:
        return []
    grouped: dict[str, list[SecurityTarget]] = {}
    for target in targets:
        grouped.setdefault(target.category, []).append(target)
    for bucket in grouped.values():
        bucket[:] = _object_balanced_targets(bucket)
    selected = _required_priority_targets(grouped, limit)
    ordered_categories = CATEGORY_ORDER + sorted(category for category in grouped if category not in CATEGORY_ORDER)
    while len(selected) < limit:
        added = False
        for category in ordered_categories:
            bucket = grouped.get(category) or []
            if not bucket:
                continue
            selected.append(bucket.pop(0))
            added = True
            if len(selected) >= limit:
                break
        if not added:
            break
    return selected


def _required_priority_targets(grouped: dict[str, list[SecurityTarget]], limit: int) -> list[SecurityTarget]:
    required: list[SecurityTarget] = []

    for category, predicates in _priority_quota_plan(limit):
        bucket = grouped.get(category) or []
        for predicate in predicates:
            if len(required) >= limit:
                break
            target = next((item for item in bucket if predicate(item) and item not in required), None)
            if target:
                required.append(target)
        if bucket:
            grouped[category] = [target for target in bucket if target not in required]
        if len(required) >= limit:
            break
    return required


def _priority_quota_plan(limit: int):
    update_delete = [
        lambda target: target.object_type == "Post" and _mutation_action(target.target_operation) == "update",
        lambda target: target.object_type == "Post" and _mutation_action(target.target_operation) == "delete",
        lambda target: target.object_type == "Comment" and _mutation_action(target.target_operation) == "update",
        lambda target: target.object_type == "Comment" and _mutation_action(target.target_operation) == "delete",
    ]
    bfla = [
        lambda target: target.object_type == "User",
        lambda target: target.object_type == "CommandOutput",
    ]
    injection = [
        lambda target: target.object_type == "Post" and target.target_operation == "search",
    ]
    stale = [
        lambda target: target.object_type == "Post" and target.target_operation == "post",
        lambda target: target.object_type == "Comment" and target.target_operation == "comment",
    ]
    bola_read = [
        lambda target: target.object_type == "Post" and target.target_operation == "post",
        lambda target: target.object_type == "Comment" and target.target_operation == "comment",
    ]
    bopla = [
        lambda target: target.object_type == "User" and target.sensitive_field == "resetToken" and target.target_operation == "me",
        lambda target: target.object_type == "Post" and target.sensitive_field == "internalNote" and target.target_operation == "post",
        lambda target: target.object_type == "Comment" and target.sensitive_field == "moderationNote" and target.target_operation == "comment",
        lambda target: target.object_type == "Post" and target.sensitive_field == "internalNote" and target.target_operation == "search",
        lambda target: target.object_type == "User" and target.sensitive_field == "resetToken",
        lambda target: target.object_type == "Post" and target.sensitive_field == "internalNote",
        lambda target: target.object_type == "Comment" and target.sensitive_field == "moderationNote",
    ]

    if limit <= 6:
        return [
            (BOLA_UPDATE_DELETE, update_delete),
            (BFLA_ADMIN_LIKE_OP, bfla[:1]),
            (INJECTION, injection),
            (BOLA_READ, bola_read),
        ]
    return [
        (BOLA_UPDATE_DELETE, update_delete),
        (BFLA_ADMIN_LIKE_OP, bfla),
        (INJECTION, injection),
        (STALE_OBJECT_ACCESS, stale),
        (BOPLA_SENSITIVE_FIELD_READ, bopla[:2]),
        (BOLA_READ, bola_read),
    ]


def _with_parent_resource_setup(target: SecurityTarget, genes: list[Gene]) -> list[Gene]:
    if target.object_type != "Comment" or target.setup_operation != "createComment":
        return genes
    if any(gene.operation_name == "createPost" for gene in genes):
        return genes
    return [Gene(TransitionName.SETUP_CREATE_RESOURCE.value, "createPost", "valid_token"), *genes]


def _object_balanced_targets(targets: list[SecurityTarget]) -> list[SecurityTarget]:
    grouped: dict[str, list[SecurityTarget]] = {}
    for target in sorted(targets, key=_target_priority):
        grouped.setdefault(target.object_type or "none", []).append(target)
    if targets and targets[0].category == BOLA_UPDATE_DELETE:
        for object_type, bucket in list(grouped.items()):
            grouped[object_type] = _action_balanced_targets(bucket)
    object_types = sorted(grouped, key=_object_rank)
    selected: list[SecurityTarget] = []
    while True:
        added = False
        for object_type in object_types:
            bucket = grouped.get(object_type) or []
            if not bucket:
                continue
            selected.append(bucket.pop(0))
            added = True
        if not added:
            break
    return selected


def _action_balanced_targets(targets: list[SecurityTarget]) -> list[SecurityTarget]:
    grouped: dict[str, list[SecurityTarget]] = {}
    for target in targets:
        grouped.setdefault(_mutation_action(target.target_operation), []).append(target)
    selected: list[SecurityTarget] = []
    for action in ("update", "delete", "other"):
        selected.extend(grouped.get(action, []))
    return selected


def _mutation_action(operation_name: str | None) -> str:
    name = (operation_name or "").lower()
    if "delete" in name or "remove" in name:
        return "delete"
    if "update" in name or "edit" in name or "patch" in name:
        return "update"
    return "other"


def _object_rank(object_type: str) -> tuple[int, str]:
    return ({"Post": 0, "Comment": 1, "User": 2, "none": 4}.get(object_type, 3), object_type)


def _target_priority(target: SecurityTarget) -> tuple[int, int, int, str]:
    name = (target.target_operation or "").lower()
    object_type = (target.object_type or "").lower()
    object_rank = {"post": 0, "comment": 1, "user": 2}.get(object_type, 3)
    secure_penalty = 1 if any(term in name for term in ("secure", "preview", "public", "history", "owner")) else 0
    mutation_rank = 0
    if target.category == BOLA_UPDATE_DELETE:
        mutation_rank = 0 if "update" in name else 1 if "delete" in name else 2
    return (object_rank, secure_penalty, mutation_rank, target.target_id)


def _looks_delete(operation_name: str | None) -> bool:
    return "delete" in (operation_name or "").lower() or "remove" in (operation_name or "").lower()
