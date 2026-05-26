from __future__ import annotations

import random

from fuzzer.fsm.transitions import TransitionName
from fuzzer.ga.chromosome import Chromosome, Gene, QueryShape
from fuzzer.graphql.schema_types import Operation

AUTH_MODES = ["no_token", "valid_token", "bad_token", "empty_token", "wrong_prefix", "low_privilege"]


def _pick_operation(operation_pool: list[Operation], wants_args: bool = False, wants_auth: bool = False) -> Operation | None:
    candidates = operation_pool
    if wants_args:
        candidates = [op for op in candidates if op.args]
    if wants_auth:
        candidates = [op for op in candidates if op.auth_required_guess or op.sensitive_field_guess] or candidates
    return random.choice(candidates) if candidates else None


def random_gene(operation_pool: list[Operation]) -> Gene:
    transition = random.choice(list(TransitionName)).value
    op = _pick_operation(operation_pool, wants_args="injection" in transition, wants_auth="protected" in transition)
    auth = random.choice(AUTH_MODES)
    if "without_token" in transition:
        auth = "no_token"
    elif "bad_token" in transition:
        auth = "bad_token"
    elif "valid_token" in transition:
        auth = "valid_token"
    return Gene(transition, op.name if op else None, auth, expected_negative=auth in {"no_token", "bad_token", "low_privilege"} and "protected" in transition)


def create_initial_population(operation_pool: list[Operation], population_size: int, max_len: int) -> list[Chromosome]:
    seeds: list[Chromosome] = []
    public = _pick_operation(operation_pool)
    protected = _pick_operation(operation_pool, wants_auth=True)
    arg_op = _pick_operation(operation_pool, wants_args=True)
    if public:
        seeds.append(Chromosome([Gene(TransitionName.PUBLIC_QUERY.value, public.name, "no_token")]))
        seeds.append(Chromosome([Gene(TransitionName.ALIAS_AMPLIFIED_QUERY.value, public.name, "no_token", query_shape=QueryShape(alias_count=3))]))
        seeds.append(Chromosome([Gene(TransitionName.DEEPLY_NESTED_QUERY.value, public.name, "no_token", query_shape=QueryShape(depth=3))]))
    if protected:
        seeds.append(Chromosome([Gene(TransitionName.LOGIN_OR_GET_TOKEN.value, protected.name, "no_token"), Gene(TransitionName.PROTECTED_QUERY_WITH_VALID_TOKEN.value, protected.name, "valid_token")]))
        seeds.append(Chromosome([Gene(TransitionName.PROTECTED_QUERY_WITHOUT_TOKEN.value, protected.name, "no_token", expected_negative=True)]))
        seeds.append(Chromosome([Gene(TransitionName.PROTECTED_QUERY_WITH_BAD_TOKEN.value, protected.name, "bad_token", expected_negative=True)]))
    if arg_op:
        seeds.append(Chromosome([Gene(TransitionName.INJECTION_PAYLOAD_QUERY.value, arg_op.name, "no_token")]))
    while len(seeds) < population_size:
        length = random.randint(1, max(1, max_len))
        seeds.append(Chromosome([random_gene(operation_pool) for _ in range(length)]))
    return seeds[:population_size]
