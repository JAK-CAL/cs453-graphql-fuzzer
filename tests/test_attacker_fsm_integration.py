from fuzzer.config import (
    AppConfig,
    BaselineConfig,
    ExecutionConfig,
    GAConfig,
    LimitsConfig,
    MutationConfig,
    OracleConfig,
    OutputConfig,
    TargetConfig,
)
from fuzzer.fsm.dependency import build_dependency_edges
from fuzzer.fsm.executor import execute_chromosome
from fuzzer.fsm.guards import can_execute_transition
from fuzzer.fsm.storage import Actor, FSMStorage, ResourceRef
from fuzzer.fsm.transitions import TransitionName
from fuzzer.ga.chromosome import Chromosome, Gene
from fuzzer.graphql.client import GraphQLResponse
from fuzzer.graphql.schema_types import Argument, Operation


class FakeClient:
    """A stub GraphQL client that always returns an id+token bearing response."""

    def __init__(self):
        self.calls = 0

    def execute(self, query_or_batch, variables=None, auth_mode="no_token"):
        self.calls += 1
        body = {"data": {"id": f"r{self.calls}", "token": "tok-abc"}}
        return GraphQLResponse(
            status_code=200,
            body=body,
            text='{"data": {"id": "r", "token": "tok-abc"}}',
            latency_ms=1.0,
            response_size=64,
            timeout=False,
            auth_mode=auth_mode,
        )


def _config():
    return AppConfig(
        target=TargetConfig(),
        execution=ExecutionConfig(request_delay_ms=0),
        limits=LimitsConfig(),
        ga=GAConfig(fitness_function="default"),
        mutations=MutationConfig(),
        oracles=OracleConfig(),
        baselines=BaselineConfig(),
        output=OutputConfig(),
    )


def _resource_pool():
    return [
        Operation("login", "mutation", [Argument("password", "String")], return_type="AuthPayload"),
        Operation("createPost", "mutation", [Argument("title", "String")], return_type="Post"),
        Operation("deletePost", "mutation", [Argument("id", "ID")], return_type="Post"),
        Operation("post", "query", [Argument("id", "ID")], "Post"),
    ]


def test_blocked_own_resource_query_is_filled_then_executed():
    pool = _resource_pool()
    chrom = Chromosome([Gene(TransitionName.QUERY_OWN_RESOURCE.value, "post", "valid_token")])

    execute_chromosome(chrom, FakeClient(), pool, FSMStorage(), _config())

    assert chrom.positive_fill_count >= 1
    assert TransitionName.QUERY_OWN_RESOURCE.value in chrom.visited_transitions
    assert chrom.skipped_transition_count == 0


def test_blocked_protected_query_logs_in_first():
    pool = _resource_pool()
    chrom = Chromosome([Gene(TransitionName.PROTECTED_QUERY_WITH_VALID_TOKEN.value, "post", "valid_token")])

    execute_chromosome(chrom, FakeClient(), pool, FSMStorage(), _config())

    assert chrom.positive_fill_count >= 1
    assert TransitionName.PROTECTED_QUERY_WITH_VALID_TOKEN.value in chrom.visited_transitions
    assert chrom.skipped_transition_count == 0


def test_blocked_other_resource_query_creates_other_owned_resource():
    pool = _resource_pool()
    chrom = Chromosome([Gene(TransitionName.QUERY_OTHER_RESOURCE.value, "post", "valid_token")])
    storage = FSMStorage()

    execute_chromosome(chrom, FakeClient(), pool, storage, _config())

    assert chrom.positive_fill_count >= 1
    assert TransitionName.QUERY_OTHER_RESOURCE.value in chrom.visited_transitions
    assert chrom.skipped_transition_count == 0


def test_dependency_edges_connect_resource_producer_to_id_consumer():
    operations = [
        Operation("createPost", "mutation", return_type="Post"),
        Operation("post", "query", [Argument("id", "ID")], "Post"),
    ]

    edges = build_dependency_edges(operations)

    assert any(edge.producer == "createPost" and edge.consumer == "post" for edge in edges)


def test_other_resource_guard_requires_different_owner():
    storage = FSMStorage(active_actor="userA")
    storage.actors["userA"] = Actor("userA")
    storage.add_resource(ResourceRef("Post", "1", owner_actor="userA"))
    operation_pool = [Operation("post", "query", [Argument("id", "ID")], "Post")]
    gene = Gene(TransitionName.QUERY_OTHER_RESOURCE.value, "post", "valid_token")

    assert not can_execute_transition(gene.transition, gene, storage, operation_pool)

    storage.add_resource(ResourceRef("Post", "2", owner_actor="userB"))

    assert can_execute_transition(gene.transition, gene, storage, operation_pool)


def test_injection_guard_requires_string_or_id_argument():
    storage = FSMStorage()
    number_only = Operation("setCount", "mutation", [Argument("count", "Int")], "Int")
    searchable = Operation("search", "query", [Argument("query", "String")], "Post")

    assert not can_execute_transition(
        TransitionName.INJECTION_PAYLOAD_QUERY.value,
        Gene(TransitionName.INJECTION_PAYLOAD_QUERY.value, "setCount", "no_token"),
        storage,
        [number_only],
    )
    assert can_execute_transition(
        TransitionName.INJECTION_PAYLOAD_QUERY.value,
        Gene(TransitionName.INJECTION_PAYLOAD_QUERY.value, "search", "no_token"),
        storage,
        [searchable],
    )


def test_valid_actor_context_does_not_stick_to_anonymous_after_no_token():
    storage = FSMStorage()

    assert storage.actor_for_auth_mode("no_token") == "anonymous"
    storage.active_actor = "anonymous"

    assert storage.actor_for_auth_mode("valid_token") == "default"
