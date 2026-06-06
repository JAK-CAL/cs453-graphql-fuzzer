from fuzzer.graphql.schema_types import Argument, Operation
from fuzzer.security.skeletons import create_security_guided_population
from fuzzer.security.targets import BFLA_ADMIN_LIKE_OP, BOLA_READ, BOLA_UPDATE_DELETE, build_security_targets


def test_build_security_targets_from_schema_hypotheses():
    ops = [
        Operation("createPost", "mutation", return_type="Post", selectable_fields=["id", "title"]),
        Operation("post", "query", args=[Argument("id", "ID")], return_type="Post", selectable_fields=["id", "title", "internalNote"]),
        Operation("adminUsers", "query", return_type="User", selectable_fields=["id", "username", "resetToken"]),
    ]

    targets = build_security_targets(ops)
    categories = {target.category for target in targets}

    assert BOLA_READ in categories
    assert BFLA_ADMIN_LIKE_OP in categories
    assert any(target.sensitive_field == "internalNote" for target in targets)


def test_security_guided_population_uses_target_skeletons_first():
    ops = [
        Operation("createPost", "mutation", return_type="Post", selectable_fields=["id"]),
        Operation("post", "query", args=[Argument("id", "ID")], return_type="Post", selectable_fields=["id"]),
    ]
    targets = build_security_targets(ops)

    population = create_security_guided_population(ops, targets, population_size=2, max_len=4)

    assert population
    assert population[0].target_id is not None
    assert population[0].schedule_path


def test_security_guided_population_balances_categories():
    ops = [
        Operation("createPost", "mutation", return_type="Post", selectable_fields=["id"]),
        Operation("post", "query", args=[Argument("id", "ID")], return_type="Post", selectable_fields=["id", "internalNote"]),
        Operation("updatePost", "mutation", args=[Argument("id", "ID")], return_type="Post", selectable_fields=["id", "internalNote"]),
        Operation("adminUsers", "query", return_type="User", selectable_fields=["id", "resetToken"]),
    ]
    targets = build_security_targets(ops)

    population = create_security_guided_population(ops, targets, population_size=4, max_len=4)
    categories = {chrom.target_category for chrom in population}

    assert BOLA_READ in categories
    assert BOLA_UPDATE_DELETE in categories
    assert BFLA_ADMIN_LIKE_OP in categories
