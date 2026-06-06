from fuzzer.graphql.schema_types import Argument, Operation
from fuzzer.security.skeletons import chromosome_for_target, create_security_guided_population
from fuzzer.security.targets import BFLA_ADMIN_LIKE_OP, BOLA_READ, BOLA_UPDATE_DELETE, BOPLA_SENSITIVE_FIELD_READ, INJECTION, STALE_OBJECT_ACCESS, build_security_targets


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
        Operation("register", "mutation", return_type="User", selectable_fields=["id", "resetToken"]),
        Operation("user", "query", args=[Argument("id", "ID")], return_type="User", selectable_fields=["id", "resetToken"]),
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
    assert "BOLA_READ:Post:createPost:post" in {chrom.target_id for chrom in population}


def test_security_guided_population_balances_objects_within_stateful_categories():
    ops = [
        Operation("createPost", "mutation", return_type="Post", selectable_fields=["id"]),
        Operation("post", "query", args=[Argument("id", "ID")], return_type="Post", selectable_fields=["id", "internalNote"]),
        Operation("updatePost", "mutation", args=[Argument("id", "ID")], return_type="Post", selectable_fields=["id", "internalNote"]),
        Operation("deletePost", "mutation", args=[Argument("id", "ID")], return_type="Post", selectable_fields=["id", "internalNote"]),
        Operation("createComment", "mutation", return_type="Comment", selectable_fields=["id"]),
        Operation("comment", "query", args=[Argument("id", "ID")], return_type="Comment", selectable_fields=["id", "moderationNote"]),
        Operation("updateComment", "mutation", args=[Argument("id", "ID")], return_type="Comment", selectable_fields=["id", "moderationNote"]),
        Operation("deleteComment", "mutation", args=[Argument("id", "ID")], return_type="Comment", selectable_fields=["id", "moderationNote"]),
        Operation("adminUsers", "query", return_type="User", selectable_fields=["id", "resetToken"]),
        Operation("superSecretPrivateMutation", "mutation", args=[Argument("command", "String")], return_type="CommandOutput", selectable_fields=["stdout", "stderr"]),
    ]
    targets = build_security_targets(ops)

    population = create_security_guided_population(ops, targets, population_size=12, max_len=4)
    target_ids = {chrom.target_id for chrom in population}

    assert "BOLA_READ:Post:createPost:post" in target_ids
    assert "BOLA_READ:Comment:createComment:comment" in target_ids
    assert "BOLA_UPDATE_DELETE:Post:createPost:updatePost" in target_ids
    assert "BOLA_UPDATE_DELETE:Post:createPost:deletePost" in target_ids
    assert "BOLA_UPDATE_DELETE:Comment:createComment:updateComment" in target_ids
    assert "BOLA_UPDATE_DELETE:Comment:createComment:deleteComment" in target_ids
    assert "STALE_OBJECT_ACCESS:Post:createPost:deletePost:post" in target_ids
    assert "STALE_OBJECT_ACCESS:Comment:createComment:deleteComment:comment" in target_ids
    assert "BFLA_ADMIN_LIKE_OP:CommandOutput:superSecretPrivateMutation" in target_ids


def test_delete_bola_skeleton_verifies_deleted_resource():
    ops = [
        Operation("createPost", "mutation", return_type="Post", selectable_fields=["id"]),
        Operation("post", "query", args=[Argument("id", "ID")], return_type="Post", selectable_fields=["id", "deleted"]),
        Operation("deletePost", "mutation", args=[Argument("id", "ID")], return_type="Post", selectable_fields=["id", "deleted"]),
    ]
    target = next(target for target in build_security_targets(ops) if target.target_id == "BOLA_UPDATE_DELETE:Post:createPost:deletePost")

    chromosome = chromosome_for_target(target)

    assert [gene.transition for gene in chromosome.genes] == [
        "setup_create_resource",
        "delete_other_resource",
        "query_deleted_resource",
    ]


def test_security_guided_population_prioritizes_injection_and_field_targets():
    ops = [
        Operation("me", "query", return_type="User", selectable_fields=["id", "resetToken"]),
        Operation("createPost", "mutation", return_type="Post", selectable_fields=["id", "internalNote"]),
        Operation("post", "query", args=[Argument("id", "ID")], return_type="Post", selectable_fields=["id", "internalNote"]),
        Operation("search", "query", args=[Argument("term", "String")], return_type="Post", selectable_fields=["id", "internalNote"]),
        Operation("updatePost", "mutation", args=[Argument("id", "ID")], return_type="Post", selectable_fields=["id", "internalNote"]),
        Operation("deletePost", "mutation", args=[Argument("id", "ID")], return_type="Post", selectable_fields=["id", "internalNote"]),
        Operation("createComment", "mutation", return_type="Comment", selectable_fields=["id", "moderationNote"]),
        Operation("comment", "query", args=[Argument("id", "ID")], return_type="Comment", selectable_fields=["id", "moderationNote"]),
        Operation("updateComment", "mutation", args=[Argument("id", "ID")], return_type="Comment", selectable_fields=["id", "moderationNote"]),
        Operation("deleteComment", "mutation", args=[Argument("id", "ID")], return_type="Comment", selectable_fields=["id", "moderationNote"]),
        Operation("adminUsers", "query", return_type="User", selectable_fields=["id", "resetToken"]),
        Operation("superSecretPrivateMutation", "mutation", args=[Argument("command", "String")], return_type="CommandOutput", selectable_fields=["stdout", "stderr"]),
    ]
    targets = build_security_targets(ops)

    population = create_security_guided_population(ops, targets, population_size=12, max_len=5)
    target_ids = {chrom.target_id for chrom in population}
    categories = {chrom.target_category for chrom in population}

    assert "INJECTION:Post:search" in target_ids
    assert "STALE_OBJECT_ACCESS:Post:createPost:deletePost:post" in target_ids
    assert "STALE_OBJECT_ACCESS:Comment:createComment:deleteComment:comment" in target_ids
    assert any(target_id.startswith("BOPLA_SENSITIVE_FIELD_READ:User:me:resetToken") for target_id in target_ids)
    assert any(target_id.startswith("BOPLA_SENSITIVE_FIELD_READ:Post:post:internalNote") for target_id in target_ids)
    assert {INJECTION, STALE_OBJECT_ACCESS, BOPLA_SENSITIVE_FIELD_READ}.issubset(categories)


def test_comment_lifecycle_skeleton_creates_parent_post_first():
    ops = [
        Operation("createPost", "mutation", return_type="Post", selectable_fields=["id"]),
        Operation("createComment", "mutation", return_type="Comment", selectable_fields=["id"]),
        Operation("comment", "query", args=[Argument("id", "ID")], return_type="Comment", selectable_fields=["id"]),
        Operation("deleteComment", "mutation", args=[Argument("id", "ID")], return_type="Comment", selectable_fields=["id", "deleted"]),
    ]
    target = next(target for target in build_security_targets(ops) if target.target_id == "STALE_OBJECT_ACCESS:Comment:createComment:deleteComment:comment")

    chromosome = chromosome_for_target(target)

    assert [(gene.transition, gene.operation_name) for gene in chromosome.genes] == [
        ("setup_create_resource", "createPost"),
        ("setup_create_resource", "createComment"),
        ("delete_own_resource", "deleteComment"),
        ("query_deleted_resource", "comment"),
    ]
