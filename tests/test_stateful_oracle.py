from fuzzer.ga.chromosome import Chromosome, Gene
from fuzzer.security.stateful_oracle import classify_stateful_findings
from fuzzer.security.targets import AUTH_BYPASS, BFLA_ADMIN_LIKE_OP, BOLA_READ, BOLA_UPDATE_DELETE, BOPLA_SENSITIVE_FIELD_READ


def test_stateful_oracle_confirms_foreign_resource_read():
    chromosome = Chromosome([Gene("query_other_resource", "post", "low_privilege", expected_negative=True)])
    chromosome.target_id = "BOLA_READ:Post:createPost:post"
    chromosome.target_category = BOLA_READ
    chromosome.execution_trace.append(
        {
            "actor": "low_privilege",
            "operation": "post",
            "transition": "query_other_resource",
            "auth_mode": "low_privilege",
            "status_code": 200,
            "has_data_key": True,
            "resolver_reached": True,
            "selected_resource": {"resource_type": "Post", "id": "1", "owner_actor": "default", "state": "active"},
            "body": {"data": {"post": {"id": "1", "title": "private"}}},
        }
    )

    findings = classify_stateful_findings(chromosome, "seq", 0)

    assert findings
    assert findings[0]["confidence"] == "confirmed"
    assert findings[0]["finding_type"] == "STATEFUL_BOLA_READ"


def test_stateful_oracle_ignores_bola_read_when_response_is_different_resource():
    chromosome = Chromosome([Gene("query_other_resource", "post", "low_privilege", expected_negative=True)])
    chromosome.target_id = "BOLA_READ:Post:createPost:post"
    chromosome.target_category = BOLA_READ
    chromosome.execution_trace.append(
        {
            "actor": "low_privilege",
            "operation": "post",
            "transition": "query_other_resource",
            "auth_mode": "low_privilege",
            "status_code": 200,
            "has_data_key": True,
            "resolver_reached": True,
            "selected_resource": {"resource_type": "Post", "id": "1", "owner_actor": "default", "state": "active"},
            "body": {"data": {"post": {"id": "2", "title": "public"}}},
        }
    )

    assert classify_stateful_findings(chromosome, "seq", 0) == []


def test_stateful_oracle_ignores_own_resource_read_for_bola():
    chromosome = Chromosome([Gene("query_other_resource", "post", "low_privilege", expected_negative=True)])
    chromosome.target_id = "BOLA_READ:Post:createPost:post"
    chromosome.target_category = BOLA_READ
    chromosome.execution_trace.append(
        {
            "actor": "default",
            "operation": "post",
            "transition": "query_other_resource",
            "auth_mode": "low_privilege",
            "status_code": 200,
            "selected_resource": {"resource_type": "Post", "id": "1", "owner_actor": "default", "state": "active"},
            "body": {"data": {"post": {"id": "1", "title": "private"}}},
        }
    )

    assert classify_stateful_findings(chromosome, "seq", 0) == []


def test_stateful_oracle_attributes_bola_update_to_attack_operation():
    chromosome = Chromosome(
        [
            Gene("setup_create_resource", "createPost", "valid_token"),
            Gene("update_other_resource", "updatePost", "low_privilege", expected_negative=True),
            Gene("query_deleted_resource", "post", "valid_token"),
        ]
    )
    chromosome.target_id = "BOLA_UPDATE_DELETE:Post:createPost:updatePost"
    chromosome.target_category = BOLA_UPDATE_DELETE
    chromosome.execution_trace.extend(
        [
            {
                "actor": "default",
                "operation": "createPost",
                "transition": "setup_create_resource",
                "auth_mode": "valid_token",
                "status_code": 200,
                "selected_resource": None,
                "body": {"data": {"createPost": {"id": "1"}}},
            },
            {
                "actor": "low_privilege",
                "operation": "updatePost",
                "transition": "update_other_resource",
                "auth_mode": "low_privilege",
                "status_code": 200,
                "selected_resource": {"resource_type": "Post", "id": "1", "owner_actor": "default", "state": "active"},
                "body": {"data": {"updatePost": {"id": "1", "title": "changed"}}},
            },
            {
                "actor": "default",
                "operation": "post",
                "transition": "query_own_resource",
                "auth_mode": "valid_token",
                "status_code": 200,
                "selected_resource": {"resource_type": "Post", "id": "1", "owner_actor": "default", "state": "active"},
                "body": {"data": {"post": {"id": "1", "title": "changed"}}},
            },
        ]
    )

    findings = classify_stateful_findings(chromosome, "seq", 0)

    assert findings
    assert findings[0]["confidence"] == "confirmed"
    assert findings[0]["operation"] == "updatePost"
    assert findings[0]["transition"] == "update_other_resource"
    assert findings[0]["evidence"]["verify_operation"] == "post"
    assert findings[0]["evidence"]["side_effect_confirmed"] is True
    assert findings[0]["evidence"]["side_effect_fields"] == ["title"]


def test_stateful_oracle_does_not_confirm_bola_update_without_owner_visible_field_change():
    chromosome = Chromosome(
        [
            Gene("setup_create_resource", "createPost", "valid_token"),
            Gene("update_other_resource", "updatePost", "low_privilege", expected_negative=True),
            Gene("query_own_resource", "post", "valid_token"),
        ]
    )
    chromosome.target_id = "BOLA_UPDATE_DELETE:Post:createPost:updatePost"
    chromosome.target_category = BOLA_UPDATE_DELETE
    chromosome.execution_trace.extend(
        [
            {
                "actor": "low_privilege",
                "operation": "updatePost",
                "transition": "update_other_resource",
                "auth_mode": "low_privilege",
                "status_code": 200,
                "selected_resource": {"resource_type": "Post", "id": "1", "owner_actor": "default", "state": "active"},
                "body": {"data": {"updatePost": {"id": "1"}}},
            },
            {
                "actor": "default",
                "operation": "post",
                "transition": "query_own_resource",
                "auth_mode": "valid_token",
                "status_code": 200,
                "selected_resource": {"resource_type": "Post", "id": "1", "owner_actor": "default", "state": "active"},
                "body": {"data": {"post": {"id": "1"}}},
            },
        ]
    )

    findings = classify_stateful_findings(chromosome, "seq", 0)

    assert findings
    assert findings[0]["confidence"] == "probable"
    assert findings[0]["evidence"]["side_effect_confirmed"] is False


def test_stateful_oracle_confirms_bola_delete_when_deleted_flag_is_owner_visible():
    chromosome = Chromosome(
        [
            Gene("setup_create_resource", "createPost", "valid_token"),
            Gene("delete_other_resource", "deletePost", "low_privilege", expected_negative=True),
            Gene("query_own_resource", "post", "valid_token"),
        ]
    )
    chromosome.target_id = "BOLA_UPDATE_DELETE:Post:createPost:deletePost"
    chromosome.target_category = BOLA_UPDATE_DELETE
    chromosome.execution_trace.extend(
        [
            {
                "actor": "low_privilege",
                "operation": "deletePost",
                "transition": "delete_other_resource",
                "auth_mode": "low_privilege",
                "status_code": 200,
                "selected_resource": {"resource_type": "Post", "id": "1", "owner_actor": "default", "state": "active"},
                "body": {"data": {"deletePost": {"id": "1", "deleted": True}}},
            },
            {
                "actor": "default",
                "operation": "post",
                "transition": "query_deleted_resource",
                "auth_mode": "valid_token",
                "status_code": 200,
                "selected_resource": {"resource_type": "Post", "id": "1", "owner_actor": "default", "state": "deleted"},
                "body": {"data": {"post": {"id": "1", "deleted": True}}},
            },
        ]
    )

    findings = classify_stateful_findings(chromosome, "seq", 0)

    assert findings
    assert findings[0]["confidence"] == "confirmed"
    assert findings[0]["evidence"]["side_effect_confirmed"] is True
    assert findings[0]["evidence"]["side_effect_field"] == "deleted"


def test_stateful_oracle_ignores_sensitive_data_from_non_target_trace():
    chromosome = Chromosome([Gene("protected_query_without_token", "createPost", "no_token", expected_negative=True)])
    chromosome.target_id = "BOPLA_SENSITIVE_FIELD_READ:Post:createPost:internalNote"
    chromosome.target_category = BOPLA_SENSITIVE_FIELD_READ
    chromosome.execution_trace.extend(
        [
            {
                "actor": "anonymous",
                "operation": "me",
                "transition": "public_query",
                "auth_mode": "valid_token",
                "status_code": 200,
                "body": {"data": {"me": {"resetToken": "secret"}}},
            },
            {
                "actor": "anonymous",
                "operation": "createPost",
                "transition": "protected_query_without_token",
                "auth_mode": "no_token",
                "status_code": 200,
                "body": {"data": {"createPost": {"id": "1", "title": "ok"}}},
            },
        ]
    )

    assert classify_stateful_findings(chromosome, "seq", 0) == []


def test_stateful_oracle_requires_target_sensitive_field_for_bopla():
    chromosome = Chromosome([Gene("protected_query_without_token", "createPost", "no_token", expected_negative=True)])
    chromosome.target_id = "BOPLA_SENSITIVE_FIELD_READ:Post:createPost:internalNote"
    chromosome.target_category = BOPLA_SENSITIVE_FIELD_READ
    chromosome.execution_trace.append(
        {
            "actor": "anonymous",
            "operation": "createPost",
            "transition": "protected_query_without_token",
            "auth_mode": "no_token",
            "status_code": 200,
            "body": {"data": {"createPost": {"id": "1", "moderationNote": "different sensitive field"}}},
        }
    )

    assert classify_stateful_findings(chromosome, "seq", 0) == []


def test_stateful_auth_oracle_ignores_null_resolver_data():
    chromosome = Chromosome([Gene("protected_query_without_token", "ownerPostHistory", "no_token", expected_negative=True)])
    chromosome.target_id = "AUTH_BYPASS:Post:ownerPostHistory"
    chromosome.target_category = AUTH_BYPASS
    chromosome.execution_trace.append(
        {
            "actor": "anonymous",
            "operation": "ownerPostHistory",
            "transition": "protected_query_without_token",
            "auth_mode": "no_token",
            "status_code": 200,
            "has_data_key": True,
            "resolver_reached": True,
            "selected_resource": None,
            "body": {"data": {"ownerPostHistory": None}},
        }
    )

    assert classify_stateful_findings(chromosome, "seq", 0) == []


def test_bfla_oracle_flags_admin_like_resolver_error_under_unauthorized_context():
    chromosome = Chromosome([Gene("protected_query_with_bad_token", "superSecretPrivateMutation", "bad_token", expected_negative=True)])
    chromosome.target_id = "BFLA_ADMIN_LIKE_OP:CommandOutput:superSecretPrivateMutation"
    chromosome.target_category = BFLA_ADMIN_LIKE_OP
    chromosome.execution_trace.append(
        {
            "actor": "invalid",
            "operation": "superSecretPrivateMutation",
            "transition": "protected_query_with_bad_token",
            "auth_mode": "bad_token",
            "status_code": 200,
            "has_data_key": True,
            "resolver_reached": True,
            "error_signature": "Command failed: test",
            "selected_resource": None,
            "body": {"data": {"superSecretPrivateMutation": None}},
        }
    )

    findings = classify_stateful_findings(chromosome, "seq", 0)

    assert findings
    assert findings[0]["finding_type"] == "STATEFUL_BFLA_ADMIN_LIKE_OP"
    assert findings[0]["confidence"] == "probable"
    assert findings[0]["evidence"]["error_signature"] == "Command failed: test"
