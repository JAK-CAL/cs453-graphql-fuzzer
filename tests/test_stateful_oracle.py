from fuzzer.ga.chromosome import Chromosome, Gene
from fuzzer.security.stateful_oracle import classify_stateful_findings
from fuzzer.security.targets import BOLA_READ


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
