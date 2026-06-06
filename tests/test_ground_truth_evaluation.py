import json

from fuzzer.evaluation.ground_truth import compare_with_ground_truth


def test_ground_truth_comparison_counts_tp_fp_fn(tmp_path):
    result_dir = tmp_path / "result"
    result_dir.mkdir()
    ground_truth = tmp_path / "ground_truth.json"
    ground_truth.write_text(
        json.dumps(
            {
                "vulnerable": [
                    {"owasp": "BOPLA_SENSITIVE_FIELD_READ", "resolver": "user", "objectType": "User"},
                    {"owasp": "BOLA_READ", "resolver": "post", "objectType": "Post"},
                ],
                "secure": [
                    {"owasp": "BOPLA_SENSITIVE_FIELD_READ", "resolver": "securePost", "objectType": "Post"}
                ],
            }
        ),
        encoding="utf-8",
    )
    (result_dir / "findings.json").write_text(
        json.dumps(
            [
                {"finding_type": "AUTH_BYPASS_CANDIDATE", "operation": "user", "evidence": {"matched_keywords": ["token"]}},
                {"finding_type": "AUTH_BYPASS_CANDIDATE", "operation": "securePost", "evidence": {"matched_keywords": ["token"]}},
            ]
        ),
        encoding="utf-8",
    )

    comparison = compare_with_ground_truth(result_dir, ground_truth)

    assert comparison["tp"] == 1
    assert comparison["fp"] == 1
    assert comparison["fn"] == 1
    assert comparison["precision"] == 0.5
    assert comparison["recall"] == 0.5


def test_ground_truth_comparison_uses_target_id_resolver_fallback(tmp_path):
    result_dir = tmp_path / "result"
    result_dir.mkdir()
    ground_truth = tmp_path / "ground_truth.json"
    ground_truth.write_text(
        json.dumps(
            {
                "vulnerable": [
                    {"owasp": "BOLA_UPDATE_DELETE", "resolver": "updatePost", "objectType": "Post"},
                ],
                "secure": [],
            }
        ),
        encoding="utf-8",
    )
    (result_dir / "findings.json").write_text(
        json.dumps(
            [
                {
                    "finding_type": "STATEFUL_BOLA_UPDATE_DELETE",
                    "target_id": "BOLA_UPDATE_DELETE:Post:createPost:updatePost",
                    "target_category": "BOLA_UPDATE_DELETE",
                    "operation": "post",
                },
            ]
        ),
        encoding="utf-8",
    )

    comparison = compare_with_ground_truth(result_dir, ground_truth)

    assert comparison["tp"] == 1
    assert comparison["fn"] == 0


def test_ground_truth_maps_auth_bypass_target_to_sensitive_field_category(tmp_path):
    result_dir = tmp_path / "result"
    result_dir.mkdir()
    ground_truth = tmp_path / "ground_truth.json"
    ground_truth.write_text(
        json.dumps(
            {
                "vulnerable": [
                    {"owasp": "BOPLA_SENSITIVE_FIELD_READ", "resolver": "me", "objectType": "User"},
                ],
                "secure": [],
            }
        ),
        encoding="utf-8",
    )
    (result_dir / "findings.json").write_text(
        json.dumps(
            [
                {
                    "finding_type": "STATEFUL_AUTH_BYPASS",
                    "target_id": "AUTH_BYPASS:User:me",
                    "target_category": "AUTH_BYPASS",
                    "operation": "me",
                },
            ]
        ),
        encoding="utf-8",
    )

    comparison = compare_with_ground_truth(result_dir, ground_truth)

    assert comparison["tp"] == 1
    assert comparison["fn"] == 0
