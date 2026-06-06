from fuzzer.ga.chromosome import QueryShape
from fuzzer.fsm.storage import FSMStorage
from fuzzer.graphql.client import GraphQLResponse
from fuzzer.graphql.payloads import SQL_PAYLOADS, payload_for_operation
from fuzzer.graphql.schema_types import Argument, Operation
from fuzzer.oracle.auth import detect_auth_bypass
from fuzzer.oracle.dos import detect_dos
from fuzzer.oracle.error_leakage import detect_error_leakage
from fuzzer.oracle.injection import detect_injection


def response(body, text=None, latency=10, timeout=False, size=100, status=200):
    return GraphQLResponse(status, body, text or str(body), latency, size, timeout)


def test_auth_bypass_detection():
    findings = detect_auth_bypass(response({"data": {"me": {"email": "a@b.c"}}}), "s", 0, "me", "protected_query_without_token", "no_token", True)
    assert findings and findings[0]["finding_type"] == "AUTH_BYPASS_CANDIDATE"


def test_auth_bypass_ignores_null_resolver_data():
    findings = detect_auth_bypass(response({"data": {"ownerPostHistory": None}}), "s", 0, "ownerPostHistory", "protected_query_without_token", "no_token", True)
    assert findings == []


def test_error_leakage_detection():
    findings = detect_error_leakage(response({"errors": []}, "Traceback SQLite Exception"), "s", 0, "x", "t", "no_token")
    assert findings


def test_injection_reflection_detection():
    findings = detect_injection(response({"data": {"search": "' OR '1'='1"}}), {"q": "' OR '1'='1"}, "s", 0, "search", "injection_payload_query", "no_token")
    assert findings


def test_injection_mode_uses_sql_payload():
    payload = payload_for_operation(Operation("search", "query", [Argument("query", "String")], "Post"), FSMStorage(), "injection")

    assert payload["query"] == SQL_PAYLOADS[0]


def test_injection_policy_bypass_detection():
    body = {"data": {"search": [{"id": "1", "public": False, "internalNote": "private"}]}}
    findings = detect_injection(response(body), {"q": SQL_PAYLOADS[0]}, "s", 0, "search", "injection_payload_query", "no_token")

    assert findings and findings[0]["evidence"]["policy_bypass"] is True


def test_injection_policy_bypass_handles_list_sensitive_values():
    body = {"data": {"search": [{"id": "1", "token": ["private"]}]}}
    findings = detect_injection(response(body), {"q": SQL_PAYLOADS[0]}, "s", 0, "search", "injection_payload_query", "no_token")

    assert findings and findings[0]["evidence"]["policy_bypass"] is True


def test_dos_timeout_detection():
    findings = detect_dos(response(None, timeout=True), QueryShape(depth=4), "s", 0, "posts", "deeply_nested_query", "no_token")
    assert findings
