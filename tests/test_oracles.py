from fuzzer.ga.chromosome import QueryShape
from fuzzer.graphql.client import GraphQLResponse
from fuzzer.oracle.auth import detect_auth_bypass
from fuzzer.oracle.dos import detect_dos
from fuzzer.oracle.error_leakage import detect_error_leakage
from fuzzer.oracle.injection import detect_injection


def response(body, text=None, latency=10, timeout=False, size=100, status=200):
    return GraphQLResponse(status, body, text or str(body), latency, size, timeout)


def test_auth_bypass_detection():
    findings = detect_auth_bypass(response({"data": {"me": {"email": "a@b.c"}}}), "s", 0, "me", "protected_query_without_token", "no_token", True)
    assert findings and findings[0]["finding_type"] == "AUTH_BYPASS_CANDIDATE"


def test_error_leakage_detection():
    findings = detect_error_leakage(response({"errors": []}, "Traceback SQLite Exception"), "s", 0, "x", "t", "no_token")
    assert findings


def test_injection_reflection_detection():
    findings = detect_injection(response({"data": {"search": "' OR '1'='1"}}), {"q": "' OR '1'='1"}, "s", 0, "search", "injection_payload_query", "no_token")
    assert findings


def test_dos_timeout_detection():
    findings = detect_dos(response(None, timeout=True), QueryShape(depth=4), "s", 0, "posts", "deeply_nested_query", "no_token")
    assert findings
