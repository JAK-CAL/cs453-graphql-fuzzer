from __future__ import annotations

from fuzzer.graphql.client import GraphQLResponse
from fuzzer.oracle.base import has_data, make_finding, response_text

SENSITIVE_FIELDS = ["email", "role", "permission", "token", "password", "admin", "secret", "private", "owner"]


def detect_auth_bypass(
    response: GraphQLResponse,
    sequence_id: str,
    generation: int,
    operation: str | None,
    transition: str,
    auth_mode: str,
    expected_negative: bool = False,
) -> list[dict]:
    text = response_text(response).lower()
    matched = [field for field in SENSITIVE_FIELDS if field in text]
    suspicious_auth = auth_mode in {"no_token", "bad_token", "empty_token", "wrong_prefix", "low_privilege"}
    if suspicious_auth and has_data(response) and (matched or expected_negative):
        return [
            make_finding(
                "AUTH_BYPASS_CANDIDATE",
                "high",
                sequence_id,
                generation,
                operation,
                transition,
                auth_mode,
                response,
                {"reason": "negative or unauthenticated request returned data", "matched_keywords": matched, "response_snippet": response_text(response)[:500]},
            )
        ]
    return []
