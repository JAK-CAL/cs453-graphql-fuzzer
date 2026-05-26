from __future__ import annotations

from fuzzer.graphql.client import GraphQLResponse
from fuzzer.oracle.base import has_data, make_finding, response_text


def compare_auth_modes(
    valid_response: GraphQLResponse,
    other_response: GraphQLResponse,
    sequence_id: str,
    generation: int,
    operation: str | None,
    transition: str,
    auth_mode: str,
) -> list[dict]:
    if has_data(valid_response) and has_data(other_response):
        valid_text = response_text(valid_response)
        other_text = response_text(other_response)
        if valid_text[:300] == other_text[:300] or len(other_text) > len(valid_text) * 0.8:
            return [
                make_finding(
                    "DIFFERENTIAL_AUTH_ANOMALY",
                    "high",
                    sequence_id,
                    generation,
                    operation,
                    transition,
                    auth_mode,
                    other_response,
                    {"reason": "unauthorized response resembles authorized response", "response_snippet": other_text[:500]},
                )
            ]
    return []
