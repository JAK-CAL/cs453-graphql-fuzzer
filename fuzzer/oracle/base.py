from __future__ import annotations

import json
from typing import Any

from fuzzer.graphql.client import GraphQLResponse


def response_text(response: GraphQLResponse) -> str:
    if response.text:
        return response.text
    try:
        return json.dumps(response.body, ensure_ascii=False)
    except TypeError:
        return str(response.body)


def has_data(response: GraphQLResponse) -> bool:
    body = response.body
    if isinstance(body, list):
        return any(isinstance(item, dict) and _has_non_null_data(item.get("data")) for item in body)
    return isinstance(body, dict) and _has_non_null_data(body.get("data"))


def _has_non_null_data(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, dict):
        return any(_has_non_null_data(child) for child in value.values())
    if isinstance(value, list):
        return any(_has_non_null_data(item) for item in value)
    return True


def has_errors(response: GraphQLResponse) -> bool:
    body = response.body
    if isinstance(body, list):
        return any(isinstance(item, dict) and item.get("errors") for item in body)
    return isinstance(body, dict) and bool(body.get("errors"))


def make_finding(
    finding_type: str,
    severity: str,
    sequence_id: str,
    generation: int,
    operation: str | None,
    transition: str,
    auth_mode: str,
    response: GraphQLResponse,
    evidence: dict[str, Any],
) -> dict[str, Any]:
    return {
        "finding_type": finding_type,
        "severity": severity,
        "sequence_id": sequence_id,
        "generation": generation,
        "operation": operation,
        "transition": transition,
        "auth_mode": auth_mode,
        "status_code": response.status_code,
        "latency_ms": response.latency_ms,
        "response_size": response.response_size,
        "evidence": evidence,
    }
