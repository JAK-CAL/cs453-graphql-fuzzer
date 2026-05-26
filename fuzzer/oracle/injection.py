from __future__ import annotations

from typing import Any

from fuzzer.graphql.client import GraphQLResponse
from fuzzer.graphql.payloads import SECURITY_PAYLOADS, SQL_PAYLOADS
from fuzzer.oracle.base import make_finding, response_text

DB_KEYWORDS = ["sql", "sqlite", "postgres", "mysql", "syntax", "database", "mongoerror"]


def detect_injection(
    response: GraphQLResponse,
    payload: dict[str, Any],
    sequence_id: str,
    generation: int,
    operation: str | None,
    transition: str,
    auth_mode: str,
    baseline_latency_ms: float | None = None,
) -> list[dict]:
    text = response_text(response)
    lower = text.lower()
    payload_values = [str(v) for v in payload.values() if isinstance(v, (str, int, float, bool))]
    reflected = [v for v in payload_values if v and v in text and v in SECURITY_PAYLOADS]
    db_errors = [kw for kw in DB_KEYWORDS if kw in lower]
    latency_spike = baseline_latency_ms is not None and response.latency_ms > max(1000, baseline_latency_ms * 5)
    if reflected or db_errors or latency_spike or any(sql in text for sql in SQL_PAYLOADS):
        return [
            make_finding(
                "INJECTION_SIGNAL",
                "high" if db_errors else "medium",
                sequence_id,
                generation,
                operation,
                transition,
                auth_mode,
                response,
                {"reason": "payload reflection, DB error, or latency signal", "reflected_payloads": reflected, "matched_keywords": db_errors, "response_snippet": text[:500]},
            )
        ]
    return []
