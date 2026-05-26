from __future__ import annotations

from fuzzer.graphql.client import GraphQLResponse
from fuzzer.oracle.base import make_finding, response_text

ERROR_LEAK_KEYWORDS = [
    "Traceback",
    "Exception",
    "SQL syntax",
    "SQLite",
    "PostgreSQL",
    "MySQL",
    "MongoError",
    "TypeError",
    "ReferenceError",
    "Resolver",
    "Internal Server Error",
    "stack trace",
]


def detect_error_leakage(response: GraphQLResponse, sequence_id: str, generation: int, operation: str | None, transition: str, auth_mode: str) -> list[dict]:
    text = response_text(response)
    lower = text.lower()
    matched = [kw for kw in ERROR_LEAK_KEYWORDS if kw.lower() in lower]
    if matched:
        return [
            make_finding(
                "ERROR_LEAKAGE",
                "medium",
                sequence_id,
                generation,
                operation,
                transition,
                auth_mode,
                response,
                {"reason": "response contains internal error keyword", "matched_keywords": matched, "response_snippet": text[:500]},
            )
        ]
    return []
