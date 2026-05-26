from __future__ import annotations

from fuzzer.ga.chromosome import QueryShape
from fuzzer.graphql.client import GraphQLResponse
from fuzzer.oracle.base import make_finding


def detect_dos(
    response: GraphQLResponse,
    query_shape: QueryShape,
    sequence_id: str,
    generation: int,
    operation: str | None,
    transition: str,
    auth_mode: str,
    baseline_latency_ms: float = 200,
    baseline_response_size: int = 4096,
) -> list[dict]:
    bad = (
        response.timeout
        or response.latency_ms > max(1000, baseline_latency_ms * 5)
        or response.response_size > max(50000, baseline_response_size * 10)
        or response.status_code >= 500
    )
    if bad:
        return [
            make_finding(
                "DOS_COST_ANOMALY",
                "medium",
                sequence_id,
                generation,
                operation,
                transition,
                auth_mode,
                response,
                {
                    "reason": "timeout, latency, size, or server error under costly query shape",
                    "depth": query_shape.depth,
                    "alias_count": query_shape.alias_count,
                    "batch_size": query_shape.batch_size if query_shape.batch else 1,
                },
            )
        ]
    return []
