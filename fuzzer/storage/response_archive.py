from __future__ import annotations

from pathlib import Path

from fuzzer.graphql.client import GraphQLResponse
from fuzzer.storage.json_logger import write_json


class ResponseArchive:
    def __init__(self, result_dir: str | Path, max_bytes: int = 4096):
        self.response_dir = Path(result_dir) / "responses"
        self.response_dir.mkdir(parents=True, exist_ok=True)
        self.max_bytes = max_bytes
        self.count = 0

    def save(self, response: GraphQLResponse) -> Path:
        self.count += 1
        path = self.response_dir / f"response_{self.count:06d}.json"
        write_json(
            path,
            {
                "status_code": response.status_code,
                "latency_ms": response.latency_ms,
                "response_size": response.response_size,
                "timeout": response.timeout,
                "auth_mode": response.auth_mode,
                "request_query": (response.request_query or "")[: self.max_bytes],
                "request_variables": response.request_variables or {},
                "body": response.body,
                "text": response.text[: self.max_bytes],
            },
        )
        return path
