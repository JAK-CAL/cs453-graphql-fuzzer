from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any
from urllib import error, request

try:
    import requests
except ModuleNotFoundError:  # pragma: no cover - used only before dependencies are installed
    requests = None

from fuzzer.fsm.storage import FSMStorage


@dataclass
class GraphQLResponse:
    status_code: int
    body: Any
    text: str
    latency_ms: float
    response_size: int
    timeout: bool
    request_query: str | None = None
    request_variables: dict[str, Any] | None = None
    auth_mode: str | None = None


class GraphQLClient:
    def __init__(self, endpoint: str, timeout_seconds: float = 5, storage: FSMStorage | None = None):
        self.endpoint = endpoint
        self.timeout_seconds = timeout_seconds
        self.storage = storage or FSMStorage()

    def headers_for_auth(self, auth_mode: str) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        self.storage.active_actor = self.storage.actor_for_auth_mode(auth_mode)
        token = self.storage.get_token()
        if auth_mode == "valid_token" and token:
            headers["Authorization"] = f"Bearer {token}"
        elif auth_mode == "bad_token":
            headers["Authorization"] = "Bearer invalid-token"
        elif auth_mode == "empty_token":
            headers["Authorization"] = "Bearer "
        elif auth_mode == "wrong_prefix" and token:
            headers["Authorization"] = f"Token {token}"
        elif auth_mode == "low_privilege":
            low = self.storage.get_token("low_privilege") or token
            if low:
                headers["Authorization"] = f"Bearer {low}"
        return headers

    def execute(
        self,
        query_or_batch: str | list[dict[str, Any]],
        variables: dict[str, Any] | None = None,
        auth_mode: str = "no_token",
    ) -> GraphQLResponse:
        body: Any
        if isinstance(query_or_batch, list):
            body = query_or_batch
        else:
            body = {"query": query_or_batch, "variables": variables or {}}
        actor_name = self.storage.actor_for_auth_mode(auth_mode)
        cookies = self.storage.get_actor_cookies(actor_name)
        start = time.perf_counter()
        try:
            if requests:
                resp = requests.post(
                    self.endpoint,
                    headers=self.headers_for_auth(auth_mode),
                    cookies=cookies,
                    json=body,
                    timeout=self.timeout_seconds,
                )
                self.storage.set_actor_cookies(actor_name, requests.utils.dict_from_cookiejar(resp.cookies))
            else:
                resp = _urllib_post(self.endpoint, self.headers_for_auth(auth_mode), body, self.timeout_seconds)
            latency_ms = (time.perf_counter() - start) * 1000
            try:
                parsed = resp.json()
            except ValueError:
                parsed = None
            return GraphQLResponse(
                status_code=resp.status_code,
                body=parsed,
                text=resp.text,
                latency_ms=latency_ms,
                response_size=len(resp.content),
                timeout=False,
                request_query=json.dumps(query_or_batch) if isinstance(query_or_batch, list) else query_or_batch,
                request_variables=variables or {},
                auth_mode=auth_mode,
            )
        except TimeoutError:
            latency_ms = (time.perf_counter() - start) * 1000
            return GraphQLResponse(0, None, "timeout", latency_ms, 0, True, str(query_or_batch), variables or {}, auth_mode)
        except Exception as exc:
            latency_ms = (time.perf_counter() - start) * 1000
            return GraphQLResponse(0, {"errors": [{"message": str(exc)}]}, str(exc), latency_ms, 0, False, str(query_or_batch), variables or {}, auth_mode)


class _UrllibResponse:
    def __init__(self, status_code: int, content: bytes):
        self.status_code = status_code
        self.content = content
        self.text = content.decode("utf-8", errors="replace")

    def json(self) -> Any:
        return json.loads(self.text)


def _urllib_post(endpoint: str, headers: dict[str, str], body: Any, timeout_seconds: float) -> _UrllibResponse:
    data = json.dumps(body).encode("utf-8")
    req = request.Request(endpoint, data=data, headers=headers, method="POST")
    try:
        with request.urlopen(req, timeout=timeout_seconds) as resp:
            return _UrllibResponse(resp.status, resp.read())
    except TimeoutError:
        raise
    except error.HTTPError as exc:
        return _UrllibResponse(exc.code, exc.read())
