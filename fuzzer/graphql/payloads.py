from __future__ import annotations

from typing import Any

from fuzzer.fsm.storage import FSMStorage
from fuzzer.graphql.schema_types import Operation

SQL_PAYLOADS = ["' OR '1'='1", '" OR "1"="1', "'; SELECT 1; --"]
XSS_PAYLOADS = ["<script>alert(1)</script>"]
PATH_TRAVERSAL_PAYLOADS = ["../../etc/passwd"]
COMMAND_PAYLOADS = ["$(id)", "`id`"]
STRESS_PAYLOADS = ["A" * 2048]
SECURITY_PAYLOADS = SQL_PAYLOADS + XSS_PAYLOADS + PATH_TRAVERSAL_PAYLOADS + COMMAND_PAYLOADS + STRESS_PAYLOADS


def default_value_for_type(type_name: str, required: bool = False) -> Any:
    base = type_name.replace("!", "")
    if base == "ID":
        return "1"
    if base == "String":
        return "test"
    if base == "Int":
        return 1
    if base == "Float":
        return 1.0
    if base == "Boolean":
        return True
    return "test" if required else None


def payload_for_operation(operation: Operation, storage: FSMStorage, security_payload: str | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    for arg in operation.args:
        name_l = arg.name.lower()
        value = default_value_for_type(arg.type_name, arg.required)
        if "id" in name_l and storage.known_ids:
            value = next(iter(storage.known_ids))
        elif "user" in name_l and storage.actors:
            actor = next(iter(storage.actors.values()))
            value = actor.username or value
        elif "password" in name_l:
            value = "password"
        if security_payload and arg.type_name in {"String", "ID"}:
            value = security_payload
        payload[arg.name] = value
    return payload
