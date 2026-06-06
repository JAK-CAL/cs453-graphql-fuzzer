from __future__ import annotations

from dataclasses import dataclass

from fuzzer.graphql.schema_types import Operation


AUTH_BYPASS = "AUTH_BYPASS"
BOLA_READ = "BOLA_READ"
BOLA_UPDATE_DELETE = "BOLA_UPDATE_DELETE"
STALE_OBJECT_ACCESS = "STALE_OBJECT_ACCESS"
BFLA_ADMIN_LIKE_OP = "BFLA_ADMIN_LIKE_OP"
BOPLA_SENSITIVE_FIELD_READ = "BOPLA_SENSITIVE_FIELD_READ"
COST_ANOMALY = "COST_ANOMALY"
INJECTION = "INJECTION"

SENSITIVE_FIELD_NAMES = {
    "resetToken",
    "internalNote",
    "moderationNote",
    "token",
    "password",
    "secret",
    "private",
    "admin",
    "role",
    "permission",
}


@dataclass(frozen=True)
class SecurityTarget:
    target_id: str
    category: str
    object_type: str | None = None
    setup_operation: str | None = None
    target_operation: str | None = None
    verify_operation: str | None = None
    sensitive_field: str | None = None
    expected_policy: str = "deny-or-sanitize"
    confidence: float = 0.5


def _lower(value: str | None) -> str:
    return (value or "").lower()


def _has_id_arg(op: Operation) -> bool:
    return any("id" in arg.name.lower() for arg in op.args)


def _is_create(op: Operation) -> bool:
    name = _lower(op.name)
    return op.operation_type == "mutation" and any(term in name for term in ("create", "register", "add", "new"))


def _is_update(op: Operation) -> bool:
    name = _lower(op.name)
    return op.operation_type == "mutation" and any(term in name for term in ("update", "edit", "patch"))


def _is_delete(op: Operation) -> bool:
    name = _lower(op.name)
    return op.operation_type == "mutation" and any(term in name for term in ("delete", "remove"))


def _is_read_by_id(op: Operation) -> bool:
    name = _lower(op.name)
    return op.operation_type == "query" and _has_id_arg(op) and not any(term in name for term in ("secure", "preview", "public", "history"))


def _is_admin_like(op: Operation) -> bool:
    name = _lower(op.name)
    fields = " ".join(op.selectable_fields).lower()
    return any(term in f"{name} {fields}" for term in ("admin", "secret", "private", "audit", "system"))


def _sensitive_fields(op: Operation) -> list[str]:
    result = []
    for field in op.selectable_fields:
        lowered = field.lower()
        if field in SENSITIVE_FIELD_NAMES or any(term.lower() in lowered for term in SENSITIVE_FIELD_NAMES):
            result.append(field)
    return result


def _target_id(category: str, *parts: str | None) -> str:
    body = ":".join(part or "none" for part in parts)
    return f"{category}:{body}"


def build_security_targets(operations: list[Operation]) -> list[SecurityTarget]:
    """Build black-box security hypotheses from the schema-visible operation pool.

    These are not ground-truth vulnerability labels. They are candidate policies
    that the fuzzer should exercise with stateful schedules.
    """
    targets: list[SecurityTarget] = []
    by_return: dict[str, list[Operation]] = {}
    for op in operations:
        if op.return_type:
            by_return.setdefault(op.return_type, []).append(op)

    for op in operations:
        if _is_admin_like(op):
            targets.append(
                SecurityTarget(
                    _target_id(BFLA_ADMIN_LIKE_OP, op.return_type, op.name),
                    BFLA_ADMIN_LIKE_OP,
                    object_type=op.return_type,
                    target_operation=op.name,
                    expected_policy="low-privilege actor must not execute admin-like resolver",
                    confidence=0.85,
                )
            )
        if op.auth_required_guess or op.sensitive_field_guess:
            targets.append(
                SecurityTarget(
                    _target_id(AUTH_BYPASS, op.return_type, op.name),
                    AUTH_BYPASS,
                    object_type=op.return_type,
                    target_operation=op.name,
                    expected_policy="unauthenticated or invalid-auth request must not return business data",
                    confidence=0.65,
                )
            )
        for field in _sensitive_fields(op):
            targets.append(
                SecurityTarget(
                    _target_id(BOPLA_SENSITIVE_FIELD_READ, op.return_type, op.name, field),
                    BOPLA_SENSITIVE_FIELD_READ,
                    object_type=op.return_type,
                    target_operation=op.name,
                    sensitive_field=field,
                    expected_policy=f"sensitive field {field} must be denied or sanitized",
                    confidence=0.8,
                )
            )
        if op.args:
            targets.append(
                SecurityTarget(
                    _target_id(INJECTION, op.return_type, op.name),
                    INJECTION,
                    object_type=op.return_type,
                    target_operation=op.name,
                    expected_policy="structured payloads must not trigger injection-like behavior",
                    confidence=0.45,
                )
            )

    for object_type, ops in by_return.items():
        producers = [op for op in ops if _is_create(op)]
        readers = [op for op in ops if _is_read_by_id(op)]
        modifiers = [op for op in ops if _is_update(op) or _is_delete(op)]
        deleters = [op for op in ops if _is_delete(op)]
        for producer in producers:
            for reader in readers:
                targets.append(
                    SecurityTarget(
                        _target_id(BOLA_READ, object_type, producer.name, reader.name),
                        BOLA_READ,
                        object_type=object_type,
                        setup_operation=producer.name,
                        target_operation=reader.name,
                        verify_operation=reader.name,
                        expected_policy="other actor must not read owner resource by id",
                        confidence=0.75,
                    )
                )
            for modifier in modifiers:
                targets.append(
                    SecurityTarget(
                        _target_id(BOLA_UPDATE_DELETE, object_type, producer.name, modifier.name),
                        BOLA_UPDATE_DELETE,
                        object_type=object_type,
                        setup_operation=producer.name,
                        target_operation=modifier.name,
                        verify_operation=readers[0].name if readers else None,
                        expected_policy="other actor must not mutate owner resource",
                        confidence=0.75,
                    )
                )
            for deleter in deleters:
                for reader in readers:
                    targets.append(
                        SecurityTarget(
                            _target_id(STALE_OBJECT_ACCESS, object_type, producer.name, deleter.name, reader.name),
                            STALE_OBJECT_ACCESS,
                            object_type=object_type,
                            setup_operation=producer.name,
                            target_operation=reader.name,
                            verify_operation=reader.name,
                            expected_policy="deleted resource must not remain readable",
                            confidence=0.7,
                        )
                    )

    return _dedupe_targets(targets)


def _dedupe_targets(targets: list[SecurityTarget]) -> list[SecurityTarget]:
    seen: set[str] = set()
    unique: list[SecurityTarget] = []
    for target in targets:
        if target.target_id in seen:
            continue
        seen.add(target.target_id)
        unique.append(target)
    return unique

