from __future__ import annotations

from typing import Any

from fuzzer.ga.chromosome import Chromosome
from fuzzer.security.targets import (
    AUTH_BYPASS,
    BFLA_ADMIN_LIKE_OP,
    BOLA_READ,
    BOLA_UPDATE_DELETE,
    BOPLA_SENSITIVE_FIELD_READ,
    STALE_OBJECT_ACCESS,
)


def classify_stateful_findings(chromosome: Chromosome, sequence_id: str, generation: int) -> list[dict[str, Any]]:
    """Classify sequence-level evidence after all genes have run.

    The existing per-response oracles still run for generic issues. This oracle
    adds stateful evidence such as foreign-resource access, side-effect
    verification, stale reads, and sensitive field exposure.
    """
    if not chromosome.target_category or not chromosome.execution_trace:
        return []

    category = chromosome.target_category
    traces = chromosome.execution_trace
    target_operation = _target_operation(chromosome.target_id)
    findings: list[dict[str, Any]] = []

    if category in {AUTH_BYPASS, BFLA_ADMIN_LIKE_OP}:
        suspicious = [
            t
            for t in traces
            if _matches_target_operation(t, target_operation)
            and t["auth_mode"] in {"no_token", "bad_token", "empty_token", "wrong_prefix", "low_privilege"}
        ]
        for trace in suspicious:
            confidence = _confidence_for_response(trace)
            if confidence == "not_finding" and category == BFLA_ADMIN_LIKE_OP and trace.get("resolver_reached") and trace.get("error_signature"):
                confidence = "probable"
            if confidence != "not_finding":
                reason = (
                    "admin-like resolver reached and produced execution error under unauthorized context"
                    if category == BFLA_ADMIN_LIKE_OP and trace.get("error_signature") and confidence == "probable"
                    else "unauthorized context produced business or resolver evidence"
                )
                findings.append(_finding(category, confidence, chromosome, sequence_id, generation, trace, reason))

    elif category == BOPLA_SENSITIVE_FIELD_READ:
        target_field = _target_sensitive_field(chromosome.target_id)
        for trace in traces:
            if not _matches_target_operation(trace, target_operation):
                continue
            if (target_field and _has_field_data(trace.get("body"), target_field)) or (not target_field and _has_sensitive_data(trace.get("body"))):
                findings.append(_finding(category, "confirmed", chromosome, sequence_id, generation, trace, "sensitive-looking field returned in response"))

    elif category == BOLA_READ:
        for trace in traces:
            resource = trace.get("selected_resource") or {}
            actor = trace.get("actor")
            foreign_resource = isinstance(resource, dict) and resource.get("owner_actor") and resource.get("owner_actor") != actor
            if (
                _matches_target_operation(trace, target_operation)
                and trace.get("transition") == "query_other_resource"
                and _has_non_null_data(trace.get("body"))
                and _response_contains_resource_id(trace)
                and foreign_resource
            ):
                findings.append(_finding(category, "confirmed", chromosome, sequence_id, generation, trace, "other-actor resource read returned non-null data"))

    elif category == BOLA_UPDATE_DELETE:
        attack_trace = next(
            (
                t
                for t in traces
                if _matches_target_operation(t, target_operation)
                and _foreign_mutation_trace(t)
                and _has_non_null_data(t.get("body"))
                and _response_contains_resource_id(t)
            ),
            None,
        )
        verify_trace = next(
            (
                t
                for t in traces
                if t.get("transition") in {"query_own_resource", "query_deleted_resource"}
                and _has_non_null_data(t.get("body"))
                and _same_selected_resource(attack_trace, t)
                and _response_contains_resource_id(t)
            ),
            None,
        )
        side_effect_confirmed, side_effect_evidence = _side_effect_evidence(attack_trace, verify_trace)
        if attack_trace and verify_trace and side_effect_confirmed:
            findings.append(
                _finding(
                    category,
                    "confirmed",
                    chromosome,
                    sequence_id,
                    generation,
                    attack_trace,
                    "foreign mutation followed by owner-visible verification data",
                    {
                        "verify_operation": verify_trace.get("operation"),
                        "verify_status_code": verify_trace.get("status_code"),
                        **side_effect_evidence,
                    },
                )
            )
        elif attack_trace:
            findings.append(
                _finding(
                    category,
                    "probable",
                    chromosome,
                    sequence_id,
                    generation,
                    attack_trace,
                    "foreign mutation returned non-null data but owner-visible side effect was not confirmed",
                    side_effect_evidence if verify_trace else None,
                )
            )

    elif category == STALE_OBJECT_ACCESS:
        for trace in traces:
            resource = trace.get("selected_resource") or {}
            deleted_resource = isinstance(resource, dict) and resource.get("state") == "deleted"
            if (
                _matches_target_operation(trace, target_operation)
                and trace.get("transition") == "query_deleted_resource"
                and _has_non_null_data(trace.get("body"))
                and _response_contains_resource_id(trace)
                and deleted_resource
            ):
                findings.append(_finding(category, "confirmed", chromosome, sequence_id, generation, trace, "deleted resource read returned non-null data"))

    return findings


def _finding(
    category: str,
    confidence: str,
    chromosome: Chromosome,
    sequence_id: str,
    generation: int,
    trace: dict[str, Any],
    reason: str,
    extra_evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    severity = "high" if confidence == "confirmed" else "medium" if confidence == "probable" else "low"
    evidence = {
        "reason": reason,
        "status_code": trace.get("status_code"),
        "actor": trace.get("actor"),
        "selected_resource": trace.get("selected_resource"),
        "error_signature": trace.get("error_signature"),
        "schedule_path": chromosome.schedule_path,
    }
    if extra_evidence:
        evidence.update(extra_evidence)
    return {
        "finding_type": f"STATEFUL_{category}",
        "severity": severity,
        "confidence": confidence,
        "sequence_id": sequence_id,
        "generation": generation,
        "target_id": chromosome.target_id,
        "target_category": chromosome.target_category,
        "operation": trace.get("operation"),
        "transition": trace.get("transition"),
        "auth_mode": trace.get("auth_mode"),
        "evidence": evidence,
    }


def _confidence_for_response(trace: dict[str, Any]) -> str:
    body = trace.get("body")
    if _has_sensitive_data(body) or _has_non_null_data(body):
        return "confirmed"
    return "not_finding"


def _target_operation(target_id: str | None) -> str | None:
    parts = (target_id or "").split(":")
    if len(parts) < 3:
        return None
    category = parts[0]
    if category in {AUTH_BYPASS, BFLA_ADMIN_LIKE_OP, BOPLA_SENSITIVE_FIELD_READ}:
        return parts[2]
    if category in {BOLA_READ, BOLA_UPDATE_DELETE} and len(parts) >= 4:
        return parts[3]
    if category == STALE_OBJECT_ACCESS and len(parts) >= 5:
        return parts[4]
    return None


def _target_sensitive_field(target_id: str | None) -> str | None:
    parts = (target_id or "").split(":")
    if len(parts) >= 4 and parts[0] == BOPLA_SENSITIVE_FIELD_READ:
        return parts[3]
    return None


def _matches_target_operation(trace: dict[str, Any], target_operation: str | None) -> bool:
    return not target_operation or target_operation == "none" or trace.get("operation") == target_operation


def _has_non_null_data(body: Any) -> bool:
    if not isinstance(body, dict) or "data" not in body:
        return False
    data = body.get("data")
    if isinstance(data, dict):
        return any(value is not None for value in data.values())
    return data not in (None, {})


def _has_sensitive_data(body: Any) -> bool:
    sensitive = {"token", "password", "secret", "private", "admin", "role", "permission", "internalnote", "moderationnote", "resettoken"}

    def walk(value: Any) -> bool:
        if isinstance(value, dict):
            for key, child in value.items():
                if key.lower() in sensitive and child is not None:
                    return True
                if walk(child):
                    return True
        elif isinstance(value, list):
            return any(walk(item) for item in value)
        return False

    return walk(body)


def _has_field_data(body: Any, field_name: str) -> bool:
    target = field_name.lower()

    def walk(value: Any) -> bool:
        if isinstance(value, dict):
            for key, child in value.items():
                if key.lower() == target and child is not None:
                    return True
                if walk(child):
                    return True
        elif isinstance(value, list):
            return any(walk(item) for item in value)
        return False

    return walk(body)


def _response_contains_resource_id(trace: dict[str, Any]) -> bool:
    resource = trace.get("selected_resource") or {}
    if not isinstance(resource, dict):
        return False
    resource_id = resource.get("id")
    if resource_id is None:
        return False
    return _contains_id_value(trace.get("body"), str(resource_id))


def _contains_id_value(value: Any, resource_id: str) -> bool:
    if isinstance(value, dict):
        for key, child in value.items():
            if key.lower() in {"id", "_id", "uuid"} and child is not None and str(child) == resource_id:
                return True
            if _contains_id_value(child, resource_id):
                return True
    elif isinstance(value, list):
        return any(_contains_id_value(item, resource_id) for item in value)
    return False


def _same_selected_resource(left: dict[str, Any] | None, right: dict[str, Any]) -> bool:
    if left is None:
        return False
    left_resource = left.get("selected_resource") or {}
    right_resource = right.get("selected_resource") or {}
    if not isinstance(left_resource, dict) or not isinstance(right_resource, dict):
        return False
    return (
        left_resource.get("resource_type") == right_resource.get("resource_type")
        and left_resource.get("id") is not None
        and str(left_resource.get("id")) == str(right_resource.get("id"))
    )


def _side_effect_evidence(attack_trace: dict[str, Any] | None, verify_trace: dict[str, Any] | None) -> tuple[bool, dict[str, Any]]:
    if attack_trace is None or verify_trace is None:
        return False, {}
    attack_payload = _single_result_payload(attack_trace.get("body"))
    verify_payload = _single_result_payload(verify_trace.get("body"))
    if not isinstance(attack_payload, dict) or not isinstance(verify_payload, dict):
        return False, {"side_effect_confirmed": False}

    if attack_trace.get("transition") == "delete_other_resource":
        deleted = _field_truthy(attack_payload, "deleted") or _field_truthy(verify_payload, "deleted")
        return deleted, {"side_effect_confirmed": deleted, "side_effect_field": "deleted" if deleted else None}

    changed_fields: list[str] = []
    for field in ("title", "content", "body", "public"):
        if field in attack_payload and field in verify_payload and attack_payload[field] is not None and attack_payload[field] == verify_payload[field]:
            changed_fields.append(field)
    return bool(changed_fields), {"side_effect_confirmed": bool(changed_fields), "side_effect_fields": changed_fields}


def _single_result_payload(body: Any) -> Any:
    if not isinstance(body, dict):
        return None
    data = body.get("data")
    if not isinstance(data, dict):
        return None
    non_null_values = [value for value in data.values() if value is not None]
    if len(non_null_values) != 1:
        return None
    return non_null_values[0]


def _field_truthy(value: Any, field_name: str) -> bool:
    if isinstance(value, dict):
        for key, child in value.items():
            if key.lower() == field_name.lower():
                return child is True or str(child).lower() == "true"
            if _field_truthy(child, field_name):
                return True
    elif isinstance(value, list):
        return any(_field_truthy(item, field_name) for item in value)
    return False


def _foreign_mutation_trace(trace: dict[str, Any]) -> bool:
    if trace.get("transition") not in {"update_other_resource", "delete_other_resource"}:
        return False
    resource = trace.get("selected_resource") or {}
    if not isinstance(resource, dict):
        return False
    owner = resource.get("owner_actor")
    actor = trace.get("actor")
    return bool(owner and owner != actor)
