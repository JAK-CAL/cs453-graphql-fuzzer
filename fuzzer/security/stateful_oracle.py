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
    findings: list[dict[str, Any]] = []

    if category in {AUTH_BYPASS, BFLA_ADMIN_LIKE_OP}:
        suspicious = [t for t in traces if t["auth_mode"] in {"no_token", "bad_token", "empty_token", "wrong_prefix", "low_privilege"}]
        for trace in suspicious:
            confidence = _confidence_for_response(trace)
            if confidence != "not_finding":
                findings.append(_finding(category, confidence, chromosome, sequence_id, generation, trace, "unauthorized context produced business or resolver evidence"))

    elif category == BOPLA_SENSITIVE_FIELD_READ:
        for trace in traces:
            if _has_sensitive_data(trace.get("body")):
                findings.append(_finding(category, "confirmed", chromosome, sequence_id, generation, trace, "sensitive-looking field returned in response"))

    elif category == BOLA_READ:
        for trace in traces:
            resource = trace.get("selected_resource") or {}
            actor = trace.get("actor")
            foreign_resource = isinstance(resource, dict) and resource.get("owner_actor") and resource.get("owner_actor") != actor
            if trace.get("transition") == "query_other_resource" and _has_non_null_data(trace.get("body")) and foreign_resource:
                findings.append(_finding(category, "confirmed", chromosome, sequence_id, generation, trace, "other-actor resource read returned non-null data"))

    elif category == BOLA_UPDATE_DELETE:
        attack = any(_foreign_mutation_trace(t) and _has_non_null_data(t.get("body")) for t in traces)
        verify = any(t.get("transition") == "query_own_resource" and _has_non_null_data(t.get("body")) for t in traces)
        if attack and verify:
            findings.append(_finding(category, "confirmed", chromosome, sequence_id, generation, traces[-1], "foreign mutation followed by owner-visible verification data"))
        elif attack:
            findings.append(_finding(category, "probable", chromosome, sequence_id, generation, traces[-1], "foreign mutation returned non-null data"))

    elif category == STALE_OBJECT_ACCESS:
        for trace in traces:
            if trace.get("transition") == "query_deleted_resource" and _has_non_null_data(trace.get("body")):
                findings.append(_finding(category, "confirmed", chromosome, sequence_id, generation, trace, "deleted resource read returned non-null data"))

    return findings


def _finding(category: str, confidence: str, chromosome: Chromosome, sequence_id: str, generation: int, trace: dict[str, Any], reason: str) -> dict[str, Any]:
    severity = "high" if confidence == "confirmed" else "medium" if confidence == "probable" else "low"
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
        "evidence": {
            "reason": reason,
            "status_code": trace.get("status_code"),
            "actor": trace.get("actor"),
            "selected_resource": trace.get("selected_resource"),
            "schedule_path": chromosome.schedule_path,
        },
    }


def _confidence_for_response(trace: dict[str, Any]) -> str:
    body = trace.get("body")
    if _has_sensitive_data(body) or _has_non_null_data(body):
        return "confirmed"
    if trace.get("resolver_reached"):
        return "probable"
    if trace.get("has_data_key"):
        return "weak"
    return "not_finding"


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


def _foreign_mutation_trace(trace: dict[str, Any]) -> bool:
    if trace.get("transition") not in {"update_other_resource", "delete_other_resource"}:
        return False
    resource = trace.get("selected_resource") or {}
    if not isinstance(resource, dict):
        return False
    owner = resource.get("owner_actor")
    actor = trace.get("actor")
    return bool(owner and owner != actor)
