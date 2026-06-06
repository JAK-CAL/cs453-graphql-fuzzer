from __future__ import annotations


def collect_findings(chromosomes) -> list[dict]:
    findings = []
    seen = set()
    for chrom in chromosomes:
        for finding in chrom.findings:
            key = _finding_identity(finding)
            if key not in seen:
                seen.add(key)
                findings.append(finding)
    return findings


def _finding_identity(finding: dict) -> tuple:
    """Deduplicate by vulnerability identity, not by request variant.

    Different auth modes or transitions can expose the same resolver-level
    issue. Keeping auth mode in the key made auth-focused baselines look much
    stronger by counting repeated probes as separate vulnerabilities.
    """
    target_id = finding.get("target_id")
    if target_id:
        return ("target", target_id, finding.get("confidence"))
    evidence = finding.get("evidence") or {}
    matched = evidence.get("matched_keywords") or []
    if isinstance(matched, str):
        matched = [matched]
    sensitive_hint = ",".join(sorted(str(item).lower() for item in matched))
    selected_resource = evidence.get("selected_resource") or {}
    object_type = selected_resource.get("resource_type") if isinstance(selected_resource, dict) else None
    return (
        finding.get("finding_type"),
        finding.get("operation"),
        finding.get("target_category"),
        object_type,
        sensitive_hint,
    )
