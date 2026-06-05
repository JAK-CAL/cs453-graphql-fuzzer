from __future__ import annotations


def collect_findings(chromosomes) -> list[dict]:
    findings = []
    seen = set()
    for chrom in chromosomes:
        for finding in chrom.findings:
            key = (
                finding.get("finding_type"),
                finding.get("operation"),
                finding.get("transition"),
                finding.get("auth_mode"),
                finding.get("target_id"),
                finding.get("confidence"),
                str(finding.get("evidence", {}).get("matched_keywords", "")),
            )
            if key not in seen:
                seen.add(key)
                findings.append(finding)
    return findings
