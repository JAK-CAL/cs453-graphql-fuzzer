from __future__ import annotations

import json
from pathlib import Path
from typing import Any

try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover
    yaml = None

from fuzzer.storage.json_logger import write_json


SENSITIVE_FIELD_CATEGORY = "BOPLA_SENSITIVE_FIELD_READ"


def compare_with_ground_truth(result_dir: str | Path, ground_truth_path: str | Path | None = None) -> dict[str, Any]:
    root = Path(result_dir)
    gt_path = _resolve_ground_truth_path(root, ground_truth_path)
    if gt_path is None or not gt_path.exists():
        return {
            "ground_truth_path": str(gt_path) if gt_path else None,
            "available": False,
            "reason": "ground truth file not found",
        }

    ground_truth = json.loads(gt_path.read_text(encoding="utf-8"))
    findings = _load_json(root / "findings.json", [])
    vulnerable = [_entry("vulnerable", item) for item in ground_truth.get("vulnerable", [])]
    secure = [_entry("secure", item) for item in ground_truth.get("secure", [])]
    vulnerable_keys = {_identity(entry) for entry in vulnerable}
    secure_keys = {_identity(entry) for entry in secure}

    true_positive_keys: set[tuple[str, str, str | None]] = set()
    false_positive_keys: set[tuple[str, str, str | None]] = set()
    unclassified: list[dict[str, Any]] = []
    matched_findings: list[dict[str, Any]] = []

    for finding in findings:
        resolver = finding.get("operation")
        if not resolver:
            unclassified.append({"finding": finding, "reason": "missing operation"})
            continue
        category = _category_for_finding(finding)
        tp_matches = _matching_keys(vulnerable_keys, resolver, category)
        fp_matches = _matching_keys(secure_keys, resolver, category)
        if tp_matches:
            true_positive_keys.update(tp_matches)
            matched_findings.append({"kind": "TP", "resolver": resolver, "category": category, "matches": _format_keys(tp_matches)})
        elif fp_matches:
            false_positive_keys.update(fp_matches)
            matched_findings.append({"kind": "FP", "resolver": resolver, "category": category, "matches": _format_keys(fp_matches)})
        else:
            unclassified.append({"finding": finding, "reason": "resolver/category not in ground truth"})

    false_negative_keys = vulnerable_keys - true_positive_keys
    tp = len(true_positive_keys)
    fp = len(false_positive_keys)
    fn = len(false_negative_keys)
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    f1 = 2 * precision * recall / max(1e-12, precision + recall)
    comparison = {
        "ground_truth_path": str(gt_path),
        "available": True,
        "vulnerable_total": len(vulnerable_keys),
        "secure_total": len(secure_keys),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "true_positives": _format_keys(true_positive_keys),
        "false_positives": _format_keys(false_positive_keys),
        "false_negatives": _format_keys(false_negative_keys),
        "unclassified_finding_count": len(unclassified),
        "unclassified_findings": unclassified,
        "matched_findings": matched_findings,
        "category_recall": _category_recall(vulnerable_keys, true_positive_keys),
    }
    write_json(root / "ground_truth_comparison.json", comparison)
    _write_markdown_summary(root / "evaluation_summary.md", comparison)
    return comparison


def _resolve_ground_truth_path(root: Path, explicit: str | Path | None) -> Path | None:
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    config_path = root / "config.resolved.yaml"
    if config_path.exists():
        config = _load_yaml(config_path)
        configured = ((config.get("target") or {}).get("ground_truth_path") if isinstance(config, dict) else None)
        if configured:
            candidates.append(Path(configured))
    candidates.extend(
        [
            Path("../vulnerable-graphql-api/ground-truth/ground_truth.json"),
            Path("..") / "vulnerable-graphql-api" / "ground-truth" / "ground_truth.json",
            Path.cwd().parent / "vulnerable-graphql-api" / "ground-truth" / "ground_truth.json",
        ]
    )
    for candidate in candidates:
        resolved = candidate if candidate.is_absolute() else (Path.cwd() / candidate)
        if resolved.exists():
            return resolved
    return candidates[0] if candidates else None


def _load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def _load_yaml(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if yaml:
        return yaml.safe_load(text) or {}
    return {}


def _entry(kind: str, item: dict[str, Any]) -> dict[str, Any]:
    return {
        "kind": kind,
        "owasp": item.get("owasp"),
        "resolver": item.get("resolver"),
        "object_type": item.get("objectType"),
    }


def _identity(entry: dict[str, Any]) -> tuple[str, str, str | None]:
    return (entry["owasp"], entry["resolver"], entry.get("object_type"))


def _category_for_finding(finding: dict[str, Any]) -> str | None:
    if finding.get("target_category"):
        return str(finding["target_category"])
    finding_type = str(finding.get("finding_type") or "")
    if finding_type.startswith("STATEFUL_"):
        return finding_type.removeprefix("STATEFUL_")
    if "AUTH" in finding_type:
        return SENSITIVE_FIELD_CATEGORY
    if "DOS" in finding_type or "COST" in finding_type:
        return "COST_ANOMALY"
    if "INJECTION" in finding_type:
        return "INJECTION"
    return None


def _matching_keys(keys: set[tuple[str, str, str | None]], resolver: str, category: str | None) -> set[tuple[str, str, str | None]]:
    resolver_matches = {key for key in keys if key[1] == resolver}
    if category:
        category_matches = {key for key in resolver_matches if key[0] == category}
        if category_matches:
            return category_matches
    return resolver_matches if category is None else set()


def _format_keys(keys: set[tuple[str, str, str | None]]) -> list[dict[str, str | None]]:
    return [
        {"owasp": owasp, "resolver": resolver, "objectType": object_type}
        for owasp, resolver, object_type in sorted(keys)
    ]


def _category_recall(vulnerable_keys: set[tuple[str, str, str | None]], true_positive_keys: set[tuple[str, str, str | None]]) -> dict[str, dict[str, float]]:
    categories = sorted({key[0] for key in vulnerable_keys})
    result: dict[str, dict[str, float]] = {}
    for category in categories:
        total = {key for key in vulnerable_keys if key[0] == category}
        found = {key for key in true_positive_keys if key[0] == category}
        result[category] = {"found": len(found), "total": len(total), "recall": len(found) / max(1, len(total))}
    return result


def _write_markdown_summary(path: Path, comparison: dict[str, Any]) -> None:
    if not comparison.get("available"):
        path.write_text("# Evaluation Summary\n\nGround truth is not available.\n", encoding="utf-8")
        return
    lines = [
        "# Evaluation Summary",
        "",
        "| Metric | Value |",
        "| --- | ---: |",
        f"| TP | {comparison['tp']} |",
        f"| FP | {comparison['fp']} |",
        f"| FN | {comparison['fn']} |",
        f"| Precision | {comparison['precision']:.3f} |",
        f"| Recall | {comparison['recall']:.3f} |",
        f"| F1 | {comparison['f1']:.3f} |",
        f"| Unclassified findings | {comparison['unclassified_finding_count']} |",
        "",
        "## Category Recall",
        "",
        "| Category | Found | Total | Recall |",
        "| --- | ---: | ---: | ---: |",
    ]
    for category, value in comparison["category_recall"].items():
        lines.append(f"| {category} | {value['found']} | {value['total']} | {value['recall']:.3f} |")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
