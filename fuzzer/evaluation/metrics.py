from __future__ import annotations

import csv
import json
from pathlib import Path
from statistics import mean

from fuzzer.evaluation.ground_truth import compare_with_ground_truth


def load_json(path: Path, default):
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def compute_metrics(result_dir: str | Path) -> dict:
    root = Path(result_dir)
    findings = load_json(root / "findings.json", [])
    coverage = load_json(root / "coverage.json", {})
    sequences = load_json(root / "sequences.json", [])
    latencies = []
    sizes = []
    latency_path = root / "latency_log.csv"
    if latency_path.exists():
        with latency_path.open(encoding="utf-8", newline="") as handle:
            for row in csv.DictReader(handle):
                if row.get("latency_ms"):
                    latencies.append(float(row["latency_ms"]))
                if row.get("response_size"):
                    sizes.append(int(float(row["response_size"])))
    total_requests = sum(seq.get("total_request_count", 0) for seq in sequences)
    valid_requests = sum(seq.get("valid_request_count", 0) for seq in sequences)
    unique_finding_keys = {
        (f.get("finding_type"), f.get("operation"), f.get("transition"), f.get("auth_mode"))
        for f in findings
    }
    ground_truth = compare_with_ground_truth(root)
    metrics = {
        "state_coverage": coverage.get("state_coverage", 0),
        "transition_coverage": coverage.get("transition_coverage", 0),
        "operation_coverage": coverage.get("operation_coverage", 0),
        "valid_request_ratio": valid_requests / max(1, total_requests),
        "unique_error_count": sum(len(seq.get("unique_error_patterns", [])) for seq in sequences),
        "total_findings": len(findings),
        "unique_findings": len(unique_finding_keys),
        "auth_anomaly_count": sum(1 for f in findings if "AUTH" in f.get("finding_type", "")),
        "injection_signal_count": sum(1 for f in findings if "INJECTION" in f.get("finding_type", "")),
        "cost_anomaly_count": sum(1 for f in findings if "DOS" in f.get("finding_type", "") or "COST" in f.get("finding_type", "")),
        "error_leakage_count": sum(1 for f in findings if "ERROR" in f.get("finding_type", "")),
        "time_to_first_finding": None,
        "max_latency": max(latencies) if latencies else 0,
        "average_latency": mean(latencies) if latencies else 0,
        "max_response_size": max(sizes) if sizes else 0,
        "reproducible_finding_count": 0,
        "ground_truth_available": ground_truth.get("available", False),
        "ground_truth_tp": ground_truth.get("tp", 0),
        "ground_truth_fp": ground_truth.get("fp", 0),
        "ground_truth_fn": ground_truth.get("fn", 0),
        "ground_truth_precision": ground_truth.get("precision", 0),
        "ground_truth_recall": ground_truth.get("recall", 0),
        "ground_truth_f1": ground_truth.get("f1", 0),
    }
    return metrics
