from __future__ import annotations

from pathlib import Path

from fuzzer.evaluation.metrics import compute_metrics
from fuzzer.storage.json_logger import write_json


def write_report(result_dir: str | Path) -> dict:
    metrics = compute_metrics(result_dir)
    write_json(Path(result_dir) / "metrics.json", metrics)
    return metrics
