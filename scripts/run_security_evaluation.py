from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover - dependency-free local runs
    yaml = None

from fuzzer.config import _simple_yaml_load
from fuzzer.storage.json_logger import _simple_yaml_dump


DEFAULT_METHODS = [
    "fsm-ga",
    "template-only",
    "dependency-only",
    "ga-without-fsm",
    "random-graphql",
    "random-sequence",
    "auth-only",
    "query-shape-only",
]


def main() -> int:
    parser = argparse.ArgumentParser(description="Run budget/seed GraphQL security evaluation.")
    parser.add_argument("--base-config", default="configs/current_security_base.yaml")
    parser.add_argument("--methods", default=",".join(DEFAULT_METHODS))
    parser.add_argument("--budgets", default="20,40,80")
    parser.add_argument("--seeds", default="1,2,3")
    parser.add_argument("--out", default="results/security_evaluation")
    args = parser.parse_args()

    base_text = Path(args.base_config).read_text(encoding="utf-8")
    base = yaml.safe_load(base_text) if yaml else _simple_yaml_load(base_text)
    methods = _split(args.methods)
    budgets = [int(value) for value in _split(args.budgets)]
    seeds = [int(value) for value in _split(args.seeds)]
    out_root = Path(args.out)
    config_root = out_root / "_configs"
    config_root.mkdir(parents=True, exist_ok=True)

    rows: list[dict[str, Any]] = []
    for budget in budgets:
        for seed in seeds:
            for method in methods:
                result_dir = out_root / f"{method}_budget{budget}_seed{seed}"
                config = _config_for(base, method, budget, seed, str(result_dir).replace("\\", "/"))
                config_path = config_root / f"{method}_budget{budget}_seed{seed}.yaml"
                config_text = yaml.safe_dump(config, sort_keys=False, allow_unicode=True) if yaml else _simple_yaml_dump(config)
                config_path.write_text(config_text, encoding="utf-8")
                _run([sys.executable, "-m", "fuzzer.cli", "fuzz", "--config", str(config_path), "--mode", method])
                _run([sys.executable, "-m", "fuzzer.cli", "evaluate", "--result-dir", str(result_dir)])
                metrics = json.loads((result_dir / "metrics.json").read_text(encoding="utf-8"))
                rows.append(
                    {
                        "method": method,
                        "budget": budget,
                        "seed": seed,
                        "tp": metrics.get("ground_truth_tp", 0),
                        "fp": metrics.get("ground_truth_fp", 0),
                        "fn": metrics.get("ground_truth_fn", 0),
                        "precision": metrics.get("ground_truth_precision", 0),
                        "recall": metrics.get("ground_truth_recall", 0),
                        "f1": metrics.get("ground_truth_f1", 0),
                        "candidate_findings": metrics.get("unique_findings", 0),
                    }
                )
    summary = {"rows": rows, "aggregate": _aggregate(rows)}
    (out_root / "budget_curve.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    _write_markdown(out_root / "budget_curve.md", summary)
    return 0


def _split(value: str) -> list[str]:
    return [part.strip() for part in value.split(",") if part.strip()]


def _config_for(base: dict[str, Any], method: str, budget: int, seed: int, result_dir: str) -> dict[str, Any]:
    config = json.loads(json.dumps(base))
    config.setdefault("execution", {})["random_seed"] = seed
    config.setdefault("output", {})["result_dir"] = result_dir
    config.setdefault("baselines", {})["iterations"] = budget
    ga = config.setdefault("ga", {})
    ga["request_budget"] = budget if method == "fsm-ga" else None
    ga["fitness_function"] = "security-schedule" if method in {"fsm-ga", "template-only"} else "default"
    ga["population_size"] = max(4, min(12, budget // 4 or 4))
    ga["generations"] = max(1, min(6, budget // max(1, ga["population_size"])))
    return config


def _run(command: list[str]) -> None:
    print("+", " ".join(command), flush=True)
    subprocess.run(command, check=True)


def _aggregate(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, int], list[dict[str, Any]]] = {}
    for row in rows:
        groups.setdefault((row["method"], row["budget"]), []).append(row)
    result = []
    for (method, budget), values in sorted(groups.items()):
        result.append(
            {
                "method": method,
                "budget": budget,
                "runs": len(values),
                "mean_tp": _mean(values, "tp"),
                "mean_fp": _mean(values, "fp"),
                "mean_fn": _mean(values, "fn"),
                "mean_precision": _mean(values, "precision"),
                "mean_recall": _mean(values, "recall"),
                "mean_f1": _mean(values, "f1"),
                "mean_candidate_findings": _mean(values, "candidate_findings"),
            }
        )
    return result


def _mean(rows: list[dict[str, Any]], key: str) -> float:
    return sum(float(row.get(key, 0)) for row in rows) / max(1, len(rows))


def _write_markdown(path: Path, summary: dict[str, Any]) -> None:
    lines = [
        "# Budget Curve",
        "",
        "| Method | Budget | Runs | Mean TP | Mean FP | Mean FN | Mean Precision | Mean Recall | Mean F1 |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in summary["aggregate"]:
        lines.append(
            f"| {row['method']} | {row['budget']} | {row['runs']} | {row['mean_tp']:.2f} | "
            f"{row['mean_fp']:.2f} | {row['mean_fn']:.2f} | {row['mean_precision']:.3f} | "
            f"{row['mean_recall']:.3f} | {row['mean_f1']:.3f} |"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
