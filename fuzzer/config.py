from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover - used only before dependencies are installed
    yaml = None


@dataclass
class TargetConfig:
    name: str = "graphql-target"
    endpoint: str = "http://localhost:3000/graphql"
    schema_path: str | None = None
    ground_truth_path: str | None = None


@dataclass
class ExecutionConfig:
    timeout_seconds: float = 5
    request_delay_ms: int = 50
    max_response_archive_bytes: int = 4096
    reset_between_chromosomes: bool = False
    reset_query: str = "mutation { resetServer(confirm: true, clearSessions: true) }"
    random_seed: int | None = None


@dataclass
class LimitsConfig:
    max_sequence_length: int = 8
    max_query_depth: int = 4
    max_alias_count: int = 10
    max_duplicate_fields: int = 5
    max_batch_size: int = 3


@dataclass
class GAConfig:
    population_size: int = 30
    generations: int = 20
    mutation_rate: float = 0.35
    crossover_rate: float = 0.50
    elitism_count: int = 2
    tournament_size: int = 3
    fitness_function: str = "default"
    request_budget: int | None = None
    surface_probe_enabled: bool = True
    surface_probe_max_requests: int = 12
    finding_archive_elitism_count: int = 2
    objective_seed_count: int = 2


@dataclass
class MutationConfig:
    sequence: bool = True
    auth: bool = True
    payload: bool = True
    query_shape: bool = True


@dataclass
class OracleConfig:
    auth_bypass: bool = True
    error_leakage: bool = True
    injection: bool = True
    dos: bool = True


@dataclass
class BaselineConfig:
    iterations: int = 200


@dataclass
class OutputConfig:
    result_dir: str = "results/run_001"


@dataclass
class AppConfig:
    target: TargetConfig
    execution: ExecutionConfig
    limits: LimitsConfig
    ga: GAConfig
    mutations: MutationConfig
    oracles: OracleConfig
    baselines: BaselineConfig
    output: OutputConfig

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _section(cls: type, data: dict[str, Any], key: str):
    return cls(**(data.get(key) or {}))


def load_config(path: str | Path) -> AppConfig:
    config_path = Path(path)
    text = config_path.read_text(encoding="utf-8")
    raw = yaml.safe_load(text) if yaml else _simple_yaml_load(text)
    raw = raw or {}
    return AppConfig(
        target=_section(TargetConfig, raw, "target"),
        execution=_section(ExecutionConfig, raw, "execution"),
        limits=_section(LimitsConfig, raw, "limits"),
        ga=_section(GAConfig, raw, "ga"),
        mutations=_section(MutationConfig, raw, "mutations"),
        oracles=_section(OracleConfig, raw, "oracles"),
        baselines=_section(BaselineConfig, raw, "baselines"),
        output=_section(OutputConfig, raw, "output"),
    )


def _coerce_scalar(value: str) -> Any:
    value = value.strip()
    if value.startswith('"') and value.endswith('"'):
        return value[1:-1]
    if value.startswith("'") and value.endswith("'"):
        return value[1:-1]
    if value.lower() == "true":
        return True
    if value.lower() == "false":
        return False
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        return value


def _simple_yaml_load(text: str) -> dict[str, Any]:
    data: dict[str, Any] = {}
    current: dict[str, Any] | None = None
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        if not raw_line.startswith(" ") and line.endswith(":"):
            key = line[:-1].strip()
            data[key] = {}
            current = data[key]
        elif raw_line.startswith("  ") and current is not None and ":" in line:
            key, value = line.strip().split(":", 1)
            current[key.strip()] = _coerce_scalar(value)
    return data
