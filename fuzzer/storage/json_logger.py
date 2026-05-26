from __future__ import annotations

import csv
import json
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any

try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover - used only before dependencies are installed
    yaml = None


def ensure_result_dir(result_dir: str | Path) -> Path:
    path = Path(result_dir)
    (path / "responses").mkdir(parents=True, exist_ok=True)
    return path


def to_jsonable(value: Any) -> Any:
    if is_dataclass(value):
        return to_jsonable(asdict(value))
    if isinstance(value, set):
        return sorted(value)
    if isinstance(value, list):
        return [to_jsonable(v) for v in value]
    if isinstance(value, dict):
        return {str(k): to_jsonable(v) for k, v in value.items()}
    return value


def write_json(path: str | Path, data: Any) -> None:
    Path(path).write_text(json.dumps(to_jsonable(data), ensure_ascii=False, indent=2), encoding="utf-8")


def write_yaml(path: str | Path, data: Any) -> None:
    payload = to_jsonable(data)
    if yaml:
        text = yaml.safe_dump(payload, sort_keys=False, allow_unicode=True)
    else:
        text = _simple_yaml_dump(payload)
    Path(path).write_text(text, encoding="utf-8")


def append_csv(path: str | Path, row: dict[str, Any], fieldnames: list[str]) -> None:
    path = Path(path)
    exists = path.exists()
    with path.open("a", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        if not exists:
            writer.writeheader()
        writer.writerow({key: row.get(key, "") for key in fieldnames})


def _simple_yaml_dump(data: Any, indent: int = 0) -> str:
    pad = " " * indent
    if isinstance(data, dict):
        lines = []
        for key, value in data.items():
            if isinstance(value, dict):
                lines.append(f"{pad}{key}:")
                lines.append(_simple_yaml_dump(value, indent + 2).rstrip())
            else:
                lines.append(f"{pad}{key}: {json.dumps(value, ensure_ascii=False) if isinstance(value, str) else value}")
        return "\n".join(lines) + "\n"
    return f"{pad}{data}\n"
