from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class QueryShape:
    depth: int = 1
    alias_count: int = 0
    batch: bool = False
    batch_size: int = 1
    duplicate_fields: int = 0


@dataclass
class Gene:
    transition: str
    operation_name: str | None
    auth_mode: str
    payload: dict[str, Any] = field(default_factory=dict)
    query_shape: QueryShape = field(default_factory=QueryShape)
    expected_negative: bool = False


@dataclass
class Chromosome:
    genes: list[Gene]
    fitness: float = 0.0
    findings: list[dict[str, Any]] = field(default_factory=list)
    state_visit_history: list[str] = field(default_factory=list)
    visited_states: set[str] = field(default_factory=set)
    visited_transitions: set[str] = field(default_factory=set)
    valid_request_count: int = 0
    total_request_count: int = 0
    unique_error_patterns: set[str] = field(default_factory=set)
    skipped_transition_count: int = 0
    unrepaired_invalid_sequence_count: int = 0
    positive_fill_count: int = 0

    def visit_state(self, state: str) -> None:
        self.state_visit_history.append(state)
        self.visited_states.add(state)
