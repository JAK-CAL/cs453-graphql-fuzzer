from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any

from fuzzer.ga.chromosome import Chromosome


DEEP_STATEFUL_CATEGORIES = {
    "BOLA_READ",
    "BOLA_UPDATE_DELETE",
    "STALE_OBJECT_ACCESS",
    "BFLA_ADMIN_LIKE_OP",
}


def finding_identity(finding: dict[str, Any]) -> tuple:
    """Identity for security/regression findings.

    Auth mode and transition are useful evidence, but they should not dominate
    vulnerability identity because auth-only baselines repeat the same surface
    under many auth variants.
    """
    return (
        finding.get("target_category") or _category_from_type(finding.get("finding_type")),
        finding.get("target_id"),
        finding.get("operation"),
        (finding.get("evidence") or {}).get("selected_resource", {}).get("resource_type")
        if isinstance((finding.get("evidence") or {}).get("selected_resource"), dict)
        else None,
        finding.get("confidence"),
    )


def _category_from_type(finding_type: str | None) -> str | None:
    value = str(finding_type or "")
    if value.startswith("STATEFUL_"):
        return value.removeprefix("STATEFUL_")
    if "AUTH" in value:
        return "BOPLA_SENSITIVE_FIELD_READ"
    if "INJECTION" in value:
        return "INJECTION"
    if "DOS" in value or "COST" in value:
        return "COST_ANOMALY"
    return None


def clone_for_evolution(chromosome: Chromosome) -> Chromosome:
    clone = Chromosome(copy.deepcopy(chromosome.genes))
    clone.target_id = chromosome.target_id
    clone.target_category = chromosome.target_category
    clone.schedule_path = chromosome.schedule_path
    return clone


@dataclass
class FindingArchive:
    best_by_identity: dict[tuple, Chromosome] = field(default_factory=dict)
    found_categories: set[str] = field(default_factory=set)
    seen_targets: set[str] = field(default_factory=set)

    def update(self, chromosomes: list[Chromosome]) -> None:
        for chromosome in chromosomes:
            if chromosome.target_category:
                self.seen_targets.add(chromosome.target_category)
            for finding in chromosome.findings:
                key = finding_identity(finding)
                category = key[0]
                if category:
                    self.found_categories.add(str(category))
                current = self.best_by_identity.get(key)
                if current is None or _archive_rank(chromosome) > _archive_rank(current):
                    self.best_by_identity[key] = clone_for_evolution(chromosome)

    def elites(self, count: int) -> list[Chromosome]:
        ranked = sorted(self.best_by_identity.values(), key=_archive_rank, reverse=True)
        return [clone_for_evolution(chromosome) for chromosome in ranked[: max(0, count)]]


def _archive_rank(chromosome: Chromosome) -> tuple:
    deep_bonus = 1 if chromosome.target_category in DEEP_STATEFUL_CATEGORIES else 0
    confirmed = sum(1 for finding in chromosome.findings if finding.get("confidence") == "confirmed")
    probable = sum(1 for finding in chromosome.findings if finding.get("confidence") == "probable")
    return (
        deep_bonus,
        confirmed,
        probable,
        len(chromosome.findings),
        chromosome.fitness,
    )
