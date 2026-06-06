from __future__ import annotations

import random

from fuzzer.config import AppConfig
from fuzzer.fsm.surface_probe import bootstrap_surface
from fuzzer.ga.budget import RequestBudget
from fuzzer.ga.crossover import crossover
from fuzzer.ga.fitness import get_fitness_function
from fuzzer.ga.mutation import mutate_chromosome
from fuzzer.ga.repair import repair_chromosome
from fuzzer.ga.selection import select_parent
from fuzzer.runners.common import execute_isolated_chromosome, finalize_run, prepare_run
from fuzzer.security.skeletons import create_security_guided_population
from fuzzer.security.targets import BFLA_ADMIN_LIKE_OP, BOLA_READ, BOLA_UPDATE_DELETE, BOPLA_SENSITIVE_FIELD_READ, INJECTION, STALE_OBJECT_ACCESS, build_security_targets
from fuzzer.storage.coverage import coverage_summary
from fuzzer.storage.json_logger import append_csv, write_json

SUMMARY_FIELDS = [
    "generation",
    "best_fitness",
    "avg_fitness",
    "total_findings",
    "auth_findings",
    "injection_findings",
    "dos_findings",
    "error_leakage_findings",
    "stateful_findings",
    "state_coverage",
    "transition_coverage",
]


def run(config: AppConfig) -> dict:
    result_dir, storage, client, _schema, operations, server_model = prepare_run(config)
    budget = RequestBudget(config.ga.request_budget)
    if operations:
        probe_budget = budget if config.ga.surface_probe_counts_toward_budget else None
        bootstrap_surface(client, operations, server_model, probe_budget, config, storage)
    targets = build_security_targets(operations)
    write_json(result_dir / "security_targets.json", targets)
    population = create_security_guided_population(
        operations,
        targets,
        config.ga.population_size,
        config.limits.max_sequence_length,
    )
    write_json(result_dir / "initial_population.json", population)
    if not operations:
        append_csv(result_dir / "generation_summary.csv", {"generation": 0, "best_fitness": 0, "avg_fitness": 0}, SUMMARY_FIELDS)
        write_json(result_dir / "server_model.json", server_model.to_dict())
        return finalize_run(result_dir, population)
    executed_archive = []
    found_target_ids: set[str] = set()
    for generation in range(config.ga.generations):
        if budget.exhausted:
            break
        executed = []
        for idx, chrom in enumerate(_execution_order(population, found_target_ids)):
            repaired = repair_chromosome(chrom, operations, config.limits.max_sequence_length)
            if not budget.can_spend(_estimated_request_cost(repaired)):
                continue
            executed.append(execute_isolated_chromosome(repaired, operations, config, generation, f"gen{generation:03d}_seq{idx:04d}", server_model, budget))
            if budget.exhausted:
                break
        if not executed:
            break
        executed_archive.extend(executed)
        found_target_ids.update(_found_target_ids(executed))
        population = sorted(executed, key=lambda c: c.fitness, reverse=True)
        findings = [f for chrom in population for f in chrom.findings]
        coverage = coverage_summary(population)
        append_csv(
            result_dir / "generation_summary.csv",
            {
                "generation": generation,
                "best_fitness": population[0].fitness,
                "avg_fitness": sum(c.fitness for c in population) / max(1, len(population)),
                "total_findings": len(findings),
                "auth_findings": sum(1 for f in findings if "AUTH" in f.get("finding_type", "")),
                "injection_findings": sum(1 for f in findings if "INJECTION" in f.get("finding_type", "")),
                "dos_findings": sum(1 for f in findings if "DOS" in f.get("finding_type", "")),
                "error_leakage_findings": sum(1 for f in findings if "ERROR" in f.get("finding_type", "")),
                "stateful_findings": sum(1 for f in findings if f.get("finding_type", "").startswith("STATEFUL_")),
                "state_coverage": coverage["state_coverage"],
                "transition_coverage": coverage["transition_coverage"],
            },
            SUMMARY_FIELDS,
        )
        survivor_count = max(config.ga.elitism_count, config.ga.population_size // 2)
        next_population = _diverse_survivors(population, survivor_count, found_target_ids)
        while len(next_population) < config.ga.population_size:
            a = select_parent(population, config.ga.tournament_size)
            b = select_parent(population, config.ga.tournament_size)
            child = crossover(a, b, config.limits.max_sequence_length) if random.random() < config.ga.crossover_rate else a
            if random.random() < config.ga.mutation_rate:
                child = mutate_chromosome(child, operations, config.limits.max_sequence_length, config.limits)
            child = repair_chromosome(child, operations, config.limits.max_sequence_length)
            fitness_fn = get_fitness_function(config.ga.fitness_function)
            fitness_fn(child)
            next_population.append(child)
        population = next_population
    write_json(result_dir / "server_model.json", server_model.to_dict())
    return finalize_run(result_dir, executed_archive or population)


def _diverse_survivors(population, limit: int, found_target_ids: set[str] | None = None):
    found_target_ids = found_target_ids or set()
    survivors = []
    seen = set()
    for chromosome in sorted(population, key=lambda chromosome: _archive_penalty(chromosome, found_target_ids)):
        key = _target_key(chromosome)
        if key in seen:
            continue
        survivors.append(chromosome)
        seen.add(key)
        if len(survivors) >= limit:
            return survivors
    for chromosome in population:
        if chromosome in survivors:
            continue
        survivors.append(chromosome)
        if len(survivors) >= limit:
            break
    return survivors


def _found_target_ids(population) -> set[str]:
    found: set[str] = set()
    for chromosome in population:
        if chromosome.findings and chromosome.target_id:
            found.add(chromosome.target_id)
        for finding in chromosome.findings:
            target_id = finding.get("target_id")
            if target_id:
                found.add(target_id)
    return found


def _target_key(chromosome) -> tuple:
    if chromosome.target_id:
        return ("target", chromosome.target_id)
    return ("schedule", tuple((gene.transition, gene.operation_name, gene.auth_mode) for gene in chromosome.genes))


def _estimated_request_cost(chromosome) -> int:
    # Login/resource-fill prerequisites can add requests for protected and
    # stateful schedules, so this is intentionally conservative.
    auth_setup = 1 if any(gene.auth_mode in {"valid_token", "low_privilege"} for gene in chromosome.genes) else 0
    stateful_setup = sum(1 for gene in chromosome.genes if gene.transition in {"setup_create_resource", "query_own_resource"})
    return max(1, len(chromosome.genes) + auth_setup + stateful_setup)


def _execution_order(population, found_target_ids: set[str] | None = None):
    found_target_ids = found_target_ids or set()
    return sorted(
        population,
        key=lambda chromosome: (
            _archive_penalty(chromosome, found_target_ids),
            _target_rank(chromosome),
            _estimated_request_cost(chromosome),
            -(chromosome.fitness or 0.0),
        ),
    )


def _archive_penalty(chromosome, found_target_ids: set[str]) -> int:
    return 1 if chromosome.target_id in found_target_ids else 0


def _target_rank(chromosome) -> int:
    category_rank = {
        BOLA_READ: 0,
        BOLA_UPDATE_DELETE: 1,
        STALE_OBJECT_ACCESS: 2,
        INJECTION: 3,
        BFLA_ADMIN_LIKE_OP: 4,
        BOPLA_SENSITIVE_FIELD_READ: 5,
    }.get(chromosome.target_category, 5)
    target_id = (chromosome.target_id or "").lower()
    object_rank = 0 if ":post:" in target_id else 1 if ":comment:" in target_id else 2 if ":user:" in target_id else 3
    secure_penalty = 1 if any(term in target_id for term in ("secure", "preview", "public", "history", "owner")) else 0
    return category_rank * 10 + object_rank + secure_penalty
