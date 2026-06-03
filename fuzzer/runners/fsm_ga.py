from __future__ import annotations

import random

from fuzzer.config import AppConfig
from fuzzer.fsm.surface_probe import bootstrap_surface
from fuzzer.ga.budget import RequestBudget
from fuzzer.ga.crossover import crossover
from fuzzer.ga.fitness import get_fitness_function
from fuzzer.ga.mutation import mutate_chromosome
from fuzzer.ga.population import create_initial_population
from fuzzer.ga.repair import repair_chromosome
from fuzzer.ga.selection import select_parent
from fuzzer.runners.common import execute_isolated_chromosome, finalize_run, prepare_run
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
    "state_coverage",
    "transition_coverage",
]


def run(config: AppConfig) -> dict:
    result_dir, storage, client, _schema, operations, server_model = prepare_run(config)
    budget = RequestBudget(config.ga.request_budget)
    if operations:
        bootstrap_surface(client, operations, server_model, budget, config, storage)
    population = create_initial_population(operations, config.ga.population_size, config.limits.max_sequence_length)
    write_json(result_dir / "initial_population.json", population)
    if not operations:
        append_csv(result_dir / "generation_summary.csv", {"generation": 0, "best_fitness": 0, "avg_fitness": 0}, SUMMARY_FIELDS)
        write_json(result_dir / "server_model.json", server_model.to_dict())
        return finalize_run(result_dir, population)
    for generation in range(config.ga.generations):
        if budget.exhausted:
            break
        executed = []
        for idx, chrom in enumerate(population):
            repaired = repair_chromosome(chrom, operations, config.limits.max_sequence_length)
            executed.append(execute_isolated_chromosome(repaired, operations, config, generation, f"gen{generation:03d}_seq{idx:04d}", server_model, budget))
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
                "state_coverage": coverage["state_coverage"],
                "transition_coverage": coverage["transition_coverage"],
            },
            SUMMARY_FIELDS,
        )
        next_population = population[: config.ga.elitism_count]
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
    return finalize_run(result_dir, population)
