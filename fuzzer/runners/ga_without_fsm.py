from __future__ import annotations

import random

from fuzzer.config import AppConfig
from fuzzer.ga.crossover import crossover
from fuzzer.ga.fitness import get_fitness_function
from fuzzer.ga.mutation import mutate_chromosome
from fuzzer.ga.population import create_initial_population
from fuzzer.ga.repair import repair_chromosome
from fuzzer.ga.selection import select_parent
from fuzzer.runners.common import execute_isolated_chromosome, finalize_run, prepare_run
from fuzzer.storage.coverage import coverage_summary
from fuzzer.storage.json_logger import append_csv


SUMMARY_FIELDS = [
    "generation",
    "best_fitness",
    "avg_fitness",
    "total_findings",
    "state_coverage",
    "transition_coverage",
]


def run(config: AppConfig) -> dict:
    result_dir, _storage, _client, _schema, operations, server_model = prepare_run(config)
    population = create_initial_population(operations, config.ga.population_size, config.limits.max_sequence_length)
    fitness_fn = get_fitness_function("default")
    if not operations:
        return finalize_run(result_dir, population)
    executed_archive = []
    for generation in range(config.ga.generations):
        executed = []
        for idx, chrom in enumerate(population):
            repaired = repair_chromosome(chrom, operations, config.limits.max_sequence_length)
            executed.append(execute_isolated_chromosome(repaired, operations, config, generation, f"ga_no_fsm_{generation:03d}_{idx:04d}", server_model))
        executed_archive.extend(executed)
        population = sorted(executed, key=lambda c: c.fitness, reverse=True)
        findings = [finding for chrom in population for finding in chrom.findings]
        coverage = coverage_summary(population)
        append_csv(
            result_dir / "generation_summary.csv",
            {
                "generation": generation,
                "best_fitness": population[0].fitness,
                "avg_fitness": sum(chrom.fitness for chrom in population) / max(1, len(population)),
                "total_findings": len(findings),
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
            fitness_fn(child)
            next_population.append(child)
        population = next_population
    return finalize_run(result_dir, executed_archive or population)
