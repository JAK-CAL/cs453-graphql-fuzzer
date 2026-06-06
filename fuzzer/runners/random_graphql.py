from __future__ import annotations

from fuzzer.config import AppConfig
from fuzzer.ga.budget import RequestBudget
from fuzzer.ga.chromosome import Chromosome
from fuzzer.ga.population import random_gene
from fuzzer.runners.common import can_start_chromosome, execute_isolated_chromosome, finalize_run, prepare_run


def run(config: AppConfig) -> dict:
    result_dir, _storage, _client, _schema, operations, _server_model = prepare_run(config)
    budget = RequestBudget(config.ga.request_budget)
    chromosomes = []
    for idx in range(config.baselines.iterations):
        if budget.exhausted:
            break
        chrom = Chromosome([random_gene(operations)])
        if not can_start_chromosome(chrom, budget):
            break
        chromosomes.append(execute_isolated_chromosome(chrom, operations, config, 0, f"random_graphql_{idx:04d}", budget=budget))
    return finalize_run(result_dir, chromosomes)
