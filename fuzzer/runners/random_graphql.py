from __future__ import annotations

from fuzzer.config import AppConfig
from fuzzer.ga.chromosome import Chromosome
from fuzzer.ga.population import random_gene
from fuzzer.runners.common import execute_isolated_chromosome, finalize_run, prepare_run


def run(config: AppConfig) -> dict:
    result_dir, _storage, _client, _schema, operations = prepare_run(config)
    chromosomes = []
    for idx in range(config.baselines.iterations):
        chrom = Chromosome([random_gene(operations)])
        chromosomes.append(execute_isolated_chromosome(chrom, operations, config, 0, f"random_graphql_{idx:04d}"))
    return finalize_run(result_dir, chromosomes)
