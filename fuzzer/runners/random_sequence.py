from __future__ import annotations

import random

from fuzzer.config import AppConfig
from fuzzer.ga.chromosome import Chromosome
from fuzzer.ga.population import random_gene
from fuzzer.runners.common import execute_isolated_chromosome, finalize_run, prepare_run


def run(config: AppConfig) -> dict:
    result_dir, _storage, _client, _schema, operations, _server_model = prepare_run(config)
    chromosomes = []
    for idx in range(config.baselines.iterations):
        length = random.randint(1, config.limits.max_sequence_length)
        chrom = Chromosome([random_gene(operations) for _ in range(length)])
        chromosomes.append(execute_isolated_chromosome(chrom, operations, config, 0, f"random_sequence_{idx:04d}"))
    return finalize_run(result_dir, chromosomes)
