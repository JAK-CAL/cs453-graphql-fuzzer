from __future__ import annotations

from fuzzer.config import AppConfig
from fuzzer.fsm.transitions import TransitionName
from fuzzer.ga.budget import RequestBudget
from fuzzer.ga.chromosome import Chromosome, Gene
from fuzzer.ga.population import AUTH_MODES
from fuzzer.runners.common import can_start_chromosome, execute_isolated_chromosome, finalize_run, prepare_run


def run(config: AppConfig) -> dict:
    result_dir, _storage, _client, _schema, operations, _server_model = prepare_run(config)
    budget = RequestBudget(config.ga.request_budget)
    chromosomes = []
    for idx, op in enumerate(operations[: config.baselines.iterations]):
        if budget.exhausted:
            break
        genes = [Gene(TransitionName.PUBLIC_QUERY.value, op.name, mode, expected_negative=mode != "valid_token") for mode in AUTH_MODES]
        chrom = Chromosome(genes)
        if not can_start_chromosome(chrom, budget):
            break
        chromosomes.append(execute_isolated_chromosome(chrom, operations, config, 0, f"auth_only_{idx:04d}", budget=budget))
    return finalize_run(result_dir, chromosomes)
