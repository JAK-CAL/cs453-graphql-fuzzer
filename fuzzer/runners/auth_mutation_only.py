from __future__ import annotations

from fuzzer.config import AppConfig
from fuzzer.fsm.transitions import TransitionName
from fuzzer.ga.chromosome import Chromosome, Gene
from fuzzer.ga.population import AUTH_MODES
from fuzzer.runners.common import execute_isolated_chromosome, finalize_run, prepare_run


def run(config: AppConfig) -> dict:
    result_dir, _storage, _client, _schema, operations, _server_model = prepare_run(config)
    chromosomes = []
    for idx, op in enumerate(operations[: config.baselines.iterations]):
        genes = [Gene(TransitionName.PUBLIC_QUERY.value, op.name, mode, expected_negative=mode != "valid_token") for mode in AUTH_MODES]
        chromosomes.append(execute_isolated_chromosome(Chromosome(genes), operations, config, 0, f"auth_only_{idx:04d}"))
    return finalize_run(result_dir, chromosomes)
