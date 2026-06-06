from __future__ import annotations

from fuzzer.config import AppConfig
from fuzzer.fsm.transitions import TransitionName
from fuzzer.ga.chromosome import Chromosome, Gene, QueryShape
from fuzzer.runners.common import execute_isolated_chromosome, finalize_run, prepare_run


def run(config: AppConfig) -> dict:
    result_dir, _storage, _client, _schema, operations, _server_model = prepare_run(config)
    chromosomes = []
    shapes = [
        QueryShape(depth=config.limits.max_query_depth),
        QueryShape(alias_count=config.limits.max_alias_count),
        QueryShape(duplicate_fields=config.limits.max_duplicate_fields),
        QueryShape(batch=True, batch_size=config.limits.max_batch_size),
    ]
    for idx, op in enumerate(operations[: config.baselines.iterations]):
        genes = [Gene(TransitionName.DEEPLY_NESTED_QUERY.value, op.name, "no_token", query_shape=shape) for shape in shapes]
        chromosomes.append(execute_isolated_chromosome(Chromosome(genes), operations, config, 0, f"query_shape_{idx:04d}"))
    return finalize_run(result_dir, chromosomes)
