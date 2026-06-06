from __future__ import annotations

from fuzzer.config import AppConfig
from fuzzer.fsm.transitions import TransitionName
from fuzzer.ga.budget import RequestBudget
from fuzzer.ga.chromosome import Chromosome, Gene, QueryShape
from fuzzer.runners.common import can_start_chromosome, execute_isolated_chromosome, finalize_run, prepare_run


def run(config: AppConfig) -> dict:
    result_dir, _storage, _client, _schema, operations, _server_model = prepare_run(config)
    budget = RequestBudget(config.ga.request_budget)
    chromosomes = []
    shapes = [
        QueryShape(depth=config.limits.max_query_depth),
        QueryShape(alias_count=config.limits.max_alias_count),
        QueryShape(duplicate_fields=config.limits.max_duplicate_fields),
        QueryShape(batch=True, batch_size=config.limits.max_batch_size),
    ]
    for idx, op in enumerate(operations[: config.baselines.iterations]):
        if budget.exhausted:
            break
        genes = [Gene(TransitionName.DEEPLY_NESTED_QUERY.value, op.name, "no_token", query_shape=shape) for shape in shapes]
        chrom = Chromosome(genes)
        if not can_start_chromosome(chrom, budget):
            break
        chromosomes.append(execute_isolated_chromosome(chrom, operations, config, 0, f"query_shape_{idx:04d}", budget=budget))
    return finalize_run(result_dir, chromosomes)
