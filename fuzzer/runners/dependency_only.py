from __future__ import annotations

from fuzzer.config import AppConfig
from fuzzer.fsm.dependency import build_dependency_edges
from fuzzer.fsm.transitions import TransitionName
from fuzzer.ga.chromosome import Chromosome, Gene
from fuzzer.runners.common import execute_isolated_chromosome, finalize_run, prepare_run
from fuzzer.storage.json_logger import write_json


def run(config: AppConfig) -> dict:
    result_dir, _storage, _client, _schema, operations, server_model = prepare_run(config)
    edges = build_dependency_edges(operations)
    write_json(result_dir / "dependency_edges.json", edges)
    op_map = {op.name: op for op in operations}
    chromosomes = []
    for idx, edge in enumerate(edges[: config.baselines.iterations]):
        producer = op_map.get(edge.producer)
        consumer = op_map.get(edge.consumer)
        if producer is None or consumer is None:
            continue
        producer_transition = TransitionName.SETUP_CREATE_RESOURCE.value if producer.operation_type == "mutation" else TransitionName.PUBLIC_QUERY.value
        if consumer.operation_type == "mutation":
            consumer_transition = TransitionName.UPDATE_OTHER_RESOURCE.value
        else:
            consumer_transition = TransitionName.QUERY_OTHER_RESOURCE.value
        chrom = Chromosome(
            [
                Gene(producer_transition, producer.name, "valid_token"),
                Gene(consumer_transition, consumer.name, "low_privilege", expected_negative=True),
            ]
        )
        chrom.schedule_path = f"{producer.name} -> {consumer.name}"
        chromosomes.append(execute_isolated_chromosome(chrom, operations, config, 0, f"dependency_only_{idx:04d}", server_model))
    return finalize_run(result_dir, chromosomes)
