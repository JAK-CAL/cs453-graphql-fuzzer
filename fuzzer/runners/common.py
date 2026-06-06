from __future__ import annotations

import copy
import json
import random
from pathlib import Path

from fuzzer.config import AppConfig
from fuzzer.fsm.dependency import build_dependency_edges
from fuzzer.fsm.executor import execute_chromosome
from fuzzer.fsm.server_model import ServerModel
from fuzzer.fsm.storage import FSMStorage
from fuzzer.ga.chromosome import Chromosome
from fuzzer.graphql.client import GraphQLClient
from fuzzer.graphql.introspection import introspect_schema, probe_schema_placeholder
from fuzzer.graphql.operation_pool import build_operation_pool
from fuzzer.graphql.schema_types import Operation
from fuzzer.storage.coverage import coverage_summary
from fuzzer.storage.findings import collect_findings
from fuzzer.storage.json_logger import ensure_result_dir, write_json, write_yaml


def prepare_run(config: AppConfig) -> tuple[Path, FSMStorage, GraphQLClient, dict, list[Operation], ServerModel]:
    if config.execution.random_seed is not None:
        random.seed(config.execution.random_seed)
    result_dir = ensure_result_dir(config.output.result_dir)
    for name in [
        "config.resolved.yaml",
        "schema.json",
        "operation_pool.json",
        "generation_summary.csv",
        "findings.json",
        "coverage.json",
        "latency_log.csv",
        "sequences.json",
        "metrics.json",
        "initial_population.json",
        "security_targets.json",
    ]:
        path = result_dir / name
        if path.exists():
            path.unlink()
    response_dir = result_dir / "responses"
    if response_dir.exists():
        for path in response_dir.glob("response_*.json"):
            path.unlink()
    write_yaml(result_dir / "config.resolved.yaml", config.to_dict())
    (result_dir / "latency_log.csv").write_text(
        "timestamp,sequence_id,generation,operation,transition,auth_mode,status_code,latency_ms,response_size,timeout\n",
        encoding="utf-8",
    )
    storage = FSMStorage()
    client = GraphQLClient(config.target.endpoint, config.execution.timeout_seconds, storage)
    if config.target.schema_path and Path(config.target.schema_path).exists():
        schema = json.loads(Path(config.target.schema_path).read_text(encoding="utf-8"))
    else:
        schema = introspect_schema(client) or probe_schema_placeholder(client)
    operations = [
        op
        for op in build_operation_pool(schema)
        if op.name not in {"resetServer"}
    ]
    storage.set_dependency_edges(build_dependency_edges(operations))
    write_json(result_dir / "schema.json", schema)
    write_json(result_dir / "operation_pool.json", operations)
    return result_dir, storage, client, schema, operations, ServerModel()


def make_isolated_client(config: AppConfig) -> tuple[FSMStorage, GraphQLClient]:
    storage = FSMStorage()
    return storage, GraphQLClient(config.target.endpoint, config.execution.timeout_seconds, storage)


def reset_target(client: GraphQLClient, config: AppConfig) -> None:
    if not config.execution.reset_between_chromosomes:
        return
    client.execute(config.execution.reset_query, {}, "no_token")


def execute_isolated_chromosome(chromosome, operation_pool, config: AppConfig, generation: int, sequence_id: str, server_model=None, budget=None):
    storage, client = make_isolated_client(config)
    fresh = Chromosome(genes=copy.deepcopy(chromosome.genes))
    fresh.target_id = chromosome.target_id
    fresh.target_category = chromosome.target_category
    fresh.schedule_path = chromosome.schedule_path
    reset_target(client, config)
    executed = execute_chromosome(
        fresh, client, operation_pool, storage, config, generation, sequence_id,
        server_model=server_model, budget=budget,
    )
    reset_target(client, config)
    return executed


def finalize_run(result_dir: Path, chromosomes) -> dict:
    findings = collect_findings(chromosomes)
    coverage = coverage_summary(chromosomes)
    sequences = [
        {
            "target_id": chrom.target_id,
            "target_category": chrom.target_category,
            "schedule_path": chrom.schedule_path,
            "fitness": chrom.fitness,
            "genes": chrom.genes,
            "valid_request_count": chrom.valid_request_count,
            "total_request_count": chrom.total_request_count,
            "unique_error_patterns": chrom.unique_error_patterns,
            "findings": chrom.findings,
            "execution_trace": [
                {
                    "actor": trace.get("actor"),
                    "operation": trace.get("operation"),
                    "transition": trace.get("transition"),
                    "auth_mode": trace.get("auth_mode"),
                    "status_code": trace.get("status_code"),
                    "has_data_key": trace.get("has_data_key"),
                    "resolver_reached": trace.get("resolver_reached"),
                    "selected_resource": trace.get("selected_resource"),
                }
                for trace in chrom.execution_trace
            ],
        }
        for chrom in chromosomes
    ]
    write_json(result_dir / "findings.json", findings)
    write_json(result_dir / "coverage.json", coverage)
    write_json(result_dir / "sequences.json", sequences)
    return {"findings": findings, "coverage": coverage, "sequences": sequences}
