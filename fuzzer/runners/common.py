from __future__ import annotations

from pathlib import Path

from fuzzer.config import AppConfig
from fuzzer.fsm.storage import FSMStorage
from fuzzer.graphql.client import GraphQLClient
from fuzzer.graphql.introspection import introspect_schema, probe_schema_placeholder
from fuzzer.graphql.operation_pool import build_operation_pool
from fuzzer.graphql.schema_types import Operation
from fuzzer.storage.coverage import coverage_summary
from fuzzer.storage.findings import collect_findings
from fuzzer.storage.json_logger import ensure_result_dir, write_json, write_yaml


def prepare_run(config: AppConfig) -> tuple[Path, FSMStorage, GraphQLClient, dict, list[Operation]]:
    result_dir = ensure_result_dir(config.output.result_dir)
    write_yaml(result_dir / "config.resolved.yaml", config.to_dict())
    (result_dir / "latency_log.csv").write_text(
        "timestamp,sequence_id,generation,operation,transition,auth_mode,status_code,latency_ms,response_size,timeout\n",
        encoding="utf-8",
    )
    storage = FSMStorage()
    client = GraphQLClient(config.target.endpoint, config.execution.timeout_seconds, storage)
    schema = introspect_schema(client) or probe_schema_placeholder(client)
    operations = build_operation_pool(schema)
    write_json(result_dir / "schema.json", schema)
    write_json(result_dir / "operation_pool.json", operations)
    return result_dir, storage, client, schema, operations


def finalize_run(result_dir: Path, chromosomes) -> dict:
    findings = collect_findings(chromosomes)
    coverage = coverage_summary(chromosomes)
    sequences = [
        {
            "fitness": chrom.fitness,
            "genes": chrom.genes,
            "valid_request_count": chrom.valid_request_count,
            "total_request_count": chrom.total_request_count,
            "findings": chrom.findings,
        }
        for chrom in chromosomes
    ]
    write_json(result_dir / "findings.json", findings)
    write_json(result_dir / "coverage.json", coverage)
    write_json(result_dir / "sequences.json", sequences)
    return {"findings": findings, "coverage": coverage, "sequences": sequences}
