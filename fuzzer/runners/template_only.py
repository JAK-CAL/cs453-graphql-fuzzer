from __future__ import annotations

from fuzzer.config import AppConfig
from fuzzer.runners.common import execute_isolated_chromosome, finalize_run, prepare_run
from fuzzer.security.skeletons import chromosome_for_target
from fuzzer.security.targets import build_security_targets
from fuzzer.storage.json_logger import write_json


def run(config: AppConfig) -> dict:
    result_dir, _storage, _client, _schema, operations, server_model = prepare_run(config)
    targets = build_security_targets(operations)
    write_json(result_dir / "security_targets.json", targets)
    chromosomes = []
    for idx, target in enumerate(targets[: config.baselines.iterations]):
        chrom = chromosome_for_target(target)
        chromosomes.append(execute_isolated_chromosome(chrom, operations, config, 0, f"template_only_{idx:04d}", server_model))
    return finalize_run(result_dir, chromosomes)
