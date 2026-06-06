from fuzzer.ga.chromosome import Chromosome, Gene
from fuzzer.config import AppConfig, BaselineConfig, ExecutionConfig, GAConfig, LimitsConfig, MutationConfig, OracleConfig, OutputConfig, TargetConfig
from fuzzer.runners.common import execute_isolated_chromosome


def _config() -> AppConfig:
    return AppConfig(
        target=TargetConfig(endpoint="http://127.0.0.1:1/graphql"),
        execution=ExecutionConfig(timeout_seconds=1, request_delay_ms=0),
        limits=LimitsConfig(),
        ga=GAConfig(fitness_function="security-schedule"),
        mutations=MutationConfig(),
        oracles=OracleConfig(),
        baselines=BaselineConfig(),
        output=OutputConfig(),
    )


def test_execute_isolated_chromosome_preserves_target_metadata():
    chrom = Chromosome([Gene("public_query", None, "no_token")])
    chrom.target_id = "BOLA_READ:Post:createPost:post"
    chrom.target_category = "BOLA_READ"
    chrom.schedule_path = "valid_token.createPost > low_privilege.post"

    executed = execute_isolated_chromosome(chrom, [], _config(), 0, "seq")

    assert executed.target_id == chrom.target_id
    assert executed.target_category == chrom.target_category
    assert executed.schedule_path == chrom.schedule_path
