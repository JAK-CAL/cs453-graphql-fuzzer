from fuzzer.fsm.states import FSMState
from fuzzer.ga.chromosome import Chromosome, Gene
from fuzzer.ga.fitness import get_fitness_function, fitness_security_schedule, fitness_state_weight_average


def test_state_weight_average_counts_repeated_visits():
    chrom = Chromosome([])
    chrom.visit_state(FSMState.S0_START.value)
    chrom.visit_state(FSMState.S8_INTERESTING_BEHAVIOR_FOUND.value)
    chrom.visit_state(FSMState.S8_INTERESTING_BEHAVIOR_FOUND.value)

    assert fitness_state_weight_average(chrom) == 8.0


def test_state_weight_average_empty_chromosome_is_zero():
    chrom = Chromosome([])

    assert fitness_state_weight_average(chrom) == 0.0


def test_state_weight_average_is_registered():
    assert get_fitness_function("state-weight-average") is fitness_state_weight_average


def test_security_schedule_rewards_stateful_evidence():
    chrom = Chromosome([])
    chrom.target_id = "BOLA_READ:Post:createPost:post"
    chrom.target_category = "BOLA_READ"
    chrom.total_request_count = 1
    chrom.valid_request_count = 1
    chrom.execution_trace.append({"selected_resource": {"id": "1"}, "resolver_reached": True, "has_data_key": True})
    chrom.findings.append({"finding_type": "STATEFUL_BOLA_READ", "confidence": "confirmed"})

    assert fitness_security_schedule(chrom) > 30


def test_security_schedule_penalizes_repeated_identical_genes():
    compact = Chromosome([Gene("protected_query_without_token", "me", "no_token", expected_negative=True)])
    compact.total_request_count = 1
    compact.valid_request_count = 1
    compact.findings.append({"finding_type": "AUTH_BYPASS_CANDIDATE", "operation": "me"})

    repeated = Chromosome(
        [
            Gene("protected_query_without_token", "me", "no_token", expected_negative=True),
            Gene("protected_query_without_token", "me", "no_token", expected_negative=True),
        ]
    )
    repeated.total_request_count = 2
    repeated.valid_request_count = 2
    repeated.findings.extend(
        [
            {"finding_type": "AUTH_BYPASS_CANDIDATE", "operation": "me"},
            {"finding_type": "AUTH_BYPASS_CANDIDATE", "operation": "me"},
        ]
    )

    assert fitness_security_schedule(compact) > fitness_security_schedule(repeated)


def test_security_schedule_is_registered():
    assert get_fitness_function("security-schedule") is fitness_security_schedule
