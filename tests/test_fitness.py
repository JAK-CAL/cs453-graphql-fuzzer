from fuzzer.fsm.states import FSMState
from fuzzer.ga.chromosome import Chromosome
from fuzzer.ga.fitness import get_fitness_function, fitness_state_weight_average


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
