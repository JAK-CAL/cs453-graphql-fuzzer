from scripts.run_security_evaluation import DEFAULT_METHODS, _config_for


def test_security_evaluation_applies_request_budget_to_all_methods():
    base = {
        "execution": {},
        "output": {},
        "baselines": {},
        "ga": {},
    }

    for method in DEFAULT_METHODS:
        config = _config_for(base, method, 24, 7, "results/example")

        assert config["ga"]["request_budget"] == 24
        assert config["baselines"]["iterations"] == 24
        assert config["execution"]["random_seed"] == 7
