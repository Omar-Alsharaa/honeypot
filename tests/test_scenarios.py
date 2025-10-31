from honeypot.scenarios import get_scenario, list_scenarios


def test_scenarios_registered():
    names = {s.name for s in list_scenarios()}
    expected = {"baseline", "web-basic", "hybrid-lfi", "gauntlet"}
    assert expected.issubset(names)


def test_get_scenario_case_insensitive():
    assert get_scenario("BASELINE").name == "baseline"


def test_scenario_metadata_shape():
    scenario = get_scenario("web-basic")
    assert scenario.objectives, "objectives should not be empty"
    assert scenario.hints, "hints should not be empty"
    assert all(isinstance(obj, str) for obj in scenario.objectives)
