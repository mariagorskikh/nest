"""Fault declaration contract from legacy PR #8 (@mariagorskikh).

Legacy PRs #10 and #11 remain future latency and topology profiles; these
tests only harden the numeric declarations the current transport consumes.
"""

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from nandatown.sim.scenario import FaultRule, ScenarioSpec, load_scenario_text


@pytest.mark.parametrize(("field", "action", "value"), [
    ("nth", "drop_rate", 0),
    ("nth", "drop_rate", -1),
    ("nth", "drop_rate", True),
    ("nth", "drop_rate", 1.0),
    ("nth", "drop_rate", 1.5),
    ("nth", "drop_rate", "1"),
    ("delay", "drop", -0.1),
    ("delay", "drop", True),
    ("delay", "drop", "0.5"),
    ("delay", "drop", float("nan")),
    ("delay", "drop", float("inf")),
    ("delay", "drop", float("-inf")),
    ("rate", "delay", -0.1),
    ("rate", "delay", 1.1),
    ("rate", "delay", True),
    ("rate", "delay", "0.5"),
    ("rate", "delay", float("nan")),
    ("rate", "delay", float("inf")),
    ("rate", "delay", float("-inf")),
])
def test_fault_numbers_reject_malformed_values_even_when_unused(
        field, action, value):
    with pytest.raises(ValidationError):
        FaultRule.model_validate({"action": action, field: value})


def test_integer_yaml_values_remain_valid_for_float_fault_fields():
    spec = load_scenario_text("""
name: integer-fault-values
agents: []
faults:
  - {action: delay, kind: ping, nth: 1, delay: 2, rate: 1}
""")

    rule = spec.faults[0]
    assert rule.nth == 1 and type(rule.nth) is int
    assert rule.delay == 2.0 and type(rule.delay) is float
    assert rule.rate == 1.0 and type(rule.rate) is float


def test_shipped_scenario_schema_matches_generated_numeric_contract():
    path = Path(__file__).parents[1] / "schemas" / "scenario.schema.json"
    shipped = json.loads(path.read_text())
    generated = ScenarioSpec.model_json_schema()
    generated["$id"] = "https://nandatown.local/schemas/scenario.schema.json"

    assert shipped == generated
    fault = shipped["$defs"]["FaultRule"]["properties"]
    assert fault["nth"]["minimum"] == 1
    assert fault["delay"]["minimum"] == 0
    assert fault["rate"]["minimum"] == 0
    assert fault["rate"]["maximum"] == 1
