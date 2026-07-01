# SPDX-License-Identifier: Apache-2.0
"""Validator unit tests and the end-to-end discrimination gate for the market.

Two layers:

1. **Validator direct-call**, hand-built event lists drive each branch of
   ``validate_multi_attribute_pareto_optimal`` (dominated agreement fails, a
   clean frontier passes, a breakdown is not a dominance failure) and of
   ``validate_multi_attribute_individually_rational`` (a sub-reservation
   agreement fails).
2. **End-to-end discrimination** (the core deliverable), boot the real
   ``multi_attribute_market`` scenario through ``ScenarioRunner`` under seeds
   42, 7, 1337. With ``negotiation: pareto`` every validator PASSES; with
   ``negotiation: alternating_offers`` (a deadline-blind, timeout-driven plugin)
   ``validate_multi_attribute_pareto_optimal`` FAILS on at least one agreement
   dominated by an exchanged bundle. The layer is overridden in-test; the shipped
   YAML is untouched.
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path
from typing import Any

import pytest
from nest_core.plugins import PluginRegistry
from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_core.validators import (
    ValidationResult,
    validate_multi_attribute_individually_rational,
    validate_multi_attribute_pareto_optimal,
    validate_trace,
)

SCENARIO_PATH = Path(__file__).resolve().parents[3] / "scenarios" / "multi_attribute_market.yaml"


def _send(msg: str) -> dict[str, Any]:
    """A minimal send event carrying a colon-delimited market frame."""
    return {"kind": "send", "msg": msg, "agent": "driver", "to": "peer"}


# Validator direct-call tests


def test_pareto_validator_flags_dominated_agreement() -> None:
    """An agreement dominated by another exchanged bundle is caught and named."""
    events = [
        _send("mautil:buyer-0:buyer:1.000000:0.000000:50:150:1:30:0.000000"),
        _send("mautil:seller-0:seller:0.100000:0.900000:50:150:1:30:0.000000"),
        _send("offer:pair-0:buyer-0:buyer:2:60:30"),  # the logroll: cheap + long deadline
        _send("offer:pair-0:seller-0:seller:2:150:30"),  # resolves the seller side of the pair
        _send("offer:pair-0:buyer-0:buyer:9:95:3"),  # late, deadline-suboptimal
        _send("agree:pair-0:95:3:seller-0"),  # ... and it is what gets agreed
    ]
    result = validate_multi_attribute_pareto_optimal(events)[0]
    assert not result.passed
    assert "dominated by" in result.detail
    assert "(60,30)" in result.detail


def test_pareto_validator_passes_clean_frontier() -> None:
    """A session whose agreement is the frontier bundle passes."""
    events = [
        _send("mautil:buyer-1:buyer:1.000000:0.000000:50:150:1:30:0.000000"),
        _send("mautil:seller-1:seller:0.100000:0.900000:50:150:1:30:0.000000"),
        _send("offer:pair-1:buyer-1:buyer:2:60:30"),
        _send("offer:pair-1:seller-1:seller:2:150:30"),
        _send("agree:pair-1:60:30:seller-1"),
    ]
    result = validate_multi_attribute_pareto_optimal(events)[0]
    assert result.passed, result.detail


def test_pareto_validator_ignores_breakdown_sessions() -> None:
    """A breakdown is a legitimate no-deal, not a dominance failure."""
    events = [
        # A clean agreement so the guard ("no negotiation") does not trip.
        _send("mautil:buyer-1:buyer:1.000000:0.000000:50:150:1:30:0.000000"),
        _send("mautil:seller-1:seller:0.100000:0.900000:50:150:1:30:0.000000"),
        _send("offer:pair-1:buyer-1:buyer:2:60:30"),
        _send("offer:pair-1:seller-1:seller:2:150:30"),
        _send("agree:pair-1:60:30:seller-1"),
        # A second session that simply broke down.
        _send("mautil:buyer-2:buyer:1.000000:0.000000:50:150:1:30:0.000000"),
        _send("mautil:seller-2:seller:0.100000:0.900000:50:150:1:30:0.000000"),
        _send("offer:pair-2:buyer-2:buyer:1:55:5"),
        _send("offer:pair-2:seller-2:seller:1:150:30"),
        _send("breakdown:pair-2:10"),
    ]
    result = validate_multi_attribute_pareto_optimal(events)[0]
    assert result.passed, result.detail
    assert "pair-2" not in result.detail


def test_individual_rationality_flags_below_reservation() -> None:
    """An agreement below a party's reservation utility is flagged."""
    events = [
        # Buyer reservation 0.95, but the agreed bundle (150,30) gives it utility 0.
        _send("mautil:buyer-3:buyer:1.000000:0.000000:50:150:1:30:0.950000"),
        _send("mautil:seller-3:seller:0.100000:0.900000:50:150:1:30:0.000000"),
        _send("offer:pair-3:buyer-3:buyer:1:150:30"),
        _send("offer:pair-3:seller-3:seller:1:150:30"),
        _send("agree:pair-3:150:30:seller-3"),
    ]
    result = validate_multi_attribute_individually_rational(events)[0]
    assert not result.passed
    assert "buyer" in result.detail


# End-to-end discrimination gate


def _run_scenario(seed: int, negotiation: str) -> list[ValidationResult]:
    """Run the market scenario with a chosen negotiation layer; validate its trace."""
    config = ScenarioConfig.from_yaml(str(SCENARIO_PATH))
    config.seed = seed
    config.layers.negotiation = negotiation
    with tempfile.TemporaryDirectory() as tmp:
        trace_path = Path(tmp) / f"mam_{negotiation}_{seed}.jsonl"
        config.output.trace = str(trace_path)
        runner = ScenarioRunner(config, registry=PluginRegistry())
        asyncio.run(runner.run())
        return validate_trace(trace_path, "multi_attribute_market")


@pytest.mark.parametrize("seed", [42, 7, 1337])
def test_pareto_passes_all_validators(seed: int) -> None:
    """The plugin under test (pareto) reaches only non-dominated, rational deals."""
    if not SCENARIO_PATH.exists():
        pytest.skip(f"scenario not found at {SCENARIO_PATH}")
    results = _run_scenario(seed, "pareto")
    assert results, "expected validators to run"
    assert all(r.passed for r in results), [(r.name, r.detail) for r in results]


@pytest.mark.parametrize("seed", [42, 7, 1337])
def test_alternating_offers_fails_pareto_validator(seed: int) -> None:
    """The deadline-blind reference plugin is caught: at least one dominated deal."""
    if not SCENARIO_PATH.exists():
        pytest.skip(f"scenario not found at {SCENARIO_PATH}")
    results = _run_scenario(seed, "alternating_offers")
    pareto = next(r for r in results if r.name == "multi_attribute_pareto_optimal")
    assert not pareto.passed, f"seed={seed}: alternating_offers should be caught"
    assert "dominated by" in pareto.detail
