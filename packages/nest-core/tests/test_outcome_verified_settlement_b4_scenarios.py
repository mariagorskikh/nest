# SPDX-License-Identifier: Apache-2.0
"""Iteration-4 (outcome_verified_settlement_b4) gated-degrade scenario tests.

Run the two shipped degrade scenarios end-to-end through the real
``ScenarioRunner`` (real plugins, real discrete-event simulator, real
outcome-verified-settlement ledger -- no hand-built traces, no mocks) and assert
on the JSONL each run emits:

* ``outcome_verified_settlement_degrade`` (positive control) -- a content-gated
  5x5 run where the seller corrupts bytes from ``degrade_at_tick`` onward. Every
  reachable stream degrades correctly, all four validators PASS, and at
  least one ``gate:<ref>:<seq>:fail`` verdict is emitted (proof the degrade path
  actually ran rather than vacuously passing).
* ``outcome_verified_settlement_degrade_billbug`` (negative control) -- the same
  scenario with ``bill_regardless: true``, which bills past the verified prefix
  so *exactly* ``outcome_verified_settlement_no_overbill_on_failed_verification``
  FAILS while the other three validators still PASS.
* determinism -- the positive-control scenario, run twice at the **same** seed,
  emits a byte-identical trace. The 5% message drop is RNG-driven, so this is a
  same-seed-twice check (not a two-different-seeds one).
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_core.validators import validate_events

if TYPE_CHECKING:
    from nest_core.validators import ValidationResult

type Event = dict[str, Any]

_DEGRADE = "outcome_verified_settlement_degrade"
_BILLBUG = "outcome_verified_settlement_degrade_billbug"
_KEY = "outcome_verified_settlement"
_NOVELTY = "outcome_verified_settlement_no_overbill_on_failed_verification"
_HONESTY = "outcome_verified_settlement_verdicts_match_committed_criterion"


def _scenario_path(name: str) -> Path:
    """Locate ``scenarios/<name>.yaml`` by walking up from this test file.

    Example::

        path = _scenario_path("outcome_verified_settlement_degrade")
    """
    here = Path(__file__).resolve()
    for ancestor in here.parents:
        candidate = ancestor / "scenarios" / f"{name}.yaml"
        if candidate.exists():
            return candidate
    msg = f"scenarios/{name}.yaml not found above {here}"
    raise FileNotFoundError(msg)


def _run_scenario(name: str, out: Path, *, seed: int = 42) -> Path:
    """Run scenario *name* to trace path *out* at *seed*; return the trace path.

    Example::

        trace = _run_scenario("outcome_verified_settlement_degrade", tmp_path / "t.jsonl")
    """
    config = ScenarioConfig.from_yaml(_scenario_path(name))
    config.seed = seed
    config.output.trace = str(out)
    runner = ScenarioRunner(config)
    return asyncio.run(runner.run())


def _events(trace: Path) -> list[Event]:
    """Parse a JSONL trace file into a list of event dicts.

    Example::

        events = _events(trace_path)
    """
    lines = trace.read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line.strip()]


def _by_name(results: list[ValidationResult]) -> dict[str, ValidationResult]:
    """Index validator results by their ``name`` for direct assertion.

    Example::

        results = _by_name(validate_events(events, "outcome_verified_settlement"))
    """
    return {r.name: r for r in results}


def _sends(events: list[Event]) -> list[str]:
    """Return the message text of every send event, in order.

    Example::

        msgs = _sends(events)
    """
    return [str(e["msg"]) for e in events if e.get("kind") == "send" and "msg" in e]


def test_outcome_verified_settlement_b4_degrade_three_pass(tmp_path: Path) -> None:
    """Positive control: correct content-gated degrade passes all four validators."""
    events = _events(_run_scenario(_DEGRADE, tmp_path / "degrade.jsonl"))
    # the degrade path actually ran: at least one failing content-gate verdict
    assert any(m.startswith("gate:") and m.endswith(":fail") for m in _sends(events))
    results = validate_events(events, _KEY)
    assert len(results) == 4
    assert all(r.passed for r in results), [(r.name, r.detail) for r in results if not r.passed]


def test_outcome_verified_settlement_b4_billbug_trips_new_validator(tmp_path: Path) -> None:
    """Negative control: bill_regardless trips ONLY the novelty validator -- the
    honesty validator still passes, because the bug is billing-despite-a-correctly-
    labeled-fail, not a mislabeled verdict."""
    events = _events(_run_scenario(_BILLBUG, tmp_path / "billbug.jsonl"))
    results = _by_name(validate_events(events, _KEY))
    assert len(results) == 4
    assert not results[_NOVELTY].passed, results[_NOVELTY].detail
    drain = "outcome_verified_settlement_no_drain_after_close"
    overbill = "outcome_verified_settlement_no_overbill"
    assert results[drain].passed, results[drain].detail
    assert results[overbill].passed, results[overbill].detail
    assert results[_HONESTY].passed, results[_HONESTY].detail


def test_outcome_verified_settlement_b4_degrade_deterministic(tmp_path: Path) -> None:
    """Same scenario + same seed twice -> byte-identical trace (drops are RNG-driven)."""
    a = _run_scenario(_DEGRADE, tmp_path / "a.jsonl", seed=42)
    b = _run_scenario(_DEGRADE, tmp_path / "b.jsonl", seed=42)
    assert a.read_bytes() == b.read_bytes()
