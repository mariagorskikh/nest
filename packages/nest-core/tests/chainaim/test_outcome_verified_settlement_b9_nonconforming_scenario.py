# SPDX-License-Identifier: Apache-2.0
"""Iteration-9 (outcome_verified_settlement_b9) end-to-end nonconforming scenario tests.

Run the two shipped L3 scenarios end-to-end through the real ``ScenarioRunner``
(real plugins, real discrete-event simulator, real outcome-verified-settlement
ledger -- no hand-built traces, no mocks) and assert on the JSONL each run
emits. Mirrors ``test_outcome_verified_settlement_b4_scenarios.py`` exactly:

* ``outcome_verified_settlement_nonconforming`` (positive control) -- an
  ``gate: evaluator`` 5x5 run where the seller substitutes a different real
  unit's honestly-checksummed content from ``nonconform_at_tick`` onward. At
  least one reachable stream produces a ``gate:<ref>:<seq>:fail`` verdict (the
  L3 conformance catch ``checksum`` alone cannot make), and all four validators
  PASS.
* ``outcome_verified_settlement_nonconforming_billbug`` (negative control) --
  the same scenario with ``bill_regardless: true``, which bills past the
  L3-verified prefix so *exactly*
  ``outcome_verified_settlement_no_overbill_on_failed_verification`` FAILS
  while the other three (including the honesty validator) still PASS.
* determinism -- the positive-control scenario, run twice at the **same**
  seed, emits a byte-identical trace.
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

_NONCONFORMING = "outcome_verified_settlement_nonconforming"
_BILLBUG = "outcome_verified_settlement_nonconforming_billbug"
_KEY = "outcome_verified_settlement"
_NOVELTY = "outcome_verified_settlement_no_overbill_on_failed_verification"
_HONESTY = "outcome_verified_settlement_verdicts_match_committed_criterion"


def _scenario_path(name: str) -> Path:
    """Locate ``scenarios/<n>.yaml`` by walking up from this test file.

    Example::

        path = _scenario_path("outcome_verified_settlement_nonconforming")
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

        trace = _run_scenario("outcome_verified_settlement_nonconforming", tmp_path / "t.jsonl")
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


def test_outcome_verified_settlement_b9_nonconforming_four_pass(tmp_path: Path) -> None:
    """Positive control: correct L3-gated nonconforming run passes all four validators."""
    events = _events(_run_scenario(_NONCONFORMING, tmp_path / "nonconforming.jsonl"))
    # the nonconform path actually ran: at least one failing L3 verdict
    assert any(m.startswith("gate:") and m.endswith(":fail") for m in _sends(events))
    results = validate_events(events, _KEY)
    assert len(results) == 4
    assert all(r.passed for r in results), [(r.name, r.detail) for r in results if not r.passed]


def test_outcome_verified_settlement_b9_billbug_trips_only_novelty_validator(
    tmp_path: Path,
) -> None:
    """Negative control: bill_regardless trips ONLY the novelty validator on an
    L3 over-bill -- the honesty validator still passes (billing-despite-fail is
    not a mislabeled verdict)."""
    events = _events(_run_scenario(_BILLBUG, tmp_path / "billbug.jsonl"))
    results = _by_name(validate_events(events, _KEY))
    assert len(results) == 4
    assert not results[_NOVELTY].passed, results[_NOVELTY].detail
    drain = "outcome_verified_settlement_no_drain_after_close"
    overbill = "outcome_verified_settlement_no_overbill"
    assert results[drain].passed, results[drain].detail
    assert results[overbill].passed, results[overbill].detail
    assert results[_HONESTY].passed, results[_HONESTY].detail


def test_outcome_verified_settlement_b9_nonconforming_deterministic(tmp_path: Path) -> None:
    """Same scenario + same seed twice -> byte-identical trace."""
    a = _run_scenario(_NONCONFORMING, tmp_path / "a.jsonl", seed=42)
    b = _run_scenario(_NONCONFORMING, tmp_path / "b.jsonl", seed=42)
    assert a.read_bytes() == b.read_bytes()
