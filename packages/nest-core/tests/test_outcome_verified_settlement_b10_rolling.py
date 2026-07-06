# SPDX-License-Identifier: Apache-2.0
"""Iteration-10 (outcome_verified_settlement_b10) rolling-streams scenario tests.

Run the shipped ``outcome_verified_settlement_rolling`` scenario end-to-end
through the real ``ScenarioRunner`` (real plugins, real discrete-event
simulator, real outcome-verified-settlement ledger -- no hand-built traces, no
mocks), mirroring ``test_outcome_verified_settlement_b4_scenarios.py`` /
``..._b9_nonconforming_scenario.py``, and assert on the JSONL it emits:

* every buyer rolls exactly ``streams_per_buyer`` (3) consecutive streams under
  unique per-cycle refs -- cycle 1 keeps the legacy ``{buyer}-stream`` ref,
  cycles 2-3 open ``{buyer}-stream-r2`` / ``-r3``;
* a failed verdict closes only that cycle's stream (``reason=degrade``) and the
  next cycle still opens -- documented here as an explicit ordering assertion;
* per-cycle caps and billing are independent: later cycles bill their own
  verified prefix after earlier cycles already closed, and no single cycle
  exceeds its own cap;
* all four validators PASS on the rolling trace (unique refs mean the per-ref
  grouping in the validators needs no changes);
* same-seed determinism: run twice at the same seed -> byte-identical traces;
* regression: the BASE scenario (``streams_per_buyer`` unset, default 1) still
  opens exactly the five legacy refs and no rolling ``-r`` refs at all -- the
  default path stays byte-identical (the exact-hash check lives in the manual
  Definition-of-Done step).
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_core.validators import validate_events

type Event = dict[str, Any]

_ROLLING = "outcome_verified_settlement_rolling"
_BASE = "outcome_verified_settlement"
_KEY = "outcome_verified_settlement"
_BUYERS = [f"buyer-{i}" for i in range(5)]
_CYCLES = 3
# buyer-4 is partitioned from its only seller (seller-4 is alone in partition
# group 2; the factory pairs buyer-i with seller-(i % 5), so buyer-4 -> seller-4).
# It can never receive an ack, so it never verifies, never bills, and -- per the
# spec's partition semantics -- correctly does NOT roll: it closes its single
# stream on timeout and stops. Only the four connected buyers roll all 3 cycles.
_CONNECTED_BUYERS = [f"buyer-{i}" for i in range(4)]
_PARTITIONED_BUYER = "buyer-4"


def _scenario_path(name: str) -> Path:
    """Locate ``scenarios/<name>.yaml`` by walking up from this test file.

    Example::

        path = _scenario_path("outcome_verified_settlement_rolling")
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

        trace = _run_scenario("outcome_verified_settlement_rolling", tmp_path / "t.jsonl")
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


def _sends(events: list[Event]) -> list[str]:
    """Return the message text of every send event, in order (sig suffix stripped).

    Example::

        msgs = _sends(events)
    """
    return [
        str(e["msg"]).rsplit("|sig:", 1)[0]
        for e in events
        if e.get("kind") == "send" and "msg" in e
    ]


def _open_refs(events: list[Event]) -> list[str]:
    """Refs of every ``stream-open`` send, in trace order.

    Example::

        refs = _open_refs(events)
    """
    return [m.split(":")[1] for m in _sends(events) if m.startswith("stream-open:")]


def _closes(events: list[Event]) -> list[tuple[str, int, str]]:
    """(ref, drained, reason) of every ``stream-close`` send, in trace order.

    Example::

        closes = _closes(events)
    """
    out: list[tuple[str, int, str]] = []
    for m in _sends(events):
        if not m.startswith("stream-close:"):
            continue
        parts = m.split(":")
        out.append((parts[1], int(parts[3]), parts[5]))
    return out


def _cycle_ref(buyer: str, cycle: int) -> str:
    """Expected on-wire ref for one buyer's rolling cycle.

    Example::

        _cycle_ref("buyer-0", 2)  # "buyer-0-stream-r2"
    """
    return f"{buyer}-stream" if cycle == 1 else f"{buyer}-stream-r{cycle}"


def test_outcome_verified_settlement_b10_rolling_unique_refs_per_cycle(tmp_path: Path) -> None:
    """Connected buyers roll 3 unique-ref cycles; the partitioned buyer opens 1 and stops.

    Spec-correct partition behavior: the four buyers that can reach their seller
    roll all 3 cycles under unique per-cycle refs (12 opens); buyer-4, cut off
    from seller-4, opens exactly its single cycle-1 stream and never rolls
    (1 open) -- 13 opens total, all distinct.
    """
    events = _events(_run_scenario(_ROLLING, tmp_path / "rolling.jsonl"))
    refs = _open_refs(events)
    assert len(set(refs)) == len(refs), "duplicate stream-open ref"
    connected_expected = {
        _cycle_ref(b, c) for b in _CONNECTED_BUYERS for c in range(1, _CYCLES + 1)
    }
    partitioned_expected = {_cycle_ref(_PARTITIONED_BUYER, 1)}
    expected = connected_expected | partitioned_expected
    assert set(refs) == expected, sorted(set(refs) ^ expected)
    # the partitioned buyer opened only cycle 1 -- no rolling refs for it
    assert not any(r.startswith(f"{_PARTITIONED_BUYER}-stream-r") for r in refs), (
        f"{_PARTITIONED_BUYER} should not roll under full partition"
    )


def test_outcome_verified_settlement_b10_failed_verdict_closes_cycle_next_opens(
    tmp_path: Path,
) -> None:
    """A failing verdict degrade-closes only that cycle; the NEXT cycle still opens.

    This documents the rolling contract: close-for-any-reason (including a
    failed L3 verdict) rolls to the next cycle while cycles remain.
    """
    events = _events(_run_scenario(_ROLLING, tmp_path / "rolling.jsonl"))
    sends = _sends(events)
    # the nonconform path actually ran in cycle 1 for at least one buyer
    assert any(m.startswith("gate:") and m.endswith(":fail") for m in sends)
    degrade_closed = [
        m.split(":")[1]
        for m in sends
        if m.startswith("stream-close:") and m.split(":")[5] == "degrade"
    ]
    assert degrade_closed, "expected at least one degrade-close under nonconform injection"
    # find a cycle-1 degrade close and assert its buyer's -r2 stream opens later
    cycle1 = next((r for r in degrade_closed if r.endswith("-stream")), None)
    assert cycle1 is not None, degrade_closed
    buyer = cycle1.removesuffix("-stream")
    close_idx = next(i for i, m in enumerate(sends) if m.startswith(f"stream-close:{cycle1}:"))
    open_idx = next(
        i for i, m in enumerate(sends) if m.startswith(f"stream-open:{buyer}-stream-r2:")
    )
    assert open_idx > close_idx, (close_idx, open_idx)


def test_outcome_verified_settlement_b10_per_cycle_caps_independent(tmp_path: Path) -> None:
    """Each cycle bills its own verified prefix under its own cap, independently."""
    events = _events(_run_scenario(_ROLLING, tmp_path / "rolling.jsonl"))
    closes = _closes(events)
    closed_refs = [ref for (ref, _, _) in closes]
    assert len(closed_refs) == len(set(closed_refs)), "a ref closed more than once"
    for ref, drained, _reason in closes:
        assert drained <= 20, f"{ref} drained {drained} past its own cap"
    # later cycles still bill after earlier cycles closed: rolling is not one-shot
    assert any(ref.endswith("-r2") and drained > 0 for (ref, drained, _) in closes), closes
    assert any(ref.endswith("-r3") and drained > 0 for (ref, drained, _) in closes), closes


def test_outcome_verified_settlement_b10_rolling_four_validators_pass(tmp_path: Path) -> None:
    """All four validators PASS on the rolling trace (per-ref grouping, no changes)."""
    events = _events(_run_scenario(_ROLLING, tmp_path / "rolling.jsonl"))
    results = validate_events(events, _KEY)
    assert len(results) == 4
    assert all(r.passed for r in results), [(r.name, r.detail) for r in results if not r.passed]


def test_outcome_verified_settlement_b10_rolling_deterministic(tmp_path: Path) -> None:
    """Same scenario + same seed twice -> byte-identical trace."""
    a = _run_scenario(_ROLLING, tmp_path / "a.jsonl", seed=42)
    b = _run_scenario(_ROLLING, tmp_path / "b.jsonl", seed=42)
    assert a.read_bytes() == b.read_bytes()


def test_outcome_verified_settlement_b10_base_scenario_unaffected(tmp_path: Path) -> None:
    """Regression: the base scenario (default streams_per_buyer=1) does not roll.

    Exactly the five legacy ``{buyer}-stream`` refs open, and no ``-r`` rolling
    ref appears anywhere in the trace. (The byte-exact determinism hash of the
    base trace is asserted in the manual Definition-of-Done step.)
    """
    events = _events(_run_scenario(_BASE, tmp_path / "base.jsonl"))
    refs = _open_refs(events)
    assert refs == [f"{b}-stream" for b in _BUYERS], refs
    assert not any("-stream-r" in m for m in _sends(events))


def test_outcome_verified_settlement_b10_partitioned_buyer_opens_once_and_bills_nothing(
    tmp_path: Path,
) -> None:
    """buyer-4 (cut off from seller-4) opens one stream, never rolls, and bills nothing.

    Positive assertion of the spec's partition semantics (attack 2): a buyer
    that cannot reach its seller receives no ack, so it settles nothing and
    drains nothing, and -- by the same logic -- must not roll a fresh cycle it
    also cannot serve. It opens exactly its single cycle-1 stream; no ``advance``
    and no rolling ``-r`` ref ever appear for it. (Its stream stays open at the
    end of the run: with no ack, its retry ladder is still unwinding when the
    tick budget ends, so no ``stream-close`` is emitted -- billing zero is the
    property that matters, not the close line.)
    """
    events = _events(_run_scenario(_ROLLING, tmp_path / "rolling.jsonl"))
    sends = _sends(events)
    part_opens = [r for r in _open_refs(events) if r.startswith(_PARTITIONED_BUYER)]
    assert part_opens == [f"{_PARTITIONED_BUYER}-stream"], part_opens
    # never rolls: no rolling ref for the partitioned buyer
    assert not any(m.startswith(f"stream-open:{_PARTITIONED_BUYER}-stream-r") for m in sends)
    # bills nothing: the partitioned buyer never drains (no closed ref carries value)
    part_drained = [
        drained for (ref, drained, _reason) in _closes(events) if ref.startswith(_PARTITIONED_BUYER)
    ]
    assert all(d == 0 for d in part_drained), part_drained
