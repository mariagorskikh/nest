# SPDX-License-Identifier: Apache-2.0
"""Iteration-6 (outcome_verified_settlement_b6) driver tests: L3 gate wiring + trace grammar.

Exercise the real buyer/seller agents through the real discrete-event simulator
and the real outcome-verified-settlement plugin (no hand-built traces, no mocks,
no YAML/ScenarioRunner yet -- that's b9), then assert on the JSONL each run
emits. Mirrors ``test_outcome_verified_settlement_b2_driver.py`` exactly, extended
for ``gate="evaluator"`` / ``criterion`` / ``nonconform_at_tick`` / ``nonconform_mode``.

The single most important test here is
``test_outcome_verified_settlement_b6_nonconform_checksum_is_honest_at_failing_seq``:
proof, at the driver/trace level (not just the pure-gate level b5 already proved),
that a nonconforming unit's declared checksum genuinely matches its delivered
bytes -- L2 would settle it -- and only L3's criterion rejects it.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
from typing import Any

from nest_core.scenarios_builtin.outcome_verified_settlement import (
    OutcomeVerifiedSettlementBuyerAgent,
    OutcomeVerifiedSettlementSellerAgent,
)
from nest_core.sim.simulator import Simulator
from nest_core.types import AgentId, PaymentRef
from nest_core.validators import validate_events
from nest_plugins_reference.payments.outcome_verified_settlement import (
    OutcomeVerifiedSettlement,
)

type Event = dict[str, Any]

_BUYER = AgentId("buyer-0")
_SELLER = AgentId("seller-0")
_REF = "buyer-0-stream"


def _run(
    tmp_path: Path,
    *,
    name: str = "trace.jsonl",
    gate: str = "ack_received",
    criterion: str = "reference_match",
    degrade_at_tick: int | None = None,
    nonconform_at_tick: int | None = None,
    nonconform_mode: str = "replay_previous",
    bill_regardless: bool = False,
    rate: int = 1,
    close_at_tick: int = 5,
    seed: int = 0,
) -> list[Event]:
    """Run a single buyer/seller stream through the real simulator; return its trace.

    Mirrors the factory's shared-ledger wiring (one balances/streams/payments map
    shared by per-agent plugin handles) so ``advance`` debits the buyer and credits
    the seller exactly as production does.
    """
    trace_path = tmp_path / name
    balances: dict[AgentId, int] = {_BUYER: 1000, _SELLER: 1000}
    streams: dict[PaymentRef, Any] = {}
    payments: dict[PaymentRef, Any] = {}

    def _handle(aid: AgentId) -> OutcomeVerifiedSettlement:
        return OutcomeVerifiedSettlement(
            aid, initial_balance=0, balances=balances, streams=streams, payments=payments
        )

    sim = Simulator(
        seed=seed,
        trace_path=str(trace_path),
        plugins={"payments": _handle(AgentId("system"))},
    )
    seller = OutcomeVerifiedSettlementSellerAgent(
        _SELLER,
        content_gated=(gate != "ack_received"),
        degrade_at_tick=degrade_at_tick,
        nonconform_at_tick=nonconform_at_tick,
        nonconform_mode=nonconform_mode,
    )
    buyer = OutcomeVerifiedSettlementBuyerAgent(
        _BUYER,
        _SELLER,
        rate_per_tick=rate,
        close_at_tick=close_at_tick,
        gate=gate,
        criterion=criterion,
        bill_regardless=bill_regardless,
    )
    sim.add_agent(_SELLER, seller)
    sim.add_agent(_BUYER, buyer)
    sim.set_agent_plugins(_SELLER, {"payments": _handle(_SELLER)})
    sim.set_agent_plugins(_BUYER, {"payments": _handle(_BUYER)})

    asyncio.run(sim.run())

    lines = trace_path.read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line.strip()]


def _sends(events: list[Event]) -> list[str]:
    """Return the message text of every send event, in order."""
    return [str(e["msg"]) for e in events if e.get("kind") == "send" and "msg" in e]


def _last(msgs: list[str], tag: str) -> str:
    """Return the last send line carrying *tag*."""
    return [m for m in msgs if m.startswith(f"{tag}:")][-1]


def _proj(events: list[Event]) -> list[tuple[Any, Any, Any]]:
    """Project events to (kind, agent, msg) for order-sensitive comparison."""
    return [(e.get("kind"), e.get("agent"), e.get("msg")) for e in events]


def test_outcome_verified_settlement_b6_evaluator_all_correct_full_drain(tmp_path: Path) -> None:
    """Positive control: no fault injected, evaluator gate passes every unit, full drain."""
    msgs = _sends(_run(tmp_path, gate="evaluator", close_at_tick=5))
    gate_lines = [m for m in msgs if m.startswith("gate:")]
    assert len(gate_lines) == 5
    assert all(m.endswith(":pass") for m in gate_lines)
    parts = _last(msgs, "stream-close").split(":")
    assert int(parts[3]) == 5
    assert parts[5] == "done"


def test_outcome_verified_settlement_b6_nonconform_replay_previous_fails_and_stops(
    tmp_path: Path,
) -> None:
    """Evaluator gate emits gate:<ref>:k:fail at the nonconforming unit and stops billing."""
    k = 3
    msgs = _sends(
        _run(tmp_path, gate="evaluator", nonconform_at_tick=k, nonconform_mode="replay_previous")
    )
    gate_lines = [m for m in msgs if m.startswith("gate:")]
    assert f"gate:{_REF}:{k}:fail" in gate_lines
    assert sum(1 for m in gate_lines if m.endswith(":fail")) == 1
    assert all(m.endswith(":pass") for m in gate_lines if not m.endswith(":fail"))
    parts = _last(msgs, "stream-close").split(":")
    assert int(parts[3]) == k  # drained == verified prefix (rate 1 * k)
    assert parts[5] == "degrade"


def test_outcome_verified_settlement_b6_nonconform_checksum_is_honest_at_failing_seq(
    tmp_path: Path,
) -> None:
    """THE key driver-level proof: at the failing seq, the declared checksum
    genuinely matches the delivered bytes -- L2 would pass; only L3 catches this.
    """
    k = 3
    msgs = _sends(
        _run(tmp_path, gate="evaluator", nonconform_at_tick=k, nonconform_mode="replay_previous")
    )
    ack_line = next(m for m in msgs if m.startswith(f"ack:{_REF}:{k}:"))
    parts = ack_line.split(":")
    chunk_hex, declared = parts[3], parts[4]
    recomputed = hashlib.sha256(bytes.fromhex(chunk_hex)).hexdigest()
    assert recomputed == declared  # honest: a bare ChecksumGate would settle this unit
    assert f"gate:{_REF}:{k}:fail" in msgs  # but reference_match (L3) still rejects it


def test_outcome_verified_settlement_b6_nonconform_stale_first_also_fails(tmp_path: Path) -> None:
    """stale_first mode (replay seq 0's content) also trips reference_match."""
    k = 3
    msgs = _sends(
        _run(tmp_path, gate="evaluator", nonconform_at_tick=k, nonconform_mode="stale_first")
    )
    assert f"gate:{_REF}:{k}:fail" in msgs
    parts = _last(msgs, "stream-close").split(":")
    assert int(parts[3]) == k


def test_outcome_verified_settlement_b6_nonconform_empty_also_fails(tmp_path: Path) -> None:
    """empty mode (deliver zero bytes) also trips reference_match."""
    k = 3
    msgs = _sends(_run(tmp_path, gate="evaluator", nonconform_at_tick=k, nonconform_mode="empty"))
    assert f"gate:{_REF}:{k}:fail" in msgs
    parts = _last(msgs, "stream-close").split(":")
    assert int(parts[3]) == k


def test_outcome_verified_settlement_b6_degrade_and_checksum_paths_unaffected(
    tmp_path: Path,
) -> None:
    """Regression: existing gate=checksum + degrade_at_tick behavior is unchanged
    by this iteration's refactor (canonical_chunk moved into gates.py, buyer/seller
    constructors gained new optional params)."""
    k = 2
    msgs = _sends(_run(tmp_path, gate="checksum", degrade_at_tick=k, close_at_tick=5))
    gate_lines = [m for m in msgs if m.startswith("gate:")]
    assert f"gate:{_REF}:{k}:fail" in gate_lines
    assert sum(1 for m in gate_lines if m.endswith(":fail")) == 1
    parts = _last(msgs, "stream-close").split(":")
    assert int(parts[3]) == k
    assert parts[5] == "degrade"


def test_outcome_verified_settlement_b6_default_ack_path_unaffected(tmp_path: Path) -> None:
    """Regression: the plain default (ack_received) path is unchanged."""
    msgs = _sends(_run(tmp_path))
    assert not any(m.startswith("gate:") for m in msgs)
    acks = [m for m in msgs if m.startswith("ack:")]
    assert acks
    assert all(len(m.split(":")) == 3 for m in acks)
    drained = int(_last(msgs, "stream-close").split(":")[3])
    assert drained == 5


def test_outcome_verified_settlement_b6_trace_grammar_wellformed_and_validators_pass(
    tmp_path: Path,
) -> None:
    """Every emitted line has the right arity and all four registered validators
    still pass on an EvaluatorGate-produced trace -- confirms they are gate-agnostic
    in practice, not just by code inspection."""
    events = _run(
        tmp_path, gate="evaluator", nonconform_at_tick=3, nonconform_mode="replay_previous"
    )
    arity = {"stream-open": 7, "tick": 5, "gate": 4, "stream-close": 6}
    for m in _sends(events):
        tag = m.split(":")[0]
        if tag in arity:
            assert len(m.split(":")) == arity[tag], m
        elif tag == "ack":
            assert len(m.split(":")) == 5, m  # content-gated: chunk_hex + declared
    results = validate_events(events, "outcome_verified_settlement")
    assert len(results) == 4
    assert all(r.passed for r in results), [r.detail for r in results if not r.passed]


def test_outcome_verified_settlement_b6_determinism_two_seeds(tmp_path: Path) -> None:
    """The evaluator/nonconform path adds no randomness: two seeds yield an identical trace."""
    a = _run(tmp_path, name="a.jsonl", gate="evaluator", nonconform_at_tick=3, seed=1)
    b = _run(tmp_path, name="b.jsonl", gate="evaluator", nonconform_at_tick=3, seed=2)
    assert _proj(a) == _proj(b)
