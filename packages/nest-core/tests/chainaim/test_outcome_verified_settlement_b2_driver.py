# SPDX-License-Identifier: Apache-2.0
"""Iteration-2 (outcome_verified_settlement_b2) driver tests: gate wiring + trace grammar.

Exercise the real buyer/seller agents through the real discrete-event simulator
and the real outcome-verified-settlement plugin (no hand-built traces, no mocks), then
assert on the JSONL the run emits:

* the default delivery-gated path is byte-identical to the pre-gate scenario
  (no ``gate:`` lines, three-field ``ack``, unchanged drained total);
* a content-gate degrade emits ``gate:<ref>:k:fail`` and stops billing at the
  verified prefix;
* every emitted line is well-formed and the two existing validators still pass;
* two seeds produce an identical trace (the gate path adds no randomness).
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from nest_core.scenarios_builtin.chainaim.outcome_verified_settlement import (
    OutcomeVerifiedSettlementBuyerAgent,
    OutcomeVerifiedSettlementSellerAgent,
)
from nest_core.sim.simulator import Simulator
from nest_core.types import AgentId, PaymentRef
from nest_core.validators import validate_events
from nest_plugins_reference.payments.chainaim.outcome_verified_settlement import (
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
    degrade_at_tick: int | None = None,
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
        _SELLER, content_gated=(gate != "ack_received"), degrade_at_tick=degrade_at_tick
    )
    buyer = OutcomeVerifiedSettlementBuyerAgent(
        _BUYER,
        _SELLER,
        rate_per_tick=rate,
        close_at_tick=close_at_tick,
        gate=gate,
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


def test_outcome_verified_settlement_b2_default_path_byte_identical(tmp_path: Path) -> None:
    """Default delivery gate leaks no content-gate grammar and bills unchanged."""
    msgs = _sends(_run(tmp_path))
    assert not any(m.startswith("gate:") for m in msgs)
    acks = [m for m in msgs if m.startswith("ack:")]
    assert acks
    assert all(len(m.split(":")) == 3 for m in acks)
    drained = int(_last(msgs, "stream-close").split(":")[3])
    assert drained == 5  # rate 1 * close_at_tick 5


def test_outcome_verified_settlement_b2_degrade_emits_fail_and_stops(tmp_path: Path) -> None:
    """Content gate emits gate:<ref>:k:fail at the corrupted unit and stops billing."""
    k = 2
    msgs = _sends(_run(tmp_path, gate="checksum", degrade_at_tick=k, close_at_tick=5))
    gate_lines = [m for m in msgs if m.startswith("gate:")]
    assert f"gate:{_REF}:{k}:fail" in gate_lines
    assert sum(1 for m in gate_lines if m.endswith(":fail")) == 1
    assert all(m.endswith(":pass") for m in gate_lines if not m.endswith(":fail"))
    parts = _last(msgs, "stream-close").split(":")
    assert int(parts[3]) == k  # drained == verified prefix (rate 1 * k)
    assert parts[5] == "degrade"


def test_outcome_verified_settlement_b2_trace_grammar_wellformed(tmp_path: Path) -> None:
    """Every emitted line has the right arity and existing validators still pass."""
    events = _run(tmp_path, gate="checksum", degrade_at_tick=3, close_at_tick=5)
    arity = {"stream-open": 7, "tick": 5, "gate": 4, "stream-close": 6}
    for m in _sends(events):
        tag = m.split(":")[0]
        if tag in arity:
            assert len(m.split(":")) == arity[tag], m
        elif tag == "ack":
            assert len(m.split(":")) == 5, m  # content-gated: chunk_hex + declared
    results = validate_events(events, "outcome_verified_settlement")
    assert len(results) == 4
    assert all(r.passed for r in results), [r.detail for r in results]


def test_outcome_verified_settlement_b2_determinism_two_seeds(tmp_path: Path) -> None:
    """The gate path adds no randomness: two seeds yield an identical trace."""
    a = _run(tmp_path, name="a.jsonl", gate="checksum", degrade_at_tick=2, seed=1)
    b = _run(tmp_path, name="b.jsonl", gate="checksum", degrade_at_tick=2, seed=2)
    assert _proj(a) == _proj(b)
