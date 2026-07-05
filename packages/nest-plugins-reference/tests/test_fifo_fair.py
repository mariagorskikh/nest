# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the fair-ordering coordination plugins.

Covers the survivor (:class:`FifoFairCoordination`) and its matched attacker
(:class:`PredatoryCoordination`): protocol conformance, arrival-order
preservation, the price-reorder front-run, and edge cases.
"""

from __future__ import annotations

from nest_core.layers.coordination import Coordination
from nest_core.types import AgentId, Task
from nest_plugins_reference.coordination.fifo_fair import (
    FifoFairCoordination,
    PredatoryCoordination,
)


async def _submit(coord: FifoFairCoordination, pairs: list[tuple[str, int]]) -> None:
    for agent, price in pairs:
        await coord.submit_order("r1", AgentId(agent), f"buy_{price}")


def test_both_plugins_satisfy_coordination_protocol() -> None:
    """Both plugins are structural ``Coordination`` implementations."""
    assert isinstance(FifoFairCoordination(), Coordination)
    assert isinstance(PredatoryCoordination(), Coordination)


async def test_fifo_preserves_arrival_order() -> None:
    """``fifo_fair`` finalizes orders in exactly the order they were submitted."""
    coord = FifoFairCoordination()
    await _submit(coord, [("t0", 100), ("t1", 149), ("t2", 107), ("t3", 121)])
    assert [a for a, _ in await coord.finalize("r1")] == ["t0", "t1", "t2", "t3"]


async def test_fifo_arrival_order_independent_of_price() -> None:
    """Arrival order is preserved even when prices would sort differently."""
    coord = FifoFairCoordination()
    await _submit(coord, [("t0", 100), ("t1", 200), ("t2", 150)])
    order = [a for a, _ in await coord.finalize("r1")]
    assert order == ["t0", "t1", "t2"]  # NOT sorted by price


async def test_predatory_reorders_by_descending_price() -> None:
    """``predatory`` front-runs: it sorts the batch by descending price."""
    coord = PredatoryCoordination()
    await _submit(coord, [("t0", 100), ("t1", 200), ("t2", 150)])
    order = [a for a, _ in await coord.finalize("r1")]
    assert order == ["t1", "t2", "t0"]  # 200, 150, 100


async def test_predatory_differs_from_fifo_on_same_input() -> None:
    """The attacker and the survivor disagree whenever prices are unsorted."""
    pairs = [("t0", 100), ("t1", 200), ("t2", 150)]
    fifo = FifoFairCoordination()
    pred = PredatoryCoordination()
    await _submit(fifo, pairs)
    await _submit(pred, pairs)
    assert await fifo.finalize("r1") != await pred.finalize("r1")


async def test_finalize_unknown_round_is_empty() -> None:
    """Finalizing a round with no orders returns an empty batch."""
    assert await FifoFairCoordination().finalize("never-opened") == []


async def test_propose_resolve_roundtrip() -> None:
    """The base protocol methods return well-formed objects."""
    coord = FifoFairCoordination()
    rnd = await coord.propose(Task(id="orders", description="batch"))
    assert rnd.id == "round-orders"
    outcome = await coord.resolve(rnd)
    assert outcome.round_id == rnd.id


async def test_predatory_handles_malformed_order() -> None:
    """A malformed order string is priced 0 and never crashes finalize."""
    coord = PredatoryCoordination()
    await coord.submit_order("r1", AgentId("t0"), "garbage")
    await coord.submit_order("r1", AgentId("t1"), "buy_200")
    order = [a for a, _ in await coord.finalize("r1")]
    assert order == ["t1", "t0"]  # 200 first, malformed (priced 0) last
