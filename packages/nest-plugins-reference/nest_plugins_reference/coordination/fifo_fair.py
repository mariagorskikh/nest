# SPDX-License-Identifier: Apache-2.0
"""Fair-ordering coordination -- a red-team of the ordering design space.

**The finding, in one line:** in an agent marketplace the sequencer decides the
execution order, and *whoever authors the order can extract value from it*
(front-running / MEV). We tried five sequencer-authored fair-ordering schemes
and broke every one:

===============================  ===================================  =========
scheme                           who authors the order                result
===============================  ===================================  =========
sort commitments by hash         a grinding trader (nonce grind)      broken
beacon over public commits       a last-mover trader                  broken
beacon over private commits      the omniscient sequencer             broken
beacon + sequencer-commits-first the sequencer (selective inclusion)  broken
FIFO by sequencer-polled commits the sequencer (emission order)       broken
===============================  ===================================  =========

The escape is the same in every row: **the order must be authored by something
the sequencer cannot see or control.** In Nanda Town's Tier-1 engine that
neutral author already exists -- the simulator stamps every broadcast with a
monotonic, engine-assigned ``corr`` id the sequencer cannot forge. So the
survivor, :class:`FifoFairCoordination`, executes orders in the engine's
arrival order and a validator reconstructs that order from ``corr`` (not from
anything the sequencer wrote) to prove no reordering happened.

Scope, stated honestly: in zero-latency Tier-1, "arrival order" collapses to a
fixed registration order, so this delivers **unmanipulability (anti-MEV), not
egalitarian fairness** -- no party can *alter* the order, though it is not an
equal-opportunity race. Real-latency first-come-first-served is the deployment
reading. The complete answer against a self-interested sequencer is an
*encrypted* order flow (Shutter/Aequitas), a privacy x coordination cross-layer
composition named as the frontier, not built here.

:class:`PredatoryCoordination` is the matched attacker: it reorders the batch at
finalize (front-running by price). The integrity validator FAILS it and PASSES
:class:`FifoFairCoordination`, on the same scenario.

Example::

    coord = FifoFairCoordination()
    await coord.submit_order("r1", AgentId("trader-0"), "buy_120")
    await coord.submit_order("r1", AgentId("trader-1"), "buy_100")
    batch = await coord.finalize("r1")   # arrival order preserved
    assert [a for a, _ in batch] == ["trader-0", "trader-1"]
"""

from __future__ import annotations

from nest_core.types import AgentId, Outcome, Round, Task, Vote


class FairOrderingError(ValueError):
    """Raised on a fair-ordering protocol violation.

    Example::

        raise FairOrderingError("unknown round")
    """


class FifoFairCoordination:
    """Executes orders in engine-authored arrival order; the sequencer cannot reorder.

    A single shared instance backs a scenario. Traders append their orders via
    :meth:`submit_order` (in the engine's ``on_start`` order); :meth:`finalize`
    returns them **unreordered**. The neutral arrival order is recoverable from
    the trace's ``corr`` ids, so a validator can prove ``finalize`` did not
    permute it.

    Example::

        coord = FifoFairCoordination()
        await coord.submit_order("r1", AgentId("t0"), "buy_120")
        batch = await coord.finalize("r1")
    """

    def __init__(self) -> None:
        """Create an empty sequencer.

        Example::

            coord = FifoFairCoordination()
        """
        self._orders: dict[str, list[tuple[str, str]]] = {}

    # -- Coordination protocol -------------------------------------------

    async def propose(self, task: Task) -> Round:
        """Open a coordination round for ``task``.

        Example::

            rnd = await coord.propose(Task(id="orders", description="batch"))
        """
        return Round(id=f"round-{task.id}", task=task)

    async def participate(self, round: Round) -> Vote:
        """Acknowledge participation (orders are submitted via the extension API).

        Example::

            vote = await coord.participate(rnd)
        """
        return Vote(voter=AgentId("participant"), round_id=round.id, value="ack")

    async def resolve(self, round: Round) -> Outcome:
        """Resolve ``round`` (the ordered batch is produced by :meth:`finalize`).

        Example::

            outcome = await coord.resolve(rnd)
        """
        return Outcome(round_id=round.id, task=round.task)

    async def commit(self, outcome: Outcome) -> None:
        """Commit to a resolved ``outcome`` (no-op; the batch is already durable).

        Example::

            await coord.commit(outcome)
        """

    # -- fair-ordering extension -----------------------------------------

    async def submit_order(self, round_id: str, agent: AgentId, order: str) -> None:
        """Append ``agent``'s order in arrival order.

        Example::

            await coord.submit_order("r1", AgentId("t0"), "buy_120")
        """
        self._orders.setdefault(round_id, []).append((str(agent), order))

    async def finalize(self, round_id: str) -> list[tuple[str, str]]:
        """Return ``[(agent, order), ...]`` in **arrival order** (no reordering).

        Example::

            batch = await coord.finalize("r1")
        """
        return list(self._orders.get(round_id, []))


class PredatoryCoordination(FifoFairCoordination):
    """A front-running sequencer: reorders the batch by price at finalize.

    Identical to :class:`FifoFairCoordination` except :meth:`finalize` sorts
    orders by descending price -- prioritising the biggest orders (MEV
    extraction). The integrity validator catches this because the executed
    order disagrees with the engine's ``corr`` arrival order.

    Example::

        coord = PredatoryCoordination()
        await coord.submit_order("r1", AgentId("t0"), "buy_100")
        await coord.submit_order("r1", AgentId("t1"), "buy_200")
        batch = await coord.finalize("r1")   # t1 (200) jumped ahead of t0 (100)
    """

    @staticmethod
    def _price(order: str) -> int:
        try:
            return int(order.rsplit("_", 1)[1])
        except (IndexError, ValueError):
            return 0

    async def finalize(self, round_id: str) -> list[tuple[str, str]]:
        """Return the batch reordered by descending price (the front-run).

        Example::

            batch = await coord.finalize("r1")
        """
        orders = list(self._orders.get(round_id, []))
        orders.sort(key=lambda ao: -self._price(ao[1]))
        return orders
