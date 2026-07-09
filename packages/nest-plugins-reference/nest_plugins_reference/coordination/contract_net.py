# SPDX-License-Identifier: Apache-2.0
"""Contract Net coordination plugin — classic FIPA Contract Net Protocol.

The Round object is shared between manager and workers. Bids are stored
in the round's metadata so any party can resolve them.

Example::

    coord = ContractNet(AgentId("manager"))
    rnd = await coord.propose(task)
    bid = await coord.participate(rnd)
"""

from __future__ import annotations

from nest_core.types import (
    AgentId,
    Bid,
    Money,
    Outcome,
    Round,
    Task,
    Vote,
)

from ._ids import derive_round_id


class ContractNet:
    """FIPA Contract Net Protocol implementation.

    Example::

        coord = ContractNet(AgentId("a1"))
        rnd = await coord.propose(Task(id="t1", description="work"))
    """

    def __init__(self, agent_id: AgentId) -> None:
        self._agent_id = agent_id
        self._round_seq = 0

    async def propose(self, task: Task) -> Round:
        """Propose a task for bidding.

        The round id is derived deterministically from the proposing agent, the
        task, and a monotonic per-proposer sequence number, so a seeded run
        replays byte-for-byte (ADR-004) instead of drawing a fresh ``uuid4``
        each run. See :func:`._ids.derive_round_id`.

        Example::

            rnd = await coord.propose(task)
        """
        self._round_seq += 1
        round_id = derive_round_id(self._agent_id, task.id, self._round_seq)
        rnd = Round(
            id=round_id,
            task=task,
            participants=[],
            metadata={"bids": []},
        )
        return rnd

    async def participate(self, round: Round) -> Vote | Bid:
        """Submit a bid for a round.

        Example::

            bid = await coord.participate(rnd)
        """
        bid = Bid(
            bidder=self._agent_id,
            round_id=round.id,
            amount=Money(amount=1),
        )
        bids: list[dict[str, object]] = round.metadata.setdefault("bids", [])
        bids.append({"bidder": str(bid.bidder), "amount": bid.amount.amount})
        if self._agent_id not in round.participants:
            round.participants.append(self._agent_id)
        return bid

    async def resolve(self, round: Round) -> Outcome:
        """Resolve a round by selecting the lowest bidder.

        Example::

            outcome = await coord.resolve(rnd)
        """
        bids: list[dict[str, object]] = round.metadata.get("bids", [])
        winner: AgentId | None = None
        if bids:
            best = min(bids, key=lambda b: int(str(b["amount"])))
            winner = AgentId(str(best["bidder"]))
        return Outcome(round_id=round.id, winner=winner, task=round.task)

    async def commit(self, outcome: Outcome) -> None:
        """Commit to an outcome.

        Example::

            await coord.commit(outcome)
        """
