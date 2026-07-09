# SPDX-License-Identifier: Apache-2.0
"""HotStuff coordination plugin -- ``Coordination`` protocol conformance wrapper.

This class satisfies the ``Coordination`` protocol's ``propose`` /
``participate`` / ``resolve`` / ``commit`` surface for isolated,
single-process testing: it runs one PREPARE -> COMMIT round in-memory with
no networking, no view-change timers, and no Byzantine handling.

The full networked protocol -- multi-round messaging, round-robin leader
rotation, view-change on timeout, the locked-QC safety rule across views,
and the deliberately-malicious leader behavior exercised by the Byzantine
scenario -- lives in ``nest_core.scenarios_builtin.bft_hotstuff``
(``ReplicaAgent`` / ``MaliciousLeaderAgent``), which drives the simulator's
event loop directly. This split mirrors the existing precedent set by
``contract_net`` and ``nest_core.scenarios_builtin.consensus``: every
built-in scenario factory hand-rolls its wire protocol inside
``StateMachineAgent`` subclasses rather than calling into the
``Coordination``-shaped plugin -- that plugin class exists for API
conformance and isolated unit testing only, it is not invoked by the
simulator at runtime.

Example::

    coord = HotStuff(AgentId("r0"), f=1)
    rnd = await coord.propose(Task(id="t1", description="agree on a value"))
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from typing import Any

from nest_core.types import AgentId, Outcome, Round, Task, Vote


class HotStuff:
    """Single-process HotStuff round: propose, vote, resolve by quorum.

    Example::

        coord = HotStuff(AgentId("r0"), f=1)
        rnd = await coord.propose(Task(id="t1", description="work"))
    """

    def __init__(
        self,
        agent_id: AgentId,
        f: int = 1,
        replica_ids: Sequence[AgentId] | None = None,
    ) -> None:
        self._agent_id = agent_id
        self._f = f
        self._replica_ids = list(replica_ids) if replica_ids is not None else [agent_id]

    async def propose(self, task: Task) -> Round:
        """Propose a task as a single-view HotStuff round.

        Example::

            rnd = await coord.propose(task)
        """
        round_id = str(uuid.uuid4())
        return Round(
            id=round_id,
            task=task,
            participants=[],
            metadata={"view": 0, "votes": [], "quorum": 2 * self._f + 1},
        )

    async def participate(self, round: Round) -> Vote:
        """Cast a prepare-phase accept vote for the round's task.

        Example::

            vote = await coord.participate(rnd)
        """
        vote = Vote(voter=self._agent_id, round_id=round.id, value="accept")
        votes: list[dict[str, Any]] = round.metadata.setdefault("votes", [])
        votes.append({"voter": str(vote.voter), "value": vote.value})
        if self._agent_id not in round.participants:
            round.participants.append(self._agent_id)
        return vote

    async def resolve(self, round: Round) -> Outcome:
        """Resolve a round once at least 2f+1 prepare votes have accumulated.

        Example::

            outcome = await coord.resolve(rnd)
        """
        votes: list[dict[str, Any]] = round.metadata.get("votes", [])
        accepts = sum(1 for v in votes if v.get("value") == "accept")
        quorum = int(round.metadata.get("quorum", 2 * self._f + 1))
        winner: AgentId | None = self._agent_id if accepts >= quorum else None
        return Outcome(
            round_id=round.id,
            winner=winner,
            task=round.task,
            metadata={"accepts": accepts, "quorum": quorum},
        )

    async def commit(self, outcome: Outcome) -> None:
        """Commit a resolved outcome.

        This wrapper holds no externally-visible state, so commit is a
        no-op; the networked protocol's actual commit/decide step lives in
        ``ReplicaAgent`` in ``nest_core.scenarios_builtin.bft_hotstuff``.

        Example::

            await coord.commit(outcome)
        """
