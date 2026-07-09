# SPDX-License-Identifier: Apache-2.0
"""Failure-detector layer interface: how agents decide a peer is dead.

A failure detector is a liveness oracle.  It consumes heartbeat observations
and answers, at any logical time ``now``, whether each known peer is currently
*suspected* of having failed.  Implementations range from a fixed-timeout
baseline to adaptive accrual detectors (phi-accrual) that learn the heartbeat
inter-arrival distribution and emit a continuous suspicion level.

Every method takes ``now`` (the caller's virtual simulation time) as a
keyword-only argument instead of reading a wall clock, so detection is a pure
function of the observed heartbeat history and stays fully deterministic under
replay.

Example::

    class MyDetector(FailureDetector):
        async def heartbeat(self, peer, *, now):
            self._last[peer] = now
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from nest_core.types import AgentId, Suspicion


@runtime_checkable
class FailureDetector(Protocol):
    """Liveness oracle: tracks heartbeats and reports suspected-dead peers.

    Example::

        fd: FailureDetector = PhiAccrualFailureDetector()
        await fd.heartbeat(AgentId("peer-1"), now=10.0)
        suspected = await fd.suspect(AgentId("peer-1"), now=999.0)
    """

    async def heartbeat(self, peer: AgentId, *, now: float) -> None:
        """Record a heartbeat observed from *peer* at logical time *now*.

        Example::

            await fd.heartbeat(AgentId("peer-1"), now=ctx.time)
        """
        ...

    async def suspect(self, peer: AgentId, *, now: float) -> bool:
        """Return whether *peer* is currently suspected of having failed.

        Example::

            if await fd.suspect(AgentId("peer-1"), now=ctx.time):
                reroute_around(peer)
        """
        ...

    async def phi(self, peer: AgentId, *, now: float) -> float:
        """Return the current suspicion level for *peer* (higher = more suspect).

        A fixed-timeout detector returns a normalized elapsed/timeout ratio;
        an accrual detector returns ``-log10(P(heartbeat still pending))``.

        Example::

            level = await fd.phi(AgentId("peer-1"), now=ctx.time)
        """
        ...

    async def report(self, peer: AgentId, *, now: float) -> Suspicion:
        """Return a full :class:`~nest_core.types.Suspicion` snapshot for *peer*.

        Example::

            snap = await fd.report(AgentId("peer-1"), now=ctx.time)
        """
        ...

    def known_peers(self) -> list[AgentId]:
        """Return every peer for which at least one heartbeat was observed.

        Example::

            for peer in fd.known_peers():
                print(peer)
        """
        ...
