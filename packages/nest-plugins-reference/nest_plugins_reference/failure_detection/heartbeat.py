# SPDX-License-Identifier: Apache-2.0
"""Fixed-timeout heartbeat failure detector -- the naive baseline.

This is the textbook crash detector: remember the logical time of the most
recent heartbeat from each peer and suspect that peer once the silence since
that heartbeat exceeds a fixed ``timeout``.  It needs no warm-up and no
samples, which makes it simple -- but it cannot tell a *slow* peer from a
*dead* one.  Any legitimate inter-arrival gap longer than ``timeout`` (for
example the upper tail of a jittered heartbeat interval) trips a **false**
suspicion.

The :mod:`nest_plugins_reference.failure_detection.phi_accrual` detector exists
precisely to fix that accuracy failure, and the ``failure_detection`` scenario's
accuracy validator is tuned to expose this baseline's false positives while the
accrual detector passes.

Example::

    fd = HeartbeatFailureDetector(timeout=18.0)
    await fd.heartbeat(AgentId("peer-1"), now=10.0)
    assert not await fd.suspect(AgentId("peer-1"), now=20.0)
    assert await fd.suspect(AgentId("peer-1"), now=40.0)
"""

from __future__ import annotations

from nest_core.layers.failure_detector import FailureDetector
from nest_core.types import AgentId, Suspicion

DEFAULT_TIMEOUT = 18.0
"""Default silence (in logical time units) tolerated before suspicion."""


class HeartbeatFailureDetector:
    """Suspect a peer when time-since-last-heartbeat exceeds ``timeout``.

    Example::

        fd = HeartbeatFailureDetector(timeout=30.0)
    """

    def __init__(self, timeout: float = DEFAULT_TIMEOUT) -> None:
        self._timeout = timeout
        self._last_heartbeat: dict[AgentId, float] = {}

    def _elapsed(self, peer: AgentId, now: float) -> float | None:
        last = self._last_heartbeat.get(peer)
        if last is None:
            return None
        return now - last

    async def heartbeat(self, peer: AgentId, *, now: float) -> None:
        """Record the most recent heartbeat time for *peer*.

        Example::

            await fd.heartbeat(AgentId("peer-1"), now=12.0)
        """
        self._last_heartbeat[peer] = now

    async def phi(self, peer: AgentId, *, now: float) -> float:
        """Return elapsed/timeout as a crude suspicion ratio (>=1 means suspect).

        Unknown peers (no heartbeat yet) score ``0.0``.

        Example::

            ratio = await fd.phi(AgentId("peer-1"), now=20.0)
        """
        elapsed = self._elapsed(peer, now)
        if elapsed is None or self._timeout <= 0.0:
            return 0.0
        return round(elapsed / self._timeout, 6)

    async def suspect(self, peer: AgentId, *, now: float) -> bool:
        """Suspect iff a heartbeat was seen and the silence exceeds ``timeout``.

        A peer that has never sent a heartbeat is **not** suspected -- the
        detector cannot suspect what it has never observed alive.

        Example::

            await fd.suspect(AgentId("peer-1"), now=40.0)
        """
        elapsed = self._elapsed(peer, now)
        if elapsed is None:
            return False
        return elapsed > self._timeout

    async def report(self, peer: AgentId, *, now: float) -> Suspicion:
        """Return a :class:`~nest_core.types.Suspicion` snapshot for *peer*.

        Example::

            snap = await fd.report(AgentId("peer-1"), now=40.0)
        """
        return Suspicion(
            peer=peer,
            suspected=await self.suspect(peer, now=now),
            phi=await self.phi(peer, now=now),
            last_heartbeat=self._last_heartbeat.get(peer),
            observed_at=now,
        )

    def known_peers(self) -> list[AgentId]:
        """Return all peers observed alive at least once.

        Example::

            peers = fd.known_peers()
        """
        return list(self._last_heartbeat)


# Verify HeartbeatFailureDetector structurally satisfies the protocol at import.
_check: type[FailureDetector] = HeartbeatFailureDetector  # noqa: F841
