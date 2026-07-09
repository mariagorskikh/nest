# SPDX-License-Identifier: Apache-2.0
"""Phi-accrual failure detector (Hayashibara et al., 2004).

An *accrual* failure detector decouples monitoring from interpretation: instead
of emitting a boolean "up/down" it outputs a continuously rising suspicion level
``phi`` and lets each application choose its own threshold.

For every monitored peer it keeps a sliding window of recent heartbeat
*inter-arrival* intervals and models them as a normal distribution
``N(mean, std**2)``.  Given the elapsed time ``delta = now - last_arrival``
since the most recent heartbeat, the probability that the next heartbeat has
still not arrived by ``now`` under that model is the upper tail

    P_later(delta) = 1 - F(delta) = 0.5 * erfc((delta - mean) / (std * sqrt(2)))

and the suspicion level is

    phi(delta) = -log10(P_later(delta)).

``phi`` therefore stays low while ``delta`` is typical for the learned
distribution -- even when the heartbeat stream is *jittery* -- and climbs only
once the silence becomes statistically surprising.  That is the decisive
advantage over a fixed timeout: a wide-but-normal jitter gap that would trip a
tight timeout barely moves ``phi``, while a genuine crash drives it past the
threshold within roughly one expected interval.

The window uses *population* variance and clamps the standard deviation to a
configurable floor ``min_std`` so a near-constant heartbeat stream cannot cause
a divide-by-zero or an absurdly sharp distribution.  The tail probability is
floored at :data:`_P_FLOOR` (capping ``phi`` near 18) so the result is always
finite, and every emitted float is rounded to 6 decimals so the JSONL trace is
byte-identical across runs with the same seed.

Example::

    fd = PhiAccrualFailureDetector(threshold=8.0)
    for t in range(0, 100, 10):
        await fd.heartbeat(AgentId("peer-1"), now=float(t))
    # Right after a heartbeat suspicion is ~0...
    assert await fd.phi(AgentId("peer-1"), now=100.0) < 1.0
    # ...and after a long silence it climbs past the threshold.
    assert await fd.suspect(AgentId("peer-1"), now=400.0)
"""

from __future__ import annotations

import math
from collections import deque

from nest_core.layers.failure_detector import FailureDetector
from nest_core.types import AgentId, Suspicion

DEFAULT_WINDOW_SIZE = 200
"""Maximum number of recent inter-arrival samples retained per peer."""

DEFAULT_MIN_SAMPLES = 5
"""Minimum samples before ``phi`` is computed; below this it returns ``0.0``."""

DEFAULT_MIN_STD = 1.0
"""Floor on the estimated standard deviation, in logical time units."""

DEFAULT_THRESHOLD = 8.0
"""Suspicion level at or above which a peer is reported as suspected."""

_P_FLOOR = 1e-18
"""Lower bound on the tail probability, capping ``phi`` at roughly 18."""


class _PeerWindow:
    """Sliding window of heartbeat inter-arrival samples for one peer.

    Example::

        w = _PeerWindow(window_size=200, min_std=1.0)
        w.observe(10.0)
    """

    def __init__(self, window_size: int, min_std: float) -> None:
        self._intervals: deque[float] = deque(maxlen=window_size)
        self._min_std = min_std
        self.last_arrival: float | None = None

    def observe(self, now: float) -> None:
        """Record a heartbeat arrival at *now*, updating the interval window.

        Example::

            w.observe(12.5)
        """
        if self.last_arrival is not None:
            self._intervals.append(now - self.last_arrival)
        self.last_arrival = now

    def sample_count(self) -> int:
        """Return the number of inter-arrival samples currently held.

        Example::

            n = w.sample_count()
        """
        return len(self._intervals)

    def phi(self, now: float, *, min_samples: int) -> float:
        """Return the accrual suspicion level for *now*.

        Returns ``0.0`` until at least *min_samples* intervals have been
        observed, so a cold detector never suspects a peer prematurely.

        Example::

            level = w.phi(40.0, min_samples=5)
        """
        last = self.last_arrival
        if last is None or len(self._intervals) < min_samples:
            return 0.0
        n = len(self._intervals)
        mean = sum(self._intervals) / n
        var = sum((x - mean) ** 2 for x in self._intervals) / n
        std = max(math.sqrt(var), self._min_std)
        delta = now - last
        p_later = 0.5 * math.erfc((delta - mean) / (std * math.sqrt(2.0)))
        p_later = max(p_later, _P_FLOOR)
        return -math.log10(p_later)


class PhiAccrualFailureDetector:
    """Adaptive accrual failure detector with a per-peer interval window.

    Example::

        fd = PhiAccrualFailureDetector(window_size=200, threshold=8.0)
    """

    def __init__(
        self,
        window_size: int = DEFAULT_WINDOW_SIZE,
        min_samples: int = DEFAULT_MIN_SAMPLES,
        min_std: float = DEFAULT_MIN_STD,
        threshold: float = DEFAULT_THRESHOLD,
    ) -> None:
        self._window_size = window_size
        self._min_samples = min_samples
        self._min_std = min_std
        self._threshold = threshold
        self._windows: dict[AgentId, _PeerWindow] = {}

    def _window_for(self, peer: AgentId) -> _PeerWindow:
        window = self._windows.get(peer)
        if window is None:
            window = _PeerWindow(self._window_size, self._min_std)
            self._windows[peer] = window
        return window

    async def heartbeat(self, peer: AgentId, *, now: float) -> None:
        """Record a heartbeat from *peer* at *now*.

        Example::

            await fd.heartbeat(AgentId("peer-1"), now=12.0)
        """
        self._window_for(peer).observe(now)

    async def phi(self, peer: AgentId, *, now: float) -> float:
        """Return ``phi`` for *peer*; unknown or cold peers score ``0.0``.

        Example::

            level = await fd.phi(AgentId("peer-1"), now=40.0)
        """
        window = self._windows.get(peer)
        if window is None:
            return 0.0
        return round(window.phi(now, min_samples=self._min_samples), 6)

    async def suspect(self, peer: AgentId, *, now: float) -> bool:
        """Suspect *peer* iff its ``phi`` is at or above ``threshold``.

        Example::

            await fd.suspect(AgentId("peer-1"), now=400.0)
        """
        return await self.phi(peer, now=now) >= self._threshold

    async def report(self, peer: AgentId, *, now: float) -> Suspicion:
        """Return a :class:`~nest_core.types.Suspicion` snapshot for *peer*.

        Example::

            snap = await fd.report(AgentId("peer-1"), now=400.0)
        """
        window = self._windows.get(peer)
        last_heartbeat = window.last_arrival if window is not None else None
        return Suspicion(
            peer=peer,
            suspected=await self.suspect(peer, now=now),
            phi=await self.phi(peer, now=now),
            last_heartbeat=last_heartbeat,
            observed_at=now,
        )

    def known_peers(self) -> list[AgentId]:
        """Return all peers for which a heartbeat has ever been observed.

        Example::

            peers = fd.known_peers()
        """
        return list(self._windows)


# Verify PhiAccrualFailureDetector structurally satisfies the protocol at import.
_check: type[FailureDetector] = PhiAccrualFailureDetector  # noqa: F841
