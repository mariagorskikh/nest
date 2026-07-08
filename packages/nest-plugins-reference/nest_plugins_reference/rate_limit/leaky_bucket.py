# SPDX-License-Identifier: Apache-2.0
"""Leaky Bucket Rate Limiter reference implementation."""

from __future__ import annotations

from nest_core.types import AgentId


class LeakyBucketRateLimiter:
    """Bucket leaks water at a constant rate. Requests fail if bucket overflows.

    Example::

        limiter = LeakyBucketRateLimiter(rate=1.0, capacity=5.0)
    """

    def __init__(self, rate: float = 1.0, capacity: float = 10.0) -> None:
        self.rate = rate
        self.capacity = capacity
        self._water_level: dict[AgentId, float] = {}
        self._last_updated: dict[AgentId, float] = {}

    def _leak(self, client: AgentId, now: float) -> None:
        if client not in self._water_level:
            self._water_level[client] = 0.0
            self._last_updated[client] = now
            return

        last = self._last_updated[client]
        elapsed = max(0.0, now - last)
        leaked = elapsed * self.rate
        self._water_level[client] = max(0.0, self._water_level[client] - leaked)
        self._last_updated[client] = now

    async def consume(self, client: AgentId, *, now: float, tokens: float = 1.0) -> bool:
        self._leak(client, now)
        if self._water_level[client] + tokens <= self.capacity:
            self._water_level[client] += tokens
            return True
        return False

    async def allowance(self, client: AgentId, *, now: float) -> float:
        if client not in self._water_level:
            return self.capacity

        last = self._last_updated[client]
        elapsed = max(0.0, now - last)
        leaked = elapsed * self.rate
        current_water = max(0.0, self._water_level[client] - leaked)
        return max(0.0, self.capacity - current_water)
