# SPDX-License-Identifier: Apache-2.0
"""Token Bucket Rate Limiter reference implementation."""

from __future__ import annotations

from nest_core.types import AgentId


class TokenBucketRateLimiter:
    """Refills tokens at a constant rate up to a max capacity.

    Example::

        limiter = TokenBucketRateLimiter(rate=2.0, capacity=10.0)
    """

    def __init__(self, rate: float = 1.0, capacity: float = 10.0) -> None:
        self.rate = rate
        self.capacity = capacity
        self._tokens: dict[AgentId, float] = {}
        self._last_updated: dict[AgentId, float] = {}

    def _update_tokens(self, client: AgentId, now: float) -> None:
        if client not in self._tokens:
            self._tokens[client] = self.capacity
            self._last_updated[client] = now
            return

        last = self._last_updated[client]
        elapsed = max(0.0, now - last)
        refill = elapsed * self.rate
        self._tokens[client] = min(self.capacity, self._tokens[client] + refill)
        self._last_updated[client] = now

    async def consume(self, client: AgentId, *, now: float, tokens: float = 1.0) -> bool:
        self._update_tokens(client, now)
        if self._tokens[client] >= tokens:
            self._tokens[client] -= tokens
            return True
        return False

    async def allowance(self, client: AgentId, *, now: float) -> float:
        # Dry update to get accurate allowance without updating state timestamps or consuming
        if client not in self._tokens:
            return self.capacity

        last = self._last_updated[client]
        elapsed = max(0.0, now - last)
        refill = elapsed * self.rate
        return min(self.capacity, self._tokens[client] + refill)
