# SPDX-License-Identifier: Apache-2.0
"""Rate-limiter layer interface: tracks and bounds traffic consumption per agent.

A rate limiter provides a traffic oracle. It tracks request allowances for clients
over logical simulation time 'now' and enforces limits to prevent message spam or
resource starvation.

Every method takes 'now' (the caller's virtual simulation time) as a keyword-only
argument to ensure that traffic metrics and rate limiting remain fully deterministic
and trace-reproducible.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from nest_core.types import AgentId


@runtime_checkable
class RateLimiter(Protocol):
    """Traffic oracle: tracks request counts and enforces rate limits.

    Example::

        limiter: RateLimiter = TokenBucketRateLimiter(rate=2.0, capacity=10.0)
        allowed = await limiter.consume(AgentId("agent-1"), now=ctx.time, tokens=1.0)
    """

    async def consume(self, client: AgentId, *, now: float, tokens: float = 1.0) -> bool:
        """Attempt to consume 'tokens' for a client at logical time 'now'.

        Returns True if the request is permitted, or False if the client is rate-limited.

        Example::

            if not await limiter.consume(AgentId("sender"), now=ctx.time):
                raise Exception("Rate limit exceeded")
        """
        ...

    async def allowance(self, client: AgentId, *, now: float) -> float:
        """Return the current available token allowance for the client at time 'now'.

        Example::

            remaining = await limiter.allowance(AgentId("sender"), now=ctx.time)
        """
        ...
