# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import pytest
from nest_core.layers.rate_limiter import RateLimiter
from nest_core.types import AgentId
from nest_plugins_reference.rate_limit.leaky_bucket import LeakyBucketRateLimiter
from nest_plugins_reference.rate_limit.token_bucket import TokenBucketRateLimiter


@pytest.mark.asyncio
async def test_protocol_conformance() -> None:
    # Verify both implementations conform to RateLimiter Protocol
    tb: RateLimiter = TokenBucketRateLimiter()
    lb: RateLimiter = LeakyBucketRateLimiter()
    assert isinstance(tb, RateLimiter)
    assert isinstance(lb, RateLimiter)


@pytest.mark.asyncio
async def test_token_bucket_limits() -> None:
    limiter = TokenBucketRateLimiter(rate=2.0, capacity=5.0)
    client = AgentId("agent-1")

    # Initial allowance matches capacity
    assert await limiter.allowance(client, now=0.0) == 5.0

    # Consume full capacity
    assert await limiter.consume(client, now=0.0, tokens=5.0) is True
    assert await limiter.allowance(client, now=0.0) == 0.0

    # Next consumption fails
    assert await limiter.consume(client, now=0.0, tokens=1.0) is False

    # Replenishment over virtual time
    assert await limiter.allowance(client, now=1.0) == 2.0  # elapsed 1s * rate 2 = 2 tokens
    assert await limiter.consume(client, now=1.0, tokens=2.0) is True
    assert await limiter.allowance(client, now=1.0) == 0.0

    # Cap at capacity
    assert await limiter.allowance(client, now=10.0) == 5.0  # elapsed 9s * rate 2 > capacity 5


@pytest.mark.asyncio
async def test_leaky_bucket_limits() -> None:
    limiter = LeakyBucketRateLimiter(rate=1.0, capacity=3.0)
    client = AgentId("agent-1")

    # Initial allowance matches capacity (bucket water level = 0)
    assert await limiter.allowance(client, now=0.0) == 3.0

    # Add water to capacity
    assert await limiter.consume(client, now=0.0, tokens=3.0) is True
    assert await limiter.allowance(client, now=0.0) == 0.0

    # Overflows
    assert await limiter.consume(client, now=0.0, tokens=1.0) is False

    # Leaks over virtual time
    assert await limiter.allowance(client, now=2.0) == 2.0  # leaks 2.0 water, 2.0 allowance remains
    assert await limiter.consume(client, now=2.0, tokens=2.0) is True
    assert await limiter.allowance(client, now=2.0) == 0.0


@pytest.mark.asyncio
async def test_independent_clients() -> None:
    limiter = TokenBucketRateLimiter(rate=1.0, capacity=2.0)
    c1 = AgentId("agent-1")
    c2 = AgentId("agent-2")

    # Consume tokens for c1
    assert await limiter.consume(c1, now=0.0, tokens=2.0) is True
    assert await limiter.consume(c1, now=0.0, tokens=1.0) is False

    # c2 is unaffected
    assert await limiter.allowance(c2, now=0.0) == 2.0
    assert await limiter.consume(c2, now=0.0, tokens=2.0) is True
