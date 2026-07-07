# SPDX-License-Identifier: Apache-2.0
"""Benchmark: what the default registry hides, and what the resolver fixes.

This is a property-surfacing benchmark, not a micro-benchmark. It churns a large
fleet of agents through both registries — most of them "crash" (they register once
and never heartbeat) — then advances time and asks each registry who is still
resolvable. The numbers make the hidden behavior of `in_memory` explicit:

  * ``in_memory`` returns *every* agent it has ever seen, including the crashed ones,
    and its memory grows with the total number of agents ever registered.
  * ``resolver`` returns only the agents still alive, and its memory is bounded to
    that live set, because expired records are pruned.

The gap between the two counts is the number of dead agents `in_memory` would hand
out as live addresses — the liveness lie this plugin removes.
"""

from __future__ import annotations

import pytest
from nest_core.types import AgentCard, AgentId, Query
from nest_plugins_reference.registry.caching_resolver import CachingResolverRegistry
from nest_plugins_reference.registry.in_memory import InMemoryRegistry

_CAP = "discoverable"
_FLEET = 2000
_STABLE_EVERY = 5  # one in five agents keeps a long TTL; the rest crash


def _card(i: int) -> AgentCard:
    ttl = 100_000.0 if i % _STABLE_EVERY == 0 else 10.0
    return AgentCard(
        agent_id=AgentId(f"a{i}"), name=f"a{i}", capabilities=[_CAP], metadata={"ttl": ttl}
    )


@pytest.mark.asyncio
async def test_benchmark_liveness_and_memory() -> None:
    stable_count = len(range(0, _FLEET, _STABLE_EVERY))
    query = Query(capabilities=[_CAP])

    in_memory = InMemoryRegistry()
    resolver = CachingResolverRegistry(clock=0.0)
    for i in range(_FLEET):
        card = _card(i)
        await in_memory.register(card)
        await resolver.register(card)

    # Time passes; the crashed agents never heartbeat.
    resolver.set_clock(1_000.0)  # well past the 10-tick ephemeral TTL

    in_memory_live = await in_memory.lookup(query)
    resolver_live = await resolver.lookup(query)

    # in_memory serves every agent ever registered — including the crashed ones.
    assert len(in_memory_live) == _FLEET
    # resolver serves only the agents still alive...
    assert len(resolver_live) == stable_count
    # ...and its memory is bounded to that live set, not the total ever seen.
    assert len(resolver.live_agents()) == stable_count

    # The hidden property, made explicit: this many dead agents would be handed out
    # as live addresses by the default registry, and zero by the resolver.
    dead_served_by_in_memory = len(in_memory_live) - len(resolver_live)
    assert dead_served_by_in_memory == _FLEET - stable_count
    assert dead_served_by_in_memory > 0
