# SPDX-License-Identifier: Apache-2.0
"""Caching resolver registry — DNS-style discovery with TTL, negative caching, self-eviction.

The default `in_memory` registry is a plain dictionary: once an agent registers, its
card is returned forever, even after the agent has crashed and will never answer. At
any real scale that is a liveness lie — discovery keeps handing out dead addresses.

DNS solved this decades ago with three ideas this plugin brings to the registry layer:

* **TTL on every record.** A card is only resolvable until `now + ttl`. An agent stays
  discoverable by re-registering (a heartbeat) before its TTL lapses. A crashed agent
  simply stops heartbeating and **self-evicts** when its TTL expires — no manual
  deregister, no tombstones.
* **Negative caching.** A query that matches nothing is remembered for a short
  `negative_ttl`, so a storm of lookups for something that does not exist is answered
  from cache in O(1) instead of rescanning the whole table (DNS SOA-minimum caching).
* **Per-record TTL.** Each agent picks its own freshness via `card.metadata["ttl"]`,
  exactly like a DNS zone sets TTL per record. No core type changes.

Example::

    reg = CachingResolverRegistry(default_ttl=300.0, clock=0.0)
    await reg.register(AgentCard(agent_id=AgentId("a1"), name="A1",
                                 capabilities=["sell"], metadata={"ttl": 10}))
    reg.set_clock(100.0)                       # 100s later, past the 10s TTL...
    await reg.lookup(Query(capabilities=["sell"]))   # -> [] (a1 self-evicted)
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from dataclasses import dataclass

from nest_core.types import AgentCard, AgentId, Query


@dataclass
class _Record:
    """A cached card plus the wall-time it stops being resolvable."""

    card: AgentCard
    expires_at: float


class CachingResolverRegistry:
    """A registry that expires stale records and negatively caches empty lookups.

    Example::

        reg = CachingResolverRegistry(default_ttl=300.0)
        await reg.register(card)
        results = await reg.lookup(Query(capabilities=["sell"]))
    """

    def __init__(
        self,
        default_ttl: float = 300.0,
        negative_ttl: float = 30.0,
        clock: float = 0.0,
    ) -> None:
        self._default_ttl = default_ttl
        self._negative_ttl = negative_ttl
        self._clock = clock
        self._records: dict[AgentId, _Record] = {}
        self._negative: dict[str, float] = {}
        self._subscribers: list[asyncio.Queue[AgentCard]] = []

    def set_clock(self, now: float) -> None:
        """Pin the clock for deterministic TTL expiry (the simulator advances it).

        Example::

            reg.set_clock(100.0)
        """
        self._clock = now

    def _now(self) -> float:
        # The clock is an explicit virtual time (default 0.0), advanced only via
        # set_clock. There is no wall-clock fallback, so TTL expiry is fully
        # deterministic under a fixed seed: records simply never expire until the
        # clock is advanced. This keeps the plugin Tier-1 safe under any scenario
        # that selects `registry: resolver` from YAML.
        return self._clock

    def _ttl_for(self, card: AgentCard) -> float:
        raw = card.metadata.get("ttl")
        if isinstance(raw, (int, float)) and raw > 0:
            return float(raw)
        return self._default_ttl

    def _prune(self) -> None:
        now = self._now()
        expired = [aid for aid, rec in self._records.items() if rec.expires_at <= now]
        for aid in expired:
            del self._records[aid]

    async def register(self, card: AgentCard) -> None:
        """Register (or heartbeat) a card; its freshness is `card.metadata["ttl"]`.

        Example::

            await reg.register(card)
        """
        self._records[card.agent_id] = _Record(card, self._now() + self._ttl_for(card))
        # A new record may satisfy a previously-empty query, so drop the negative cache.
        self._negative.clear()
        for q in self._subscribers:
            await q.put(card)

    async def lookup(self, query: Query) -> list[AgentCard]:
        """Return live matching cards; empty answers are negatively cached.

        Example::

            results = await reg.lookup(Query(capabilities=["sell"]))
        """
        now = self._now()
        self._prune()

        key = self._query_key(query)
        cached_until = self._negative.get(key)
        if cached_until is not None and cached_until > now:
            return []

        results = [rec.card for rec in self._records.values() if self._matches(rec.card, query)]
        if not results:
            self._negative[key] = now + self._negative_ttl
        return results

    async def subscribe(self, query: Query) -> AsyncIterator[AgentCard]:
        """Yield newly registered cards that match the query.

        Example::

            async for card in reg.subscribe(query):
                print(card.name)
        """
        q: asyncio.Queue[AgentCard] = asyncio.Queue()
        self._subscribers.append(q)
        try:
            while True:
                card = await q.get()
                if self._matches(card, query):
                    yield card
        finally:
            self._subscribers.remove(q)

    async def deregister(self, agent: AgentId) -> None:
        """Remove an agent immediately, ahead of its TTL.

        Example::

            await reg.deregister(AgentId("a1"))
        """
        self._records.pop(agent, None)

    def live_agents(self) -> set[AgentId]:
        """Ids currently resolvable (after pruning expired records).

        Example::

            live = reg.live_agents()
        """
        self._prune()
        return set(self._records.keys())

    @staticmethod
    def _query_key(query: Query) -> str:
        return json.dumps(
            {
                "caps": sorted(query.capabilities),
                "name": query.name_pattern,
                "meta": sorted((k, str(v)) for k, v in query.metadata_filter.items()),
            },
            sort_keys=True,
        )

    @staticmethod
    def _matches(card: AgentCard, query: Query) -> bool:
        if query.capabilities and not all(cap in card.capabilities for cap in query.capabilities):
            return False
        if query.name_pattern and query.name_pattern not in card.name:
            return False
        return all(card.metadata.get(k) == v for k, v in query.metadata_filter.items())
