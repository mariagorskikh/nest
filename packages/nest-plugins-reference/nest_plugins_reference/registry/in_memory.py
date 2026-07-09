# SPDX-License-Identifier: Apache-2.0
"""In-memory registry plugin — local dictionary-based agent discovery.

Example::

    registry = InMemoryRegistry()
    await registry.register(card)
    results = await registry.lookup(Query(capabilities=["sell"]))
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncGenerator

from nest_core.types import AgentCard, AgentId, Query


class InMemoryRegistry:
    """Dictionary-backed agent registry with capability indexing.

    Example::

        reg = InMemoryRegistry()
        await reg.register(AgentCard(agent_id=AgentId("a1"), name="Agent1"))
    """

    def __init__(self) -> None:
        self._cards: dict[AgentId, AgentCard] = {}
        self._by_cap: dict[str, set[AgentId]] = {}
        self._subscribers: list[asyncio.Queue[AgentCard]] = []

    def _index_add(self, card: AgentCard) -> None:
        for cap in card.capabilities:
            self._by_cap.setdefault(cap, set()).add(card.agent_id)

    def _index_remove(self, card: AgentCard) -> None:
        for cap in card.capabilities:
            bucket = self._by_cap.get(cap)
            if bucket is not None:
                bucket.discard(card.agent_id)
                if not bucket:
                    del self._by_cap[cap]

    async def register(self, card: AgentCard) -> None:
        """Register an agent card.

        Example::

            await reg.register(card)
        """
        existing = self._cards.get(card.agent_id)
        if existing is not None:
            self._index_remove(existing)
        self._cards[card.agent_id] = card
        self._index_add(card)
        for q in self._subscribers:
            with contextlib.suppress(asyncio.QueueFull):
                q.put_nowait(card)

    async def lookup(self, query: Query) -> list[AgentCard]:
        """Look up agents matching a query.

        Example::

            results = await reg.lookup(Query(capabilities=["sell"]))
        """
        if query.capabilities:
            cap_sets = [self._by_cap.get(cap, set()) for cap in query.capabilities]
            candidate_ids: set[AgentId] = cap_sets[0].copy()
            for cap_set in cap_sets[1:]:
                candidate_ids &= cap_set
            results = [self._cards[aid] for aid in candidate_ids if aid in self._cards]
        else:
            results = list(self._cards.values())

        if query.name_pattern:
            results = [c for c in results if query.name_pattern in c.name]
        return results

    async def subscribe(self, query: Query) -> AsyncGenerator[AgentCard, None]:
        """Subscribe to new agent registrations matching a query.

        Example::

            async for card in reg.subscribe(query):
                print(card.name)
        """
        q: asyncio.Queue[AgentCard] = asyncio.Queue(maxsize=1000)
        self._subscribers.append(q)
        try:
            while True:
                card = await q.get()
                if self._matches(card, query):
                    yield card
        finally:
            self._subscribers.remove(q)

    async def deregister(self, agent: AgentId) -> None:
        """Remove an agent from the registry.

        Example::

            await reg.deregister(AgentId("a1"))
        """
        card = self._cards.pop(agent, None)
        if card is not None:
            self._index_remove(card)

    @staticmethod
    def _matches(card: AgentCard, query: Query) -> bool:
        if query.capabilities and not all(cap in card.capabilities for cap in query.capabilities):
            return False
        return not (query.name_pattern and query.name_pattern not in card.name)
