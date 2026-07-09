# SPDX-License-Identifier: Apache-2.0
"""Registry layer interface: how agents find each other.
Example::
    class MyRegistry(Registry):
        async def register(self, card):
            self._store[card.agent_id] = card
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import Protocol, runtime_checkable

from nest_core.types import AgentCard, AgentId, Query


@runtime_checkable
class Registry(Protocol):
    """Agent registry for discovery and lookup.
    Example::
        registry: Registry = InMemoryRegistry()
        await registry.register(my_card)
    """

    async def register(self, card: AgentCard) -> None:
        """Register an agent card in the registry.
        Example::
            await registry.register(card)
        """
        ...

    async def lookup(self, query: Query) -> list[AgentCard]:
        """Look up agents matching a query.
        Example::
            results = await registry.lookup(Query(capabilities=["sell_data"]))
        """
        ...

    def subscribe(self, query: Query) -> AsyncGenerator[AgentCard, None]:
        """Subscribe to new agents matching a query.
        Example::
            async for card in registry.subscribe(query):
                print(card.name)
        """
        ...

    async def deregister(self, agent: AgentId) -> None:
        """Remove an agent from the registry.
        Example::
            await registry.deregister(AgentId("a1"))
        """
        ...
