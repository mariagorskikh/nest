# SPDX-License-Identifier: Apache-2.0
"""In-memory transport wired to the simulator's event queue.

Example::

    transport = InMemoryTransport(agent_id, event_queue, clock)
    await transport.send(AgentId("a2"), b"hello")
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from nest_core.types import AgentId, CorrelationId, TransportCapabilities

if TYPE_CHECKING:
    from nest_core.sim.clock import VirtualClock
    from nest_core.sim.events import EventQueue


class InMemoryTransport:
    """Transport that routes messages through the simulator's event queue.

    Example::

        transport = InMemoryTransport(AgentId("a1"), queue, clock)
        await transport.send(AgentId("a2"), b"data")
    """

    capabilities = TransportCapabilities(
        supports_streaming=False,
        ordered=True,
        reliable=True,
    )

    def __init__(
        self,
        agent_id: AgentId,
        event_queue: EventQueue,
        clock: VirtualClock,
        all_agents: list[AgentId] | None = None,
    ) -> None:
        self._agent_id = agent_id
        self._queue = event_queue
        self._clock = clock
        self.all_agents = all_agents or []

    async def send(
        self,
        to: AgentId,
        payload: bytes,
        correlation_id: CorrelationId | None = None,
    ) -> None:
        """Enqueue a message delivery event.

        Example::

            await transport.send(AgentId("a2"), b"hello")
        """
        from nest_core.sim.events import Event

        self._queue.push(
            Event(
                time=self._clock.now,
                kind="deliver",
                agent_id=to,
                target_id=self._agent_id,
                payload=payload,
                correlation_id=correlation_id,
            )
        )

    async def receive(self) -> tuple[AgentId, bytes]:
        """Not used in Tier 1 — the simulator pushes events to agents.

        Example::

            # Not applicable in simulation mode
        """
        raise NotImplementedError("Tier 1 transport is push-based via the event queue")

    async def broadcast(
        self,
        payload: bytes,
        correlation_id: CorrelationId | None = None,
    ) -> None:
        """Broadcast to all known agents.

        Example::

            await transport.broadcast(b"announcement")
        """
        for aid in self.all_agents:
            if aid != self._agent_id:
                await self.send(aid, payload, correlation_id=correlation_id)
