# SPDX-License-Identifier: Apache-2.0
"""State-machine agent base class for Tier 1 simulation.

Example::

    class PingAgent(StateMachineAgent):
        async def on_start(self, ctx):
            await ctx.send(target, b"ping")

        async def on_message(self, ctx, sender, payload):
            if payload == b"ping":
                await ctx.send(sender, b"pong")
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from nest_core.types import AgentId

if TYPE_CHECKING:
    import random as _random


@runtime_checkable
class AgentContext(Protocol):
    """Context passed to agent callbacks, providing send/schedule capabilities.

    Example::

        await ctx.send(AgentId("a2"), b"hello")
    """

    @property
    def agent_id(self) -> AgentId:
        """This agent's ID.

        Example::

            my_id = ctx.agent_id
        """
        ...

    @property
    def time(self) -> float:
        """Current simulation time.

        Example::

            t = ctx.time
        """
        ...

    @property
    def rng(self) -> _random.Random:
        """Per-agent seeded random number generator.

        Example::

            val = ctx.rng.random()
        """
        ...

    @property
    def plugins(self) -> dict[str, Any]:
        """Resolved layer plugin instances available to this agent.

        Returns an empty dict when no plugins are configured, so agents
        can fall back to direct messaging.

        Example::

            registry = ctx.plugins.get("registry")
            if registry:
                sellers = await registry.lookup(Query(capabilities=["sell"]))
        """
        ...

    async def send(self, to: AgentId, payload: bytes) -> None:
        """Send a message to another agent.

        Example::

            await ctx.send(AgentId("a2"), b"hello")
        """
        ...

    async def broadcast(self, payload: bytes) -> None:
        """Broadcast a message to all agents.

        Example::

            await ctx.broadcast(b"announcement")
        """
        ...

    async def schedule(self, delay: float, payload: bytes) -> None:
        """Schedule a self-message after *delay* time units.

        Example::

            await ctx.schedule(5.0, b"timeout")
        """
        ...

    def record_event(self, fields: dict[str, Any]) -> None:
        """Record a custom audit event into the simulation trace.

        Example::

            ctx.record_event(
                {"kind": "payment_debited", "stream_ref": "s-1", "amount": 10},
            )
        """
        ...


class StateMachineAgent:
    """Base class for Tier 1 state-machine agents.

    Subclass and override ``on_start`` and ``on_message``.

    Example::

        class EchoAgent(StateMachineAgent):
            async def on_message(self, ctx, sender, payload):
                await ctx.send(sender, payload)
    """

    async def on_start(self, ctx: AgentContext) -> None:
        """Called once when the simulation starts.

        Example::

            async def on_start(self, ctx):
                await ctx.send(AgentId("a0"), b"hello")
        """

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Called when a message arrives.

        Example::

            async def on_message(self, ctx, sender, payload):
                await ctx.send(sender, b"ack")
        """

    async def on_stop(self, ctx: AgentContext) -> None:
        """Called when the simulation ends.

        Example::

            async def on_stop(self, ctx):
                pass
        """
