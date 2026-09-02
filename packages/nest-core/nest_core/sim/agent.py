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

from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Protocol, cast, runtime_checkable

from nest_core.types import AgentId, CorrelationId

if TYPE_CHECKING:
    import random as _random


def _copied_mapping(value: object, *, field_name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{field_name} must be a mapping")
    mapping = cast("Mapping[object, object]", value)
    copied: dict[str, object] = {}
    for key, item in mapping.items():
        if not isinstance(key, str):
            raise TypeError(f"{field_name} keys must be strings")
        copied[key] = deepcopy(item)
    return MappingProxyType(copied)


@dataclass(frozen=True, slots=True)
class ScenarioEventRequest:
    """Immutable generic event handed from the simulator context to a sink."""

    kind: str
    logical_time: float
    observer: str
    subject: str
    data: Mapping[str, object]
    attributes: Mapping[str, object] = field(default_factory=lambda: dict[str, object]())

    def __post_init__(self) -> None:
        object.__setattr__(self, "data", _copied_mapping(self.data, field_name="data"))
        object.__setattr__(
            self,
            "attributes",
            _copied_mapping(self.attributes, field_name="attributes"),
        )


@dataclass(frozen=True, slots=True)
class ScenarioEventReceipt:
    """Opaque event identifier plus the generic record the simulator may trace."""

    event_id: str
    trace_record: Mapping[str, object]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "trace_record",
            _copied_mapping(self.trace_record, field_name="trace_record"),
        )


@runtime_checkable
class ScenarioEventSink(Protocol):
    """Optional sink for scenario-owned structured events."""

    def record(self, request: ScenarioEventRequest) -> ScenarioEventReceipt:
        """Record one generic request and return its traceable receipt."""
        ...


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


@runtime_checkable
class ScenarioAgentContext(AgentContext, Protocol):
    """Optional generic extensions used by instrumented simulator scenarios."""

    @property
    def event_sink(self) -> ScenarioEventSink | None:
        """Optional run-scoped scenario event sink."""
        ...

    async def send_with_correlation(self, to: AgentId, payload: bytes) -> CorrelationId:
        """Send a message and return its simulator correlation identifier."""
        ...

    def record_scenario_event(
        self,
        *,
        kind: str,
        observer: str,
        subject: str,
        data: Mapping[str, object],
        attributes: Mapping[str, object] | None = None,
    ) -> ScenarioEventReceipt | None:
        """Record one event when a generic sink is injected."""
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
