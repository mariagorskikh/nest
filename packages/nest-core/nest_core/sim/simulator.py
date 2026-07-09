# SPDX-License-Identifier: Apache-2.0
"""Tier 1 discrete-event simulator.
Drives state-machine agents through an event loop with a virtual clock.
Deterministic: same seed → identical trace.
Example::
    sim = Simulator(seed=42)
    sim.add_agent(AgentId("a1"), PingAgent())
    sim.add_agent(AgentId("a2"), PongAgent())
    await sim.run(max_ticks=1000)
"""

from __future__ import annotations
import asyncio
import random
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from nest_core.log import LazyLogger
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.sim.clock import VirtualClock
from nest_core.sim.events import Event, EventQueue
from nest_core.sim.middleware import MessageContext, MiddlewareChain
from nest_core.sim.trace import TraceWriter
from nest_core.sim.transport import InMemoryTransport
from nest_core.types import AgentId, CorrelationId

log = LazyLogger(__name__)


@dataclass
class _AgentSlot:
    agent: StateMachineAgent
    transport: InMemoryTransport
    rng: random.Random
    state: dict[str, Any] = field(default_factory=lambda: dict[str, Any]())


class _CorrelationCounter:
    __slots__ = ("_count",)

    def __init__(self) -> None:
        self._count = 0

    def next(self) -> CorrelationId:
        self._count += 1
        return CorrelationId(f"corr-{self._count}")


class _SimAgentContext:
    """Concrete AgentContext implementation backed by the simulator."""

    def __init__(
        self,
        agent_id: AgentId,
        clock: VirtualClock,
        transport: InMemoryTransport,
        event_queue: EventQueue,
        rng: random.Random,
        trace: TraceWriter | None,
        corr_counter: _CorrelationCounter,
        plugins: dict[str, Any] | None = None,
        middleware_chain: MiddlewareChain | None = None,
    ) -> None:
        self._agent_id = agent_id
        self._clock = clock
        self._transport = transport
        self._queue = event_queue
        self._rng = rng
        self._trace = trace
        self._corr = corr_counter
        self._plugins: dict[str, Any] = plugins or {}
        self._middleware_chain = middleware_chain

    async def _apply_outbound(
        self,
        recipient: AgentId,
        payload: bytes,
        correlation_id: CorrelationId,
    ) -> tuple[bytes, float | None] | None:
        if self._middleware_chain is None:
            return payload, None
        mc = MessageContext(
            sender=self._agent_id,
            recipient=recipient,
            payload=payload,
            correlation_id=correlation_id,
            now=self._clock.now,
            rng=self._rng,
            direction="send",
            plugins=self._plugins,
        )
        result = await self._middleware_chain.on_send(mc)
        if result is None:
            return None
        deliver_at = result.metadata.get("deliver_at")
        deliver_at_f = float(deliver_at) if deliver_at is not None else None
        return result.payload, deliver_at_f

    @property
    def agent_id(self) -> AgentId:
        return self._agent_id

    @property
    def time(self) -> float:
        return self._clock.now

    @property
    def rng(self) -> random.Random:
        return self._rng

    @property
    def plugins(self) -> dict[str, Any]:
        return self._plugins

    async def send(self, to: AgentId, payload: bytes) -> None:
        cid = self._corr.next()
        outbound = await self._apply_outbound(to, payload, cid)
        if outbound is None:
            return
        payload, deliver_at = outbound
        if self._trace:
            self._trace.record(
                {
                    "ts": self._clock.now,
                    "agent": str(self._agent_id),
                    "kind": "send",
                    "to": str(to),
                    "size": len(payload),
                    "msg": payload.decode("utf-8", errors="replace"),
                    "corr": str(cid),
                }
            )
        await self._transport.send(
            to,
            payload,
            correlation_id=cid,
            deliver_at=deliver_at,
        )

    async def broadcast(self, payload: bytes) -> None:
        cid = self._corr.next()
        outbound = await self._apply_outbound(AgentId("*"), payload, cid)
        if outbound is None:
            return
        payload, deliver_at = outbound
        if self._trace:
            self._trace.record(
                {
                    "ts": self._clock.now,
                    "agent": str(self._agent_id),
                    "kind": "broadcast",
                    "size": len(payload),
                    "msg": payload.decode("utf-8", errors="replace"),
                    "corr": str(cid),
                }
            )
        await self._transport.broadcast(
            payload,
            correlation_id=cid,
            deliver_at=deliver_at,
        )

    async def schedule(self, delay: float, payload: bytes) -> None:
        self._queue.push(
            Event(
                time=self._clock.now + delay,
                kind="deliver",
                agent_id=self._agent_id,
                target_id=self._agent_id,
                payload=payload,
            )
        )


# Verify _SimAgentContext satisfies the protocol at import time
_ctx_check: type[AgentContext] = _SimAgentContext  # noqa: F841


class Simulator:
    """Tier 1 discrete-event simulator.
    Example::
        sim = Simulator(seed=42, trace_path="trace.jsonl")
        sim.add_agent(AgentId("a1"), PingAgent())
        await sim.run(max_ticks=1000)
    """

    def __init__(
        self,
        seed: int = 0,
        trace_path: str | Path | None = None,
        message_drop_rate: float = 0.0,
        byzantine_fraction: float = 0.0,
        partition_groups: list[list[str]] | None = None,
        partition_heal_at: int | None = None,
        plugins: dict[str, Any] | None = None,
        parallel: bool = False,
        middleware: list[Any] | None = None,
    ) -> None:
        if not 0.0 <= message_drop_rate <= 1.0:
            msg = f"message_drop_rate must be between 0 and 1: {message_drop_rate}"
            raise ValueError(msg)
        if not 0.0 <= byzantine_fraction <= 1.0:
            msg = f"byzantine_fraction must be between 0 and 1: {byzantine_fraction}"
            raise ValueError(msg)
        self._seed = seed
        self._master_rng = random.Random(seed)
        self._clock = VirtualClock()
        self._queue = EventQueue()
        self._agents: dict[AgentId, _AgentSlot] = {}
        self._trace: TraceWriter | None = None
        if trace_path is not None:
            self._trace = TraceWriter(trace_path)
        self._tick_count = 0
        self._message_count = 0
        self._dropped_count = 0
        self._corr_counter = _CorrelationCounter()
        self._message_drop_rate = message_drop_rate
        self._byzantine_fraction = byzantine_fraction
        self._partition_groups = partition_groups
        self._partition_heal_at = partition_heal_at
        self._partition_healed = False
        self._byzantine_agents: set[AgentId] = set()
        self._partition_map: dict[AgentId, int] = {}
        self._failure_rng = random.Random(self._master_rng.randint(0, 2**63))
        self._plugins: dict[str, Any] = plugins or {}
        self._agent_plugins: dict[AgentId, dict[str, Any]] = {}
        self._parallel = parallel
        self._transport_factory: Any | None = None
        self._middleware_chain: MiddlewareChain | None = None
        if middleware:
            self._middleware_chain = MiddlewareChain(middleware, trace=self._trace)

    @property
    def clock(self) -> VirtualClock:
        """The simulator's virtual clock.
        Example::
            t = sim.clock.now
        """
        return self._clock

    @property
    def event_queue(self) -> EventQueue:
        """The simulator's event queue (for distributed worker bridges).
        Example::
            q = sim.event_queue
        """
        return self._queue

    @property
    def tick_count(self) -> int:
        """Number of events processed so far.
        Example::
            print(sim.tick_count)
        """
        return self._tick_count

    @property
    def message_count(self) -> int:
        """Number of messages delivered so far.
        Example::
            print(sim.message_count)
        """
        return self._message_count

    @property
    def dropped_count(self) -> int:
        """Number of messages dropped by failure injection.
        Example::
            print(sim.dropped_count)
        """
        return self._dropped_count

    def set_transport_factory(self, factory: Any) -> None:
        """Override how per-agent transports are constructed (distributed workers).
        Example::
            sim.set_transport_factory(lambda aid, q, c, ids: RoutedTransport(...))
        """
        self._transport_factory = factory

    def add_agent(self, agent_id: AgentId, agent: StateMachineAgent) -> None:
        """Register an agent for the simulation.
        Example::
            sim.add_agent(AgentId("a1"), MyAgent())
        """
        if agent_id in self._agents:
            msg = f"Agent already registered: {agent_id}"
            raise ValueError(msg)
        agent_rng = random.Random(self._master_rng.randint(0, 2**63))
        all_ids = [aid for aid in self._agents]
        all_ids.append(agent_id)
        if self._transport_factory is not None:
            transport = self._transport_factory(agent_id, self._queue, self._clock, all_ids)
        else:
            transport = InMemoryTransport(agent_id, self._queue, self._clock, all_ids)
        self._agents[agent_id] = _AgentSlot(
            agent=agent,
            transport=transport,
            rng=agent_rng,
        )

    def _init_failures(self) -> None:
        all_ids = list(self._agents.keys())
        if self._byzantine_fraction > 0:
            n_byzantine = max(1, int(len(all_ids) * self._byzantine_fraction))
            shuffled = list(all_ids)
            self._failure_rng.shuffle(shuffled)
            self._byzantine_agents = set(shuffled[:n_byzantine])
        if self._partition_groups:
            for group_idx, group in enumerate(self._partition_groups):
                for agent_name in group:
                    aid = AgentId(agent_name)
                    if aid in self._agents:
                        self._partition_map[aid] = group_idx

    def _should_drop(self, sender: AgentId, target: AgentId) -> bool:
        if self._message_drop_rate > 0 and self._failure_rng.random() < self._message_drop_rate:
            return True
        if self._partition_map:
            s_group = self._partition_map.get(sender, -1)
            t_group = self._partition_map.get(target, -2)
            if s_group >= 0 and t_group >= 0 and s_group != t_group:
                return True
        return False

    async def run(self, max_ticks: int = 100_000, max_time: float | None = None) -> None:
        """Run the simulation until events are exhausted or limits are reached.
        Example::
            await sim.run(max_ticks=5000)
        """
        all_ids = list(self._agents.keys())
        for slot in self._agents.values():
            slot.transport.all_agents = all_ids
        self._init_failures()
        log.debug(
            "simulation_start",
            seed=self._seed,
            agent_count=len(self._agents),
            parallel=self._parallel,
        )
        for aid in self._agents:
            if self._trace:
                self._trace.record(
                    {
                        "ts": self._clock.now,
                        "agent": str(aid),
                        "kind": "start",
                    }
                )
            self._queue.push(
                Event(
                    time=self._clock.now,
                    kind="start",
                    agent_id=aid,
                )
            )
        start_pairs = [(aid, slot) for aid, slot in self._agents.items()]
        if self._parallel:
            await asyncio.gather(
                *(slot.agent.on_start(self._make_context(aid, slot)) for aid, slot in start_pairs)
            )
        else:
            for aid, slot in start_pairs:
                await slot.agent.on_start(self._make_context(aid, slot))
        while self._queue and self._tick_count < max_ticks:
            if self._parallel:
                batch_time = self._queue.peek().time
                batch: list[Event] = []
                while self._queue and self._queue.peek().time == batch_time:
                    batch.append(self._queue.pop())
                if max_time is not None and batch_time > max_time:
                    break
                self._clock.advance_to(batch_time)
                self._tick_count += len(batch)
                self._maybe_heal_partition()

                async def _handle(ev: Event) -> None:
                    await self._dispatch_event(ev)

                await asyncio.gather(*(_handle(ev) for ev in batch))
            else:
                event = self._queue.pop()
                if max_time is not None and event.time > max_time:
                    break
                self._clock.advance_to(event.time)
                self._tick_count += 1
                self._maybe_heal_partition()
                await self._dispatch_event(event)
        stop_pairs = [(aid, slot) for aid, slot in self._agents.items()]
        for aid, _slot in stop_pairs:
            if self._trace:
                self._trace.record(
                    {
                        "ts": self._clock.now,
                        "agent": str(aid),
                        "kind": "stop",
                    }
                )
        if self._parallel:
            await asyncio.gather(
                *(slot.agent.on_stop(self._make_context(aid, slot)) for aid, slot in stop_pairs)
            )
        else:
            for aid, slot in stop_pairs:
                await slot.agent.on_stop(self._make_context(aid, slot))
        if self._trace:
            self._trace.close()

    def _maybe_heal_partition(self) -> None:
        """Clear any active network partition once the heal tick is reached."""
        if (
            self._partition_heal_at is not None
            and not self._partition_healed
            and self._tick_count >= self._partition_heal_at
        ):
            self._partition_map = {}
            self._partition_healed = True
            if self._trace:
                self._trace.record(
                    {
                        "ts": self._clock.now,
                        "agent": "_simulator",
                        "kind": "partition_healed",
                    }
                )

    async def _dispatch_event(self, event: Event) -> None:
        """Process a single simulation event."""
        if event.kind == "start":
            return
        if event.kind != "deliver":
            return
        target_slot = self._agents.get(event.agent_id)
        if target_slot is None:
            return
        if self._should_drop(event.target_id, event.agent_id):
            self._dropped_count += 1
            if self._trace:
                drop_rec: dict[str, Any] = {
                    "ts": self._clock.now,
                    "agent": str(event.agent_id),
                    "kind": "dropped",
                    "from": str(event.target_id),
                    "size": len(event.payload),
                    "msg": event.payload.decode("utf-8", errors="replace"),
                }
                if event.correlation_id is not None:
                    drop_rec["corr"] = str(event.correlation_id)
                self._trace.record(drop_rec)
            return
        delivered_payload = event.payload
        if event.target_id in self._byzantine_agents and event.payload:
            noise = self._failure_rng.randbytes(len(event.payload))
            delivered_payload = bytes(a ^ b for a, b in zip(event.payload, noise, strict=True))
        agent_overrides = self._agent_plugins.get(event.agent_id)
        merged_plugins = {**self._plugins, **agent_overrides} if agent_overrides else self._plugins
        inbound_ctx = MessageContext(
            sender=event.target_id,
            recipient=event.agent_id,
            payload=delivered_payload,
            correlation_id=event.correlation_id,
            now=self._clock.now,
            rng=target_slot.rng,
            direction="receive",
            plugins=merged_plugins,
        )
        if self._middleware_chain is not None:
            inbound_result = await self._middleware_chain.on_receive(inbound_ctx)
            if inbound_result is None:
                deny_reason = inbound_ctx.metadata.get("deny_reason")
                if deny_reason and self._trace:
                    denied_rec: dict[str, Any] = {
                        "ts": self._clock.now,
                        "agent": str(event.agent_id),
                        "kind": "denied",
                        "from": str(event.target_id),
                        "reason": str(deny_reason),
                    }
                    if event.correlation_id is not None:
                        denied_rec["corr"] = str(event.correlation_id)
                    self._trace.record(denied_rec)
                return
            delivered_payload = inbound_result.payload
        self._message_count += 1
        log.debug(
            "dispatch_deliver",
            agent=str(event.agent_id),
            from_agent=str(event.target_id),
            correlation_id=str(event.correlation_id) if event.correlation_id else None,
        )
        if self._trace:
            rec: dict[str, Any] = {
                "ts": self._clock.now,
                "agent": str(event.agent_id),
                "kind": "receive",
                "from": str(event.target_id),
                "size": len(delivered_payload),
                "msg": delivered_payload.decode("utf-8", errors="replace"),
            }
            if event.correlation_id is not None:
                rec["corr"] = str(event.correlation_id)
            self._trace.record(rec)
        ctx = self._make_context(event.agent_id, target_slot)

        async def _deliver() -> None:
            await target_slot.agent.on_message(ctx, event.target_id, delivered_payload)

        chain = self._middleware_chain
        if chain is not None and chain.has_delivery_error_handlers():
            await chain.run_delivery(inbound_ctx, _deliver)
        else:
            await _deliver()

    def set_agent_plugins(self, agent_id: AgentId, overrides: dict[str, Any]) -> None:
        """Set per-agent plugin overrides (merged on top of shared plugins).
        Example::
            sim.set_agent_plugins(AgentId("a1"), {"identity": my_identity})
        """
        self._agent_plugins[agent_id] = overrides

    def _make_context(self, agent_id: AgentId, slot: _AgentSlot) -> _SimAgentContext:
        agent_overrides = self._agent_plugins.get(agent_id)
        merged = {**self._plugins, **agent_overrides} if agent_overrides else self._plugins
        return _SimAgentContext(
            agent_id=agent_id,
            clock=self._clock,
            transport=slot.transport,
            event_queue=self._queue,
            rng=slot.rng,
            trace=self._trace,
            corr_counter=self._corr_counter,
            plugins=merged,
            middleware_chain=self._middleware_chain,
        )
