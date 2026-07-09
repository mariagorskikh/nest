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

import random
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.sim.clock import VirtualClock
from nest_core.sim.events import Event, EventQueue
from nest_core.sim.trace import TraceWriter
from nest_core.sim.transport import InMemoryTransport
from nest_core.types import AgentId, CorrelationId


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
    ) -> None:
        self._agent_id = agent_id
        self._clock = clock
        self._transport = transport
        self._queue = event_queue
        self._rng = rng
        self._trace = trace
        self._corr = corr_counter
        self._plugins: dict[str, Any] = plugins or {}

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
        await self._transport.send(to, payload, correlation_id=cid)

    async def broadcast(self, payload: bytes) -> None:
        cid = self._corr.next()
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
        await self._transport.broadcast(payload, correlation_id=cid)

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

    @property
    def clock(self) -> VirtualClock:
        """The simulator's virtual clock.

        Example::

            t = sim.clock.now
        """
        return self._clock

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

    def add_agent(self, agent_id: AgentId, agent: StateMachineAgent) -> None:
        """Register an agent for the simulation.

        Example::

            sim.add_agent(AgentId("a1"), MyAgent())
        """
        agent_rng = random.Random(self._master_rng.randint(0, 2**63))
        all_ids = [aid for aid in self._agents]
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

        for aid, slot in self._agents.items():
            ctx = self._make_context(aid, slot)
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

        for aid, slot in self._agents.items():
            ctx = self._make_context(aid, slot)
            await slot.agent.on_start(ctx)

        while self._queue and self._tick_count < max_ticks:
            event = self._queue.pop()

            if max_time is not None and event.time > max_time:
                break

            self._clock.advance_to(event.time)
            self._tick_count += 1

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

            if event.kind == "start":
                continue

            if event.kind == "deliver":
                target_slot = self._agents.get(event.agent_id)
                if target_slot is None:
                    continue

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
                    continue

                delivered_payload = event.payload
                if event.target_id in self._byzantine_agents:
                    delivered_payload = bytes(
                        (b ^ self._failure_rng.randint(0, 255)) for b in event.payload
                    )

                self._message_count += 1
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
                await target_slot.agent.on_message(ctx, event.target_id, delivered_payload)

        for aid, slot in self._agents.items():
            ctx = self._make_context(aid, slot)
            if self._trace:
                self._trace.record(
                    {
                        "ts": self._clock.now,
                        "agent": str(aid),
                        "kind": "stop",
                    }
                )
            await slot.agent.on_stop(ctx)

        if self._trace:
            self._trace.close()

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
        )
