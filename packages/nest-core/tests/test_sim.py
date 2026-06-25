# SPDX-License-Identifier: Apache-2.0
"""Tests for the Tier 1 discrete-event simulator.

Covers: clock, event queue, agent lifecycle, determinism, and performance.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest
from nest_core.sim import (
    EventQueue,
    Simulator,
    StateMachineAgent,
    VirtualClock,
)
from nest_core.sim.agent import AgentContext
from nest_core.sim.events import Event
from nest_core.types import AgentId

# ---------------------------------------------------------------------------
# Clock tests
# ---------------------------------------------------------------------------


class TestVirtualClock:
    def test_starts_at_zero(self) -> None:
        clock = VirtualClock()
        assert clock.now == 0.0

    def test_advance_to(self) -> None:
        clock = VirtualClock()
        clock.advance_to(10.0)
        assert clock.now == 10.0

    def test_cannot_go_backwards(self) -> None:
        clock = VirtualClock(start=5.0)
        with pytest.raises(ValueError, match="Cannot move clock backwards"):
            clock.advance_to(3.0)


# ---------------------------------------------------------------------------
# Event queue tests
# ---------------------------------------------------------------------------


class TestEventQueue:
    def test_fifo_at_same_time(self) -> None:
        q = EventQueue()
        q.push(Event(time=1.0, kind="first", agent_id=AgentId("a1")))
        q.push(Event(time=1.0, kind="second", agent_id=AgentId("a2")))
        assert q.pop().kind == "first"
        assert q.pop().kind == "second"

    def test_time_ordering(self) -> None:
        q = EventQueue()
        q.push(Event(time=3.0, kind="late", agent_id=AgentId("a1")))
        q.push(Event(time=1.0, kind="early", agent_id=AgentId("a2")))
        assert q.pop().kind == "early"
        assert q.pop().kind == "late"

    def test_len_and_bool(self) -> None:
        q = EventQueue()
        assert len(q) == 0
        assert not q
        q.push(Event(time=0.0, kind="x", agent_id=AgentId("a1")))
        assert len(q) == 1
        assert q


# ---------------------------------------------------------------------------
# Ping-Pong agents for integration tests
# ---------------------------------------------------------------------------


class PingAgent(StateMachineAgent):
    """Sends ping to all agents on start, responds pong to ping."""

    def __init__(self, target: AgentId) -> None:
        self.target = target
        self.received_count = 0

    async def on_start(self, ctx: AgentContext) -> None:
        await ctx.send(self.target, b"ping")

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        self.received_count += 1
        if payload == b"ping":
            await ctx.send(sender, b"pong")


class PongAgent(StateMachineAgent):
    """Responds pong to ping, counts messages."""

    def __init__(self) -> None:
        self.received_count = 0

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        self.received_count += 1
        if payload == b"ping":
            await ctx.send(sender, b"pong")


# ---------------------------------------------------------------------------
# Simulator integration tests
# ---------------------------------------------------------------------------


class TestSimulator:
    @pytest.mark.asyncio
    async def test_basic_ping_pong(self) -> None:
        sim = Simulator(seed=42)
        pinger = PingAgent(target=AgentId("pong"))
        ponger = PongAgent()
        sim.add_agent(AgentId("ping"), pinger)
        sim.add_agent(AgentId("pong"), ponger)

        await sim.run(max_ticks=100)

        assert ponger.received_count >= 1
        assert pinger.received_count >= 1
        assert sim.message_count >= 2

    @pytest.mark.asyncio
    async def test_trace_output(self, tmp_path: Path) -> None:
        trace_file = tmp_path / "trace.jsonl"
        sim = Simulator(seed=42, trace_path=trace_file)
        sim.add_agent(AgentId("a1"), PingAgent(target=AgentId("a2")))
        sim.add_agent(AgentId("a2"), PongAgent())

        await sim.run(max_ticks=100)

        content = trace_file.read_text()
        lines = [line for line in content.strip().split("\n") if line]
        assert len(lines) > 0

        import json

        header = json.loads(lines[0])
        assert header["kind"] == "trace_header"
        assert header["schema_version"] == "1.0"

        for line in lines[1:]:
            event = json.loads(line)
            assert "ts" in event
            assert "agent" in event
            assert "kind" in event

    @pytest.mark.asyncio
    async def test_deterministic_traces(self, tmp_path: Path) -> None:
        """Two runs with the same seed produce byte-identical traces."""
        traces: list[str] = []
        for i in range(2):
            trace_file = tmp_path / f"trace_{i}.jsonl"
            sim = Simulator(seed=12345, trace_path=trace_file)
            sim.add_agent(AgentId("a1"), PingAgent(target=AgentId("a2")))
            sim.add_agent(AgentId("a2"), PongAgent())
            await sim.run(max_ticks=100)
            traces.append(trace_file.read_text())

        assert traces[0] == traces[1]
        assert len(traces[0]) > 0

    @pytest.mark.asyncio
    async def test_100_agents_performance(self, tmp_path: Path) -> None:
        """100 ping-pong agents converge in <2s."""
        trace_file = tmp_path / "perf_trace.jsonl"
        sim = Simulator(seed=99, trace_path=trace_file)

        agent_ids = [AgentId(f"a{i}") for i in range(100)]
        agents: list[PingAgent] = []
        for i, aid in enumerate(agent_ids):
            target = agent_ids[(i + 1) % 100]
            agent = PingAgent(target=target)
            agents.append(agent)
            sim.add_agent(aid, agent)

        start = time.monotonic()
        await sim.run(max_ticks=10000)
        elapsed = time.monotonic() - start

        assert elapsed < 2.0, f"100 agents took {elapsed:.2f}s (limit: 2s)"
        assert sim.message_count > 0

    @pytest.mark.asyncio
    async def test_100_agents_deterministic(self, tmp_path: Path) -> None:
        """100-agent runs with the same seed produce byte-identical traces."""
        traces: list[str] = []
        for run in range(2):
            trace_file = tmp_path / f"det_{run}.jsonl"
            sim = Simulator(seed=777, trace_path=trace_file)

            agent_ids = [AgentId(f"a{i}") for i in range(100)]
            for i, aid in enumerate(agent_ids):
                target = agent_ids[(i + 1) % 100]
                sim.add_agent(aid, PingAgent(target=target))

            await sim.run(max_ticks=10000)
            traces.append(trace_file.read_text())

        assert traces[0] == traces[1]
        assert len(traces[0]) > 0

    @pytest.mark.asyncio
    async def test_max_time_limit(self) -> None:
        """Simulation stops when max_time is reached."""
        sim = Simulator(seed=1)

        class DelayAgent(StateMachineAgent):
            async def on_start(self, ctx: AgentContext) -> None:
                await ctx.schedule(10.0, b"tick")

            async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
                await ctx.schedule(10.0, b"tick")

        sim.add_agent(AgentId("a1"), DelayAgent())
        await sim.run(max_ticks=100000, max_time=50.0)

        assert sim.clock.now <= 50.0

    @pytest.mark.asyncio
    async def test_self_scheduling(self) -> None:
        """Agents can schedule messages to themselves."""
        sim = Simulator(seed=1)
        received: list[float] = []

        class TimerAgent(StateMachineAgent):
            async def on_start(self, ctx: AgentContext) -> None:
                await ctx.schedule(5.0, b"alarm")

            async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
                received.append(ctx.time)

        sim.add_agent(AgentId("timer"), TimerAgent())
        await sim.run(max_ticks=100)

        assert len(received) == 1
        assert received[0] == 5.0
