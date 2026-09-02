# SPDX-License-Identifier: Apache-2.0
"""Tests for the Tier 1 discrete-event simulator.

Covers: clock, event queue, agent lifecycle, determinism, and performance.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, cast

import nest_core.sim.agent as sim_agent
import pytest
from nest_core.sim import (
    EventQueue,
    Simulator,
    StateMachineAgent,
    VirtualClock,
)
from nest_core.sim.agent import AgentContext, ScenarioAgentContext
from nest_core.sim.events import Event
from nest_core.sim.trace import TraceWriter
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

        for line in lines:
            event = json.loads(line)
            assert "ts" in event
            assert "agent" in event
            assert "kind" in event

    @pytest.mark.asyncio
    async def test_generic_event_sink_returns_trace_record_for_context_to_write(
        self, tmp_path: Path
    ) -> None:
        """Passing TraceWriter or feature kwargs to the sink would break this boundary."""
        requests: list[Any] = []
        caller_data = {"values": ["before"]}
        caller_attributes = {"link": {"value": "before"}}
        trace_file = tmp_path / "scenario-event.jsonl"

        class RecordingSink:
            def record(self, request: Any) -> Any:
                requests.append(request)
                return sim_agent.ScenarioEventReceipt(
                    event_id="event-1",
                    trace_record={
                        "kind": request.kind,
                        "logical_time": request.logical_time,
                        "observer": request.observer,
                        "subject": request.subject,
                        "data": dict(request.data),
                        "attributes": dict(request.attributes),
                    },
                )

        class EventAgent(StateMachineAgent):
            async def on_start(self, ctx: AgentContext) -> None:
                scenario_ctx = cast("ScenarioAgentContext", ctx)
                receipt = scenario_ctx.record_scenario_event(
                    kind="scenario.fixture.observed",
                    observer="fixture-agent",
                    subject="fixture-subject",
                    data=caller_data,
                    attributes=caller_attributes,
                )
                assert receipt is not None
                assert receipt.event_id == "event-1"
                caller_data["values"].append("after")
                caller_attributes["link"]["value"] = "after"

        sim = Simulator(seed=7, trace_path=trace_file, event_sink=RecordingSink())
        sim.add_agent(AgentId("fixture-agent"), EventAgent())

        await sim.run(max_ticks=10)

        request_type = getattr(sim_agent, "ScenarioEventRequest", None)
        assert request_type is not None
        assert len(requests) == 1
        assert isinstance(requests[0], request_type)
        assert requests[0].data == {"values": ["before"]}
        assert requests[0].attributes == {"link": {"value": "before"}}
        records = [json.loads(line) for line in trace_file.read_text().splitlines()]
        assert [record for record in records if record["kind"] == "scenario.fixture.observed"] == [
            {
                "kind": "scenario.fixture.observed",
                "logical_time": 0.0,
                "observer": "fixture-agent",
                "subject": "fixture-subject",
                "data": {"values": ["before"]},
                "attributes": {"link": {"value": "before"}},
            }
        ]

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

    @pytest.mark.asyncio
    async def test_setup_failure_closes_trace_without_starting_agent_lifecycle(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Failure initialization is protected by trace cleanup but not agent stop hooks."""
        stopped: list[str] = []
        trace_close_calls = 0
        original_close = TraceWriter.close

        class StopWitness(StateMachineAgent):
            async def on_stop(self, ctx: AgentContext) -> None:
                stopped.append(str(ctx.agent_id))

        def fail_initialization() -> None:
            raise RuntimeError("setup failed")

        def record_trace_close(writer: TraceWriter) -> None:
            nonlocal trace_close_calls
            original_close(writer)
            trace_close_calls += 1

        trace = tmp_path / "setup-failure.jsonl"
        sim = Simulator(trace_path=trace)
        sim.add_agent(AgentId("witness"), StopWitness())
        monkeypatch.setattr(sim, "_init_failures", fail_initialization)
        monkeypatch.setattr(TraceWriter, "close", record_trace_close)

        with pytest.raises(RuntimeError, match="setup failed"):
            await sim.run()

        assert trace_close_calls == 1
        assert stopped == []
        assert trace.read_bytes() == b""

    @pytest.mark.asyncio
    async def test_setup_failure_remains_primary_when_trace_close_also_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Cleanup failure cannot mask the earlier Simulator setup failure."""
        stopped: list[str] = []
        trace_close_calls = 0
        original_close = TraceWriter.close

        class StopWitness(StateMachineAgent):
            async def on_stop(self, ctx: AgentContext) -> None:
                stopped.append(str(ctx.agent_id))

        def fail_initialization() -> None:
            raise RuntimeError("setup failed")

        def fail_after_trace_close(writer: TraceWriter) -> None:
            nonlocal trace_close_calls
            original_close(writer)
            trace_close_calls += 1
            raise RuntimeError("trace close failed")

        sim = Simulator(trace_path=tmp_path / "setup-and-close-failure.jsonl")
        sim.add_agent(AgentId("witness"), StopWitness())
        monkeypatch.setattr(sim, "_init_failures", fail_initialization)
        monkeypatch.setattr(TraceWriter, "close", fail_after_trace_close)

        with pytest.raises(RuntimeError, match="setup failed"):
            await sim.run()

        assert trace_close_calls == 1
        assert stopped == []

    @pytest.mark.asyncio
    async def test_primary_error_survives_cleanup_context_failure_and_trace_still_closes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Stop-context failure cannot mask the primary error or bypass trace closure."""
        trace_close_calls = 0
        original_close = TraceWriter.close
        sim = Simulator(trace_path=tmp_path / "cleanup-context-failure.jsonl")

        def fail_cleanup_context(_agent_id: AgentId, _slot: object) -> None:
            raise RuntimeError("cleanup context failed")

        class PrimaryFailure(StateMachineAgent):
            async def on_start(self, ctx: AgentContext) -> None:
                monkeypatch.setattr(sim, "_make_context", fail_cleanup_context)
                raise RuntimeError("primary start failed")

        def record_trace_close(writer: TraceWriter) -> None:
            nonlocal trace_close_calls
            original_close(writer)
            trace_close_calls += 1

        sim.add_agent(AgentId("failing"), PrimaryFailure())
        monkeypatch.setattr(TraceWriter, "close", record_trace_close)

        with pytest.raises(RuntimeError, match="primary start failed"):
            await sim.run()

        assert trace_close_calls == 1
        assert sim.trace_finalized is True

    @pytest.mark.asyncio
    async def test_start_failure_attempts_all_stops_and_flushes_without_masking(
        self, tmp_path: Path
    ) -> None:
        stopped: list[str] = []

        class FailingStart(StateMachineAgent):
            async def on_start(self, ctx: AgentContext) -> None:
                raise RuntimeError("start failed")

            async def on_stop(self, ctx: AgentContext) -> None:
                stopped.append(str(ctx.agent_id))
                raise RuntimeError("stop failed")

        class StopWitness(StateMachineAgent):
            async def on_stop(self, ctx: AgentContext) -> None:
                stopped.append(str(ctx.agent_id))

        trace = tmp_path / "start-failure.jsonl"
        sim = Simulator(trace_path=trace)
        sim.add_agent(AgentId("failing"), FailingStart())
        sim.add_agent(AgentId("witness"), StopWitness())

        with pytest.raises(RuntimeError, match="start failed"):
            await sim.run()

        assert stopped == ["failing", "witness"]
        assert [json.loads(line)["kind"] for line in trace.read_text().splitlines()][-2:] == [
            "stop",
            "stop",
        ]

    @pytest.mark.asyncio
    async def test_message_failure_attempts_stop_and_flushes_without_masking(
        self, tmp_path: Path
    ) -> None:
        stopped: list[str] = []

        class Sender(StateMachineAgent):
            async def on_start(self, ctx: AgentContext) -> None:
                await ctx.send(AgentId("failing"), b"boom")

            async def on_stop(self, ctx: AgentContext) -> None:
                stopped.append(str(ctx.agent_id))

        class FailingMessage(StateMachineAgent):
            async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
                raise RuntimeError("message failed")

            async def on_stop(self, ctx: AgentContext) -> None:
                stopped.append(str(ctx.agent_id))
                raise RuntimeError("stop failed")

        trace = tmp_path / "message-failure.jsonl"
        sim = Simulator(trace_path=trace)
        sim.add_agent(AgentId("sender"), Sender())
        sim.add_agent(AgentId("failing"), FailingMessage())

        with pytest.raises(RuntimeError, match="message failed"):
            await sim.run()

        assert stopped == ["sender", "failing"]
        assert any(json.loads(line)["kind"] == "receive" for line in trace.read_text().splitlines())

    @pytest.mark.asyncio
    async def test_stop_failure_attempts_remaining_stops_and_flushes(self, tmp_path: Path) -> None:
        stopped: list[str] = []

        class FailingStop(StateMachineAgent):
            async def on_stop(self, ctx: AgentContext) -> None:
                stopped.append(str(ctx.agent_id))
                if ctx.agent_id == AgentId("first"):
                    raise RuntimeError("first stop failed")

        trace = tmp_path / "stop-failure.jsonl"
        sim = Simulator(trace_path=trace)
        sim.add_agent(AgentId("first"), FailingStop())
        sim.add_agent(AgentId("second"), FailingStop())

        with pytest.raises(RuntimeError, match="first stop failed"):
            await sim.run()

        assert stopped == ["first", "second"]
        assert len(trace.read_text().splitlines()) == 4
