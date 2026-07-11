# SPDX-License-Identifier: Apache-2.0
"""Tests for failure injection: message drops, byzantine agents, partitions."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.sim.simulator import Simulator
from nest_core.types import AgentId


class PingAgent(StateMachineAgent):
    def __init__(self, target: AgentId, rounds: int = 5) -> None:
        self._target = target
        self._rounds = rounds
        self._round = 0
        self.received: list[bytes] = []

    async def on_start(self, ctx: AgentContext) -> None:
        await ctx.send(self._target, f"ping-{self._round}".encode())

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        self.received.append(payload)
        self._round += 1
        if self._round < self._rounds:
            await ctx.send(sender, f"ping-{self._round}".encode())


class TestMessageDrop:
    @pytest.mark.asyncio
    async def test_no_drops_at_zero(self, tmp_path: Path) -> None:
        sim = Simulator(seed=42, trace_path=tmp_path / "t.jsonl", message_drop_rate=0.0)
        a = PingAgent(AgentId("b"), rounds=10)
        b = PingAgent(AgentId("a"), rounds=10)
        sim.add_agent(AgentId("a"), a)
        sim.add_agent(AgentId("b"), b)
        await sim.run(max_ticks=10000)

        assert sim.dropped_count == 0
        assert sim.message_count > 0

    @pytest.mark.asyncio
    async def test_some_drops(self, tmp_path: Path) -> None:
        sim = Simulator(seed=42, trace_path=tmp_path / "t.jsonl", message_drop_rate=0.3)
        agents: list[PingAgent] = []
        for i in range(10):
            target = AgentId(f"a-{(i + 1) % 10}")
            agent = PingAgent(target, rounds=20)
            agents.append(agent)
            sim.add_agent(AgentId(f"a-{i}"), agent)
        await sim.run(max_ticks=50000)

        assert sim.dropped_count > 0
        assert sim.message_count > 0

    @pytest.mark.asyncio
    async def test_all_drops(self, tmp_path: Path) -> None:
        sim = Simulator(seed=42, trace_path=tmp_path / "t.jsonl", message_drop_rate=1.0)
        a = PingAgent(AgentId("b"), rounds=10)
        b = PingAgent(AgentId("a"), rounds=10)
        sim.add_agent(AgentId("a"), a)
        sim.add_agent(AgentId("b"), b)
        await sim.run(max_ticks=10000)

        assert sim.message_count == 0
        assert sim.dropped_count > 0

    @pytest.mark.asyncio
    async def test_drop_events_in_trace(self, tmp_path: Path) -> None:
        trace_file = tmp_path / "t.jsonl"
        sim = Simulator(seed=42, trace_path=trace_file, message_drop_rate=0.5)
        a = PingAgent(AgentId("b"), rounds=20)
        b = PingAgent(AgentId("a"), rounds=20)
        sim.add_agent(AgentId("a"), a)
        sim.add_agent(AgentId("b"), b)
        await sim.run(max_ticks=10000)

        content = trace_file.read_text()
        lines = [ln for ln in content.strip().split("\n") if ln]
        dropped_events = [json.loads(ln) for ln in lines if '"dropped"' in ln]
        assert len(dropped_events) > 0
        for ev in dropped_events:
            assert ev["kind"] == "dropped"


class TestNetworkPartition:
    @pytest.mark.asyncio
    async def test_partition_blocks_cross_group(self, tmp_path: Path) -> None:
        sim = Simulator(
            seed=42,
            trace_path=tmp_path / "t.jsonl",
            partition_groups=[["a"], ["b"]],
        )
        a = PingAgent(AgentId("b"), rounds=10)
        b = PingAgent(AgentId("a"), rounds=10)
        sim.add_agent(AgentId("a"), a)
        sim.add_agent(AgentId("b"), b)
        await sim.run(max_ticks=10000)

        assert sim.message_count == 0
        assert sim.dropped_count > 0

    @pytest.mark.asyncio
    async def test_same_partition_communicates(self, tmp_path: Path) -> None:
        sim = Simulator(
            seed=42,
            trace_path=tmp_path / "t.jsonl",
            partition_groups=[["a", "b"]],
        )
        a = PingAgent(AgentId("b"), rounds=5)
        b = PingAgent(AgentId("a"), rounds=5)
        sim.add_agent(AgentId("a"), a)
        sim.add_agent(AgentId("b"), b)
        await sim.run(max_ticks=10000)

        assert sim.message_count > 0
        assert sim.dropped_count == 0


class TestByzantineAgents:
    @pytest.mark.asyncio
    async def test_byzantine_corrupts_payload(self, tmp_path: Path) -> None:
        trace_file = tmp_path / "t.jsonl"
        sim = Simulator(
            seed=42,
            trace_path=trace_file,
            byzantine_fraction=0.5,
        )
        a = PingAgent(AgentId("b"), rounds=10)
        b = PingAgent(AgentId("a"), rounds=10)
        sim.add_agent(AgentId("a"), a)
        sim.add_agent(AgentId("b"), b)
        await sim.run(max_ticks=10000)

        assert sim.message_count > 0
        all_received = a.received + b.received
        corrupted = sum(
            1 for r in all_received if not r.decode("utf-8", errors="replace").startswith("ping-")
        )
        assert corrupted > 0

        receive_events = [
            json.loads(line)
            for line in trace_file.read_text().splitlines()
            if line and json.loads(line).get("kind") == "receive"
        ]
        assert any(not ev["msg"].startswith("ping-") for ev in receive_events)


class TestFailureViaRunner:
    @pytest.mark.asyncio
    async def test_runner_with_message_drop(self, tmp_path: Path) -> None:
        trace_file = tmp_path / "fail.jsonl"
        config = ScenarioConfig.from_dict(
            {
                "name": "fail-test",
                "seed": 42,
                "agents": {
                    "count": 10,
                    "roles": [
                        {"name": "buyer", "count": 5},
                        {"name": "seller", "count": 5},
                    ],
                },
                "task": {"type": "marketplace", "config": {"rounds": 5}},
                "failures": {"message_drop": 0.3},
                "duration": "ticks: 3000",
                "output": {"trace": str(trace_file)},
            }
        )

        runner = ScenarioRunner(config)
        result = await runner.run()

        assert result.exists()
        content = result.read_text()
        lines = [ln for ln in content.strip().split("\n") if ln]

        dropped = 0
        received = 0
        for line in lines:
            event: dict[str, Any] = json.loads(line)
            if event["kind"] == "dropped":
                dropped += 1
            elif event["kind"] == "receive":
                received += 1

        assert dropped > 0
        assert received > 0


class ChatterAgent(StateMachineAgent):
    """Sends one message per scheduled tick, independent of replies."""

    def __init__(self, target: AgentId, sends: int) -> None:
        self._target = target
        self._sends = sends

    async def on_start(self, ctx: AgentContext) -> None:
        for i in range(self._sends):
            await ctx.schedule(float(i + 1), f"tick-{i}".encode())

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        if sender == ctx.agent_id and payload.startswith(b"tick-"):
            await ctx.send(self._target, b"msg-" + payload)


class TestDelayedPartition:
    @pytest.mark.asyncio
    async def test_partition_starts_at_time_and_heals(self, tmp_path: Path) -> None:
        trace_file = tmp_path / "t.jsonl"
        sim = Simulator(
            seed=42,
            trace_path=trace_file,
            partition_groups=[["a"], ["b"]],
            partition_start_at_time=20.0,
            partition_heal_at_time=40.0,
        )
        sim.add_agent(AgentId("a"), ChatterAgent(AgentId("b"), sends=60))
        sim.add_agent(AgentId("b"), ChatterAgent(AgentId("a"), sends=0))
        await sim.run(max_ticks=10_000)

        events = [json.loads(ln) for ln in trace_file.read_text().strip().split("\n") if ln]
        started = [e for e in events if e["kind"] == "partition_started"]
        healed = [e for e in events if e["kind"] == "partition_healed"]
        assert len(started) == 1
        assert len(healed) == 1
        started_ts = float(started[0]["ts"])
        healed_ts = float(healed[0]["ts"])
        assert started_ts <= healed_ts

        # Self-scheduled ticks are receives too; only b's receives crossed groups.
        receives = [float(e["ts"]) for e in events if e["kind"] == "receive" and e["agent"] == "b"]
        dropped = [float(e["ts"]) for e in events if e["kind"] == "dropped"]
        # Phase 1: cross-group delivery works before the partition starts.
        assert any(ts < started_ts for ts in receives)
        # Phase 2: with message_drop=0, every drop is the partition's doing
        # and falls inside the partition window.
        assert dropped
        assert all(started_ts <= ts <= healed_ts for ts in dropped)
        # Phase 3: delivery resumes after heal.
        assert any(ts > healed_ts for ts in receives)

    @pytest.mark.asyncio
    async def test_event_count_heal_still_supported(self, tmp_path: Path) -> None:
        """The pre-existing event-count heal field keeps its meaning."""
        trace_file = tmp_path / "t.jsonl"
        sim = Simulator(
            seed=42,
            trace_path=trace_file,
            partition_groups=[["a"], ["b"]],
            partition_heal_at=30,
        )
        sim.add_agent(AgentId("a"), ChatterAgent(AgentId("b"), sends=60))
        sim.add_agent(AgentId("b"), ChatterAgent(AgentId("a"), sends=0))
        await sim.run(max_ticks=10_000)

        events = [json.loads(ln) for ln in trace_file.read_text().strip().split("\n") if ln]
        assert len([e for e in events if e["kind"] == "partition_healed"]) == 1
        assert [e for e in events if e["kind"] == "dropped"]

    @pytest.mark.asyncio
    async def test_no_start_time_preserves_legacy_behavior(self, tmp_path: Path) -> None:
        trace_file = tmp_path / "t.jsonl"
        sim = Simulator(
            seed=42,
            trace_path=trace_file,
            partition_groups=[["a"], ["b"]],
        )
        sim.add_agent(AgentId("a"), ChatterAgent(AgentId("b"), sends=10))
        sim.add_agent(AgentId("b"), ChatterAgent(AgentId("a"), sends=0))
        await sim.run(max_ticks=10_000)

        events = [json.loads(ln) for ln in trace_file.read_text().strip().split("\n") if ln]
        # Partition active from tick 0: no cross-group receive, no start event.
        assert not [e for e in events if e["kind"] == "partition_started"]
        assert not [e for e in events if e["kind"] == "receive" and e["agent"] == "b"]
        assert [e for e in events if e["kind"] == "dropped"]
