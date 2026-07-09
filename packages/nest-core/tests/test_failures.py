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

    @pytest.mark.asyncio
    async def test_byzantine_trace_deterministic_with_randbytes(self, tmp_path: Path) -> None:
        """Byzantine mangling uses randbytes — same seed yields identical traces."""
        traces: list[str] = []
        for i in range(2):
            trace_file = tmp_path / f"byz_{i}.jsonl"
            sim = Simulator(seed=99, trace_path=trace_file, byzantine_fraction=0.5)
            a = PingAgent(AgentId("b"), rounds=8)
            b = PingAgent(AgentId("a"), rounds=8)
            sim.add_agent(AgentId("a"), a)
            sim.add_agent(AgentId("b"), b)
            await sim.run(max_ticks=5000)
            traces.append(trace_file.read_text())
        assert traces[0] == traces[1]


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


class TestCombinedFailures:
    @pytest.mark.asyncio
    async def test_byzantine_and_partition(self, tmp_path: Path) -> None:
        sim = Simulator(
            seed=42,
            trace_path=tmp_path / "combo.jsonl",
            byzantine_fraction=0.5,
            partition_groups=[["a"], ["b"]],
        )
        a = PingAgent(AgentId("b"), rounds=5)
        b = PingAgent(AgentId("a"), rounds=5)
        sim.add_agent(AgentId("a"), a)
        sim.add_agent(AgentId("b"), b)
        await sim.run(max_ticks=10000)
        assert sim.message_count == 0
        assert sim.dropped_count > 0

    @pytest.mark.asyncio
    async def test_three_partition_groups(self, tmp_path: Path) -> None:
        sim = Simulator(
            seed=7,
            trace_path=tmp_path / "tripart.jsonl",
            partition_groups=[["a"], ["b"], ["c"]],
        )
        for name in ("a", "b", "c"):
            others = [AgentId(x) for x in ("a", "b", "c") if x != name]
            sim.add_agent(AgentId(name), PingAgent(others[0], rounds=3))
        await sim.run(max_ticks=5000)
        assert sim.message_count == 0

    @pytest.mark.asyncio
    async def test_byzantine_fraction_zero(self, tmp_path: Path) -> None:
        trace_file = tmp_path / "no-byz.jsonl"
        sim = Simulator(seed=42, trace_path=trace_file, byzantine_fraction=0.0)
        a = PingAgent(AgentId("b"), rounds=5)
        b = PingAgent(AgentId("a"), rounds=5)
        sim.add_agent(AgentId("a"), a)
        sim.add_agent(AgentId("b"), b)
        await sim.run(max_ticks=5000)
        assert sim.message_count > 0
        receive_events = [
            json.loads(line)
            for line in trace_file.read_text().splitlines()
            if line and json.loads(line).get("kind") == "receive"
        ]
        assert all(ev["msg"].startswith("ping-") for ev in receive_events)
