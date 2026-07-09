# SPDX-License-Identifier: Apache-2.0
"""Tests for opt-in parallel simulation mode."""

from __future__ import annotations

from pathlib import Path

import pytest
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.sim.simulator import Simulator
from nest_core.types import AgentId


class _FanoutAgent(StateMachineAgent):
    def __init__(self, peers: list[AgentId]) -> None:
        self._peers = peers

    async def on_start(self, ctx: AgentContext) -> None:
        for peer in self._peers:
            if peer != ctx.agent_id:
                await ctx.send(peer, b"hello")


class TestParallelMode:
    @pytest.mark.asyncio
    async def test_default_mode_byte_identical(self, tmp_path: Path) -> None:
        traces: list[str] = []
        for run in range(2):
            trace_file = tmp_path / f"seq_{run}.jsonl"
            sim = Simulator(seed=7, trace_path=trace_file, parallel=False)
            peers = [AgentId(f"a{i}") for i in range(4)]
            for aid in peers:
                sim.add_agent(aid, _FanoutAgent(peers))
            await sim.run(max_ticks=500)
            traces.append(trace_file.read_text())
        assert traces[0] == traces[1]

    @pytest.mark.asyncio
    async def test_parallel_mode_completes(self, tmp_path: Path) -> None:
        trace_file = tmp_path / "par.jsonl"
        sim = Simulator(seed=7, trace_path=trace_file, parallel=True)
        peers = [AgentId(f"a{i}") for i in range(6)]
        for aid in peers:
            sim.add_agent(aid, _FanoutAgent(peers))
        await sim.run(max_ticks=500)
        assert sim.message_count > 0
        assert trace_file.exists()
