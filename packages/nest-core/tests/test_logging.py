# SPDX-License-Identifier: Apache-2.0
"""Tests for optional structured logging (NEST_LOG)."""

from __future__ import annotations

import io
from contextlib import redirect_stdout
from pathlib import Path

import pytest
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.sim.simulator import Simulator
from nest_core.types import AgentId


class _PingOnce(StateMachineAgent):
    async def on_start(self, ctx: AgentContext) -> None:
        await ctx.send(AgentId("a1"), b"ping")

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        pass


async def _run_sim_with_level(level: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setenv("NEST_LOG", level)
    from nest_core.log import reset_logging_for_tests

    reset_logging_for_tests()
    trace_file = tmp_path / f"log-{level}.jsonl"
    sim = Simulator(seed=1, trace_path=trace_file)
    sim.add_agent(AgentId("a0"), _PingOnce())
    sim.add_agent(AgentId("a1"), _PingOnce())
    buf = io.StringIO()
    with redirect_stdout(buf):
        await sim.run(max_ticks=50)
    return buf.getvalue()


@pytest.mark.asyncio
async def test_debug_logging_emits_correlation_id(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = await _run_sim_with_level("debug", tmp_path, monkeypatch)
    assert "corr-" in output
    assert "dispatch_deliver" in output or "simulation_start" in output


@pytest.mark.asyncio
async def test_info_logging_filters_debug(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = await _run_sim_with_level("info", tmp_path, monkeypatch)
    assert "corr-" not in output
    assert "dispatch_deliver" not in output


@pytest.mark.asyncio
async def test_warning_logging_is_quiet(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = await _run_sim_with_level("warning", tmp_path, monkeypatch)
    assert "corr-" not in output
    assert "dispatch_deliver" not in output


@pytest.mark.asyncio
async def test_error_logging_is_quiet(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = await _run_sim_with_level("error", tmp_path, monkeypatch)
    assert "corr-" not in output
