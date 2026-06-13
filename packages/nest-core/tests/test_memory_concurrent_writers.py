# SPDX-License-Identifier: Apache-2.0
"""End-to-end tests for the memory_concurrent_writers scenario and convergence validator."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_core.validators import validate_trace


def _config(trace_file: Path, message_drop: float) -> ScenarioConfig:
    return ScenarioConfig.from_dict(
        {
            "name": "test-concurrent-writers",
            "seed": 42,
            "agents": {"count": 8, "brain": "state-machine"},
            "layers": {"memory": "lww_crdt"},
            "task": {
                "type": "memory_concurrent_writers",
                "config": {"key": "shared", "rounds": 6},
            },
            "failures": {"message_drop": message_drop},
            "duration": "ticks: 20000",
            "output": {"trace": str(trace_file)},
        }
    )


class TestMemoryConcurrentWriters:
    @pytest.mark.asyncio
    async def test_run_produces_messages(self, tmp_path: Path) -> None:
        trace_file = tmp_path / "cw.jsonl"
        runner = ScenarioRunner(_config(trace_file, message_drop=0.0))
        result = await runner.run()

        assert result.exists()
        kinds: set[str] = set()
        for line in result.read_text().splitlines():
            if line:
                event: dict[str, Any] = json.loads(line)
                kinds.add(event["kind"])
        assert "broadcast" in kinds
        assert "receive" in kinds

    @pytest.mark.asyncio
    async def test_converges_with_reliable_delivery(self, tmp_path: Path) -> None:
        trace_file = tmp_path / "cw.jsonl"
        runner = ScenarioRunner(_config(trace_file, message_drop=0.0))
        await runner.run()

        results = validate_trace(trace_file, "memory_concurrent_writers")
        assert results, "expected a convergence result"
        assert all(r.passed for r in results), [repr(r) for r in results]

    @pytest.mark.asyncio
    async def test_deterministic_trace(self, tmp_path: Path) -> None:
        traces: list[str] = []
        for i in range(2):
            trace_file = tmp_path / f"cw_{i}.jsonl"
            await ScenarioRunner(_config(trace_file, message_drop=0.1)).run()
            traces.append(trace_file.read_text())
        assert traces[0] == traces[1]
