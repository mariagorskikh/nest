# SPDX-License-Identifier: Apache-2.0
"""End-to-end tests for basis-restricted calculator memory fusion."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_core.validators import validate_trace


class TestBasisFusionMemoryScenario:
    @pytest.mark.asyncio
    async def test_calculator_fuses_basis_ignores_noise_and_ships(self) -> None:
        traces: list[bytes] = []
        with tempfile.TemporaryDirectory() as tmp:
            for run in range(2):
                config = ScenarioConfig.from_yaml("scenarios/memory_basis_fusion_calculator.yaml")
                out = Path(tmp) / f"run-{run}.jsonl"
                config.output.trace = str(out)
                trace_path = await ScenarioRunner(config).run()
                traces.append(trace_path.read_bytes())
                if run == 0:
                    results = validate_trace(trace_path, "memory_basis_fusion_calculator")
                    assert results, "validator produced no results"
                    assert all(r.passed for r in results), [r.detail for r in results]
        assert traces[0] == traces[1], "trace not byte-identical under same seed"
