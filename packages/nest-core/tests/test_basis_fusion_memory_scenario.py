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
    @pytest.mark.parametrize(
        ("scenario_path", "scenario_type", "expected_payload_marker"),
        [
            (
                "scenarios/memory_basis_fusion_calculator.yaml",
                "memory_basis_fusion_calculator",
                "Alice was beginning to get very tired",
            ),
            (
                "scenarios/memory_code_saturation_calculator.yaml",
                "memory_basis_fusion_calculator",
                "amdgpu_bo_placement_from_domain",
            ),
        ],
    )
    async def test_calculator_fuses_basis_ignores_noise_and_ships(
        self,
        scenario_path: str,
        scenario_type: str,
        expected_payload_marker: str,
    ) -> None:
        traces: list[bytes] = []
        with tempfile.TemporaryDirectory() as tmp:
            for run in range(2):
                config = ScenarioConfig.from_yaml(scenario_path)
                out = Path(tmp) / f"run-{run}.jsonl"
                config.output.trace = str(out)
                trace_path = await ScenarioRunner(config).run()
                traces.append(trace_path.read_bytes())
                if run == 0:
                    assert expected_payload_marker in trace_path.read_text()
                    results = validate_trace(trace_path, scenario_type)
                    assert results, "validator produced no results"
                    assert all(r.passed for r in results), [r.detail for r in results]
        assert traces[0] == traces[1], "trace not byte-identical under same seed"
