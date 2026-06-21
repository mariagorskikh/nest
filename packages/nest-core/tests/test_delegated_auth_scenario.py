# SPDX-License-Identifier: Apache-2.0
"""Integration and adversarial validation tests for delegated auth scenario."""

from __future__ import annotations

from pathlib import Path

import pytest
from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_core.validators import validate_trace


@pytest.mark.asyncio
async def test_delegated_auth_scenario_success(tmp_path: Path) -> None:
    """Test that delegated_auth scenario passes all validation with delegatable plugin."""
    yaml_path = Path(__file__).parent.parent.parent.parent / "scenarios" / "delegated_auth.yaml"
    if not yaml_path.exists():
        pytest.skip("delegated_auth.yaml not found")

    trace_file = tmp_path / "delegated_auth_success.jsonl"

    # Load and run config with delegatable plugin
    config = ScenarioConfig.from_yaml(yaml_path)
    config.output.trace = str(trace_file)

    runner = ScenarioRunner(config)
    result_path = await runner.run()

    assert result_path.exists()

    # Validate trace - all validators MUST pass
    results = validate_trace(result_path, "delegated_auth")
    assert len(results) == 3
    for r in results:
        assert r.passed, f"Validator {r.name} failed: {r.detail}"


@pytest.mark.asyncio
async def test_delegated_auth_scenario_adversarial_failure(tmp_path: Path) -> None:
    """Test that delegated_auth scenario fails validations when using the default jwt plugin."""
    yaml_path = Path(__file__).parent.parent.parent.parent / "scenarios" / "delegated_auth.yaml"
    if not yaml_path.exists():
        pytest.skip("delegated_auth.yaml not found")

    trace_file = tmp_path / "delegated_auth_failure.jsonl"

    # Load config and override auth plugin to jwt
    config = ScenarioConfig.from_yaml(yaml_path)
    config.layers.auth = "jwt"
    config.output.trace = str(trace_file)

    runner = ScenarioRunner(config)
    result_path = await runner.run()

    assert result_path.exists()

    # Validate trace - at least one validator MUST fail under jwt auth
    results = validate_trace(result_path, "delegated_auth")
    assert len(results) == 3
    failed_validators = [r for r in results if not r.passed]
    assert len(failed_validators) > 0, (
        "Expected adversarial validators to catch attacks under jwt auth, but all passed"
    )
