# SPDX-License-Identifier: Apache-2.0
"""End-to-end tests for the delegated_auth scenario.

Validates:
- The scenario runs to completion without TypeError (startup crash fix).
- delegation_audit events are present and record both granted and rejected ops.
- Traces are byte-identical across runs with the same seed (Tier 1 determinism).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig

_SCENARIO_YAML = Path(__file__).parent.parent.parent.parent / "scenarios" / "delegated_auth.yaml"


def _config(trace: Path, seed: int | None = None) -> ScenarioConfig:
    config = ScenarioConfig.from_yaml(_SCENARIO_YAML)
    config.output.trace = str(trace)
    if seed is not None:
        config.seed = seed
    return config


def _audits(trace: Path) -> list[dict[str, object]]:
    events = []
    for line in trace.read_text().splitlines():
        if not line.strip():
            continue
        try:
            obj: object = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and obj.get("type") == "delegation_audit":
            events.append(obj)
    return events


class TestScenarioCompletesWithoutCrash:
    @pytest.mark.asyncio
    async def test_scenario_runs_to_completion(self, tmp_path: Path) -> None:
        """Scenario must finish without TypeError from un-instantiated plugin class."""
        trace = tmp_path / "delegated_auth.jsonl"
        # This raised TypeError before the startup-crash fix
        # ("missing 1 required positional argument: 'scopes'")
        await ScenarioRunner(_config(trace)).run()
        assert trace.exists(), "trace file was not written"
        assert trace.stat().st_size > 0, "trace file is empty"

    @pytest.mark.asyncio
    async def test_delegation_audit_events_emitted(self, tmp_path: Path) -> None:
        """delegation_audit events must be present — proves the runner path was taken."""
        trace = tmp_path / "delegated_auth.jsonl"
        await ScenarioRunner(_config(trace)).run()
        audits = _audits(trace)
        assert len(audits) > 0, "no delegation_audit events found in trace"

    @pytest.mark.asyncio
    async def test_adversarial_ops_are_rejected(self, tmp_path: Path) -> None:
        """The three baked-in attacks must be refused by delegatable auth.

        Scope escalation → delegate granted=False.
        Stale-ancestor presentation → verify verified=False.
        Audience confusion → verify verified=False.
        At least one legitimate verify must also succeed (verified=True),
        proving the auth plugin is not simply always-reject.
        """
        trace = tmp_path / "delegated_auth.jsonl"
        await ScenarioRunner(_config(trace)).run()
        audits = _audits(trace)

        delegate_audits = [a for a in audits if a.get("op") == "delegate"]
        verify_audits = [a for a in audits if a.get("op") == "verify"]

        # At least one delegation must have been rejected (scope escalation)
        rejected_grants = [a for a in delegate_audits if a.get("granted") is False]
        assert rejected_grants, "expected at least one rejected delegation (scope escalation)"

        # At least one verify must have failed (stale ancestor or audience confusion)
        rejected_verifies = [a for a in verify_audits if a.get("verified") is False]
        assert rejected_verifies, "expected at least one rejected verification"

        # And at least one verify must have succeeded (legitimate leaf)
        accepted_verifies = [a for a in verify_audits if a.get("verified") is True]
        assert accepted_verifies, "expected at least one accepted verification"


class TestDeterminism:
    @pytest.mark.asyncio
    async def test_same_seed_identical_trace(self, tmp_path: Path) -> None:
        """Byte-identical traces across two runs with the same seed (Tier 1)."""
        t1 = tmp_path / "run1.jsonl"
        t2 = tmp_path / "run2.jsonl"
        await ScenarioRunner(_config(t1, seed=42)).run()
        await ScenarioRunner(_config(t2, seed=42)).run()
        h1 = hashlib.sha256(t1.read_bytes()).hexdigest()
        h2 = hashlib.sha256(t2.read_bytes()).hexdigest()
        print(f"Run 1 sha256: {h1}")
        print(f"Run 2 sha256: {h2}")
        assert h1 == h2, "traces differ — token IDs or timestamps are non-deterministic"
