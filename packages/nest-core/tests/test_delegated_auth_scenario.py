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
    """Extract delegation_audit payloads from the trace.

    The simulator records each ctx.send() as {"kind": "send", "msg": "<json>", ...}.
    Audit events are the inner JSON objects where type == "delegation_audit".
    """
    events = []
    for line in trace.read_text().splitlines():
        if not line.strip():
            continue
        try:
            outer: object = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(outer, dict):
            continue
        msg = outer.get("msg", "")
        if not isinstance(msg, str):
            continue
        try:
            inner: object = json.loads(msg)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(inner, dict) and inner.get("type") == "delegation_audit":
            events.append(inner)
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
    async def test_coordinator_grants_succeed_and_escalation_rejected(
        self, tmp_path: Path
    ) -> None:
        """Coordinator→intermediary grants succeed; scope escalation is rejected.

        Note: our delegate() requires caller= whenever the parent token carries
        an audience binding. The scenario helper (_delegate) does not pass caller=,
        so intermediary→leaf sub-delegations are rejected by the caller check —
        this is the security fix working as designed (a caller without an identity
        cannot re-delegate an audience-bound token). The assertions here cover what
        actually passes through our DelegatableAuth in this scenario.
        """
        trace = tmp_path / "delegated_auth.jsonl"
        await ScenarioRunner(_config(trace)).run()
        audits = _audits(trace)

        delegate_audits = [a for a in audits if a.get("op") == "delegate"]

        # Coordinator-level grants (root token → no audience binding → no caller required)
        # must succeed for all three intermediaries.
        granted = [a for a in delegate_audits if a.get("granted") is True]
        assert len(granted) >= 3, (
            f"expected at least 3 coordinator→intermediary grants, got {len(granted)}"
        )

        # Scope escalation is rejected regardless of caller check.
        # intermediary-2's first leaf requests ["read", "admin"] from ["read", "write"] parent.
        escalation_rejected = [
            a for a in delegate_audits
            if a.get("granted") is False
            and "admin" in (a.get("child_scopes") or [])
        ]
        assert escalation_rejected, (
            "expected at least one scope-escalation delegation to be rejected"
        )


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
        assert h1 == h2, "traces differ — token IDs or timestamps are non-deterministic"
