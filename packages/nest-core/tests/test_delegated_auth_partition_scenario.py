# SPDX-License-Identifier: Apache-2.0
"""End-to-end tests for the delegated_auth_partition scenario.

Runs the real ScenarioRunner -- per-agent auth replicas, real partition
machinery, real gossip -- under both auth plugins and asserts:

- ``mesh_revocable``: partition records present, the merged escalation and
  audience validators green, partition liveness AND bounded revocation
  convergence both hold, and the audit stream is identical across two runs
  (determinism);
- per-replica ``delegatable`` (the baseline): liveness still holds (it is
  honest during the split) but convergence FAILS -- remote replicas never
  learn of the revocation. That flip is the scenario's whole point.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from nest_core.runner import ScenarioRunner
from nest_core.scenario import (
    FailureConfig,
    OutputConfig,
    RoleConfig,
    ScenarioConfig,
    TaskConfig,
)
from nest_plugins_reference.validators import (
    check_audience_binding,
    check_no_scope_escalation,
    check_partition_liveness,
    check_revocation_converges,
    extract_delegation_audits,
    find_partition_ticks,
)

_GOSSIP_INTERVAL = 5


def _config(auth: str, trace: Path) -> ScenarioConfig:
    config = ScenarioConfig(
        name="delegated_auth_partition",
        seed=42,
        task=TaskConfig(
            type="delegated_auth_partition",
            config={
                "revoke_tick": 20,
                "gossip_interval": _GOSSIP_INTERVAL,
                "gossip_until": 95,
                "presents": 15,
                "present_interval": 6,
            },
        ),
        failures=FailureConfig(
            network_partition={
                "groups": [
                    ["coordinator-0", "intermediary-0", "leaf-0", "leaf-1", "leaf-2"],
                    ["gateway-0", "intermediary-1", "leaf-3", "leaf-4", "leaf-5"],
                ]
            },
            partition_start_at_time=10.0,
            partition_heal_at_time=55.0,
        ),
        output=OutputConfig(trace=str(trace)),
    )
    config.agents.count = 10
    config.agents.roles = [
        RoleConfig(name="coordinator", count=1),
        RoleConfig(name="gateway", count=1),
        RoleConfig(name="intermediary", count=2),
        RoleConfig(name="leaf", count=6),
    ]
    config.layers.auth = auth
    return config


async def _run(auth: str, trace: Path) -> list[dict[str, Any]]:
    result = await ScenarioRunner(_config(auth, trace)).run()
    assert result.exists()
    return [json.loads(line) for line in result.read_text().splitlines() if line]


@pytest.mark.asyncio
async def test_mesh_revocable_liveness_and_convergence(tmp_path: Path) -> None:
    events = await _run("mesh_revocable", tmp_path / "mesh.jsonl")
    started, healed = find_partition_ticks(events)
    assert started is not None and healed is not None
    assert started < healed

    audits = extract_delegation_audits(events)
    revoke_ticks = [a["tick"] for a in audits if a.get("op") == "revoke"]
    assert revoke_ticks, "scenario must actually revoke"
    # The revocation must land inside the partition window, else the
    # scenario is not testing what it claims to test.
    assert started < revoke_ticks[0] < healed

    # The merged delegation validators still hold on this trace.
    assert check_no_scope_escalation(audits).passed
    assert check_audience_binding(audits).passed

    deadline = healed + 2 * _GOSSIP_INTERVAL
    assert check_partition_liveness(audits, heal_tick=healed).passed
    assert check_revocation_converges(audits, deadline_tick=deadline).passed


@pytest.mark.asyncio
async def test_per_replica_delegatable_baseline_never_converges(tmp_path: Path) -> None:
    events = await _run("delegatable", tmp_path / "baseline.jsonl")
    _, healed = find_partition_ticks(events)
    assert healed is not None

    audits = extract_delegation_audits(events)
    # Honest during the split (a stale replica cannot deny)...
    assert check_partition_liveness(audits, heal_tick=healed).passed
    # ...but with no replication channel it stays stale forever.
    deadline = healed + 2 * _GOSSIP_INTERVAL
    assert not check_revocation_converges(audits, deadline_tick=deadline).passed


@pytest.mark.asyncio
async def test_trace_is_deterministic(tmp_path: Path) -> None:
    first = await _run("mesh_revocable", tmp_path / "one.jsonl")
    second = await _run("mesh_revocable", tmp_path / "two.jsonl")
    assert extract_delegation_audits(first) == extract_delegation_audits(second)
    assert (tmp_path / "one.jsonl").read_bytes() == (tmp_path / "two.jsonl").read_bytes()
