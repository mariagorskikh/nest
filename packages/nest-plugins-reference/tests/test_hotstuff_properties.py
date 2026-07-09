# SPDX-License-Identifier: Apache-2.0
"""Property-based safety tests for the HotStuff BFT coordination plugin.

Safety (no two honest replicas commit conflicting values for the same
view) must hold under any randomized partition schedule or randomized
malicious-leader placement -- liveness is explicitly not asserted here,
since an adversarial partition or enough equivocation can legitimately
stall progress without breaking safety.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from nest_core.scenarios_builtin.bft_hotstuff import (
    MaliciousLeaderAgent,
    ReplicaAgent,
    instantiate_identity,
)
from nest_core.sim.simulator import Simulator
from nest_core.types import AgentId
from nest_core.validators import validate_events
from nest_plugins_reference.identity.did_key import DidKeyIdentity

_N = 7
_F = 2


def _load_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    with path.open() as fh:
        for line in fh:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def _no_conflicting_commits_detail(events: list[dict[str, Any]]) -> str:
    results = validate_events(events, "bft_hotstuff")
    safety = next(r for r in results if r.name == "bft_no_conflicting_commits")
    return safety.detail


class TestSafetyUnderRandomPartitions:
    @settings(max_examples=15, deadline=None)
    @given(
        seed=st.integers(min_value=0, max_value=10000),
        split=st.integers(min_value=1, max_value=_N - 1),
        drop_rate=st.floats(min_value=0.0, max_value=0.3, allow_nan=False, allow_infinity=False),
    )
    @pytest.mark.asyncio
    async def test_safety_holds_under_random_partition_and_drop_rate(
        self, seed: int, split: int, drop_rate: float
    ) -> None:
        """No conflicting commits, however the network is partitioned or lossy."""
        replica_ids = [AgentId(f"replica-{i}") for i in range(_N)]
        groups = [
            [str(r) for r in replica_ids[:split]],
            [str(r) for r in replica_ids[split:]],
        ]

        plugins: dict[str, Any] = {"identity": DidKeyIdentity}
        instantiate_identity(plugins, replica_ids)
        agent_plugins = plugins.pop("_agent_plugins")

        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as fh:
            trace_path = Path(fh.name)
        try:
            sim = Simulator(
                seed=seed,
                trace_path=trace_path,
                message_drop_rate=drop_rate,
                partition_groups=groups,
                plugins=plugins,
            )
            for rid in replica_ids:
                sim.add_agent(rid, ReplicaAgent(rid, replica_ids, f=_F, view_timeout_ticks=40))
            for rid, overrides in agent_plugins.items():
                sim.set_agent_plugins(rid, overrides)

            await sim.run(max_ticks=3000)
            events = _load_events(trace_path)
        finally:
            trace_path.unlink(missing_ok=True)

        detail = _no_conflicting_commits_detail(events)
        assert "conflicting commits" not in detail, detail


class TestSafetyUnderRandomByzantineLeaders:
    @settings(max_examples=15, deadline=None)
    @given(
        seed=st.integers(min_value=0, max_value=10000),
        malicious_indices=st.lists(
            st.integers(min_value=0, max_value=_N - 1), unique=True, max_size=2
        ),
        byzantine_fraction=st.floats(
            min_value=0.0, max_value=0.3, allow_nan=False, allow_infinity=False
        ),
    )
    @pytest.mark.asyncio
    async def test_safety_holds_despite_equivocation_and_byzantine_noise(
        self, seed: int, malicious_indices: list[int], byzantine_fraction: float
    ) -> None:
        """No conflicting commits, however leaders equivocate or noise is injected.

        Equivocation IS expected to be detected by ``bft_no_equivocation`` when
        a malicious leader actually gets a turn -- that validator is not
        asserted here. The property under test is narrower: safety survives
        equivocation, it does not prevent it.
        """
        replica_ids = [AgentId(f"replica-{i}") for i in range(_N)]
        malicious = {str(replica_ids[i]) for i in malicious_indices}

        plugins: dict[str, Any] = {"identity": DidKeyIdentity}
        instantiate_identity(plugins, replica_ids)
        agent_plugins = plugins.pop("_agent_plugins")

        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as fh:
            trace_path = Path(fh.name)
        try:
            sim = Simulator(
                seed=seed,
                trace_path=trace_path,
                byzantine_fraction=byzantine_fraction,
                plugins=plugins,
            )
            for rid in replica_ids:
                cls = MaliciousLeaderAgent if str(rid) in malicious else ReplicaAgent
                sim.add_agent(rid, cls(rid, replica_ids, f=_F, view_timeout_ticks=40))
            for rid, overrides in agent_plugins.items():
                sim.set_agent_plugins(rid, overrides)

            await sim.run(max_ticks=3000)
            events = _load_events(trace_path)
        finally:
            trace_path.unlink(missing_ok=True)

        detail = _no_conflicting_commits_detail(events)
        assert "conflicting commits" not in detail, detail
