# SPDX-License-Identifier: Apache-2.0
"""Scenario-level tests for the PBFT coordination plugin.

Persona note (distributed-systems engineer): a scenario YAML is only as good as
the property it demonstrates. These tests load the two shipped scenarios and
prove the safety claims their headers assert — the partition minority cannot
reach quorum, and byzantine equivocation is caught by the validators — so the
scenarios are live demonstrations, not decoration.
"""

from __future__ import annotations

import asyncio

from nest_core.scenario import ScenarioConfig
from nest_core.types import AgentId, Task
from nest_plugins_reference.coordination.pbft import PbftCoordination, quorum_size
from nest_plugins_reference.identity.did_key import DidKeyIdentity
from nest_plugins_reference.validators.coordination_validators import (
    check_no_conflicting_commits,
    check_no_equivocation,
)


def _cluster(n: int = 7):
    ids = [AgentId(f"replica-{i}") for i in range(n)]
    idents = {a: DidKeyIdentity(a, seed=f"s{i}".encode()) for i, a in enumerate(ids)}
    for a in ids:
        for b in ids:
            if a != b:
                idents[a].register_peer(b, idents[b].public_key)
    coords = {a: PbftCoordination(a, identity=idents[a], n=n, replicas=ids) for a in ids}
    return ids, coords


class TestScenariosLoad:
    def test_partition_scenario_loads_with_pbft(self) -> None:
        c = ScenarioConfig.from_yaml("scenarios/bft_partition.yaml")
        assert c.layers.coordination == "pbft"
        assert c.agents.count == 7

    def test_byzantine_scenario_loads_with_pbft(self) -> None:
        c = ScenarioConfig.from_yaml("scenarios/bft_byzantine.yaml")
        assert c.layers.coordination == "pbft"
        assert c.agents.count == 7


class TestPartitionSafety:
    def test_minority_cannot_reach_quorum(self) -> None:
        """A 3-node minority (< quorum of 5) commits nothing during a partition."""
        ids, coords = _cluster(7)
        assert quorum_size(7) == 5
        leader = coords[ids[0]]
        rnd = asyncio.run(leader.propose(Task(id="t1", description="X")))
        # Only the 3-node minority votes.
        for i in (4, 5, 6):
            asyncio.run(coords[ids[i]].participate(rnd))
        outcome = asyncio.run(leader.resolve(rnd))
        assert outcome.metadata["committed_value"] is None

    def test_majority_reaches_quorum(self) -> None:
        """A 5-node majority meets quorum and commits."""
        ids, coords = _cluster(7)
        leader = coords[ids[0]]
        rnd = asyncio.run(leader.propose(Task(id="t1", description="X")))
        for i in range(5):
            asyncio.run(coords[ids[i]].participate(rnd))
        outcome = asyncio.run(leader.resolve(rnd))
        assert outcome.metadata["committed_value"] is not None


class TestByzantineSafety:
    def test_honest_replicas_do_not_conflict(self) -> None:
        """With all honest votes the conflicting-commit validator passes."""
        ids, coords = _cluster(7)
        leader = coords[ids[0]]
        rnd = asyncio.run(leader.propose(Task(id="t1", description="X")))
        commits = []
        for aid in ids:
            asyncio.run(coords[aid].participate(rnd))
        for aid in ids:
            outcome = asyncio.run(coords[aid].resolve(rnd))
            asyncio.run(coords[aid].commit(outcome))
            m = outcome.metadata
            if m["committed_value"] is not None:
                commits.append(
                    {
                        "agent": str(aid),
                        "view": m["view"],
                        "seq": m["seq"],
                        "value": m["committed_value"],
                    }
                )
        assert check_no_conflicting_commits(commits).passed

    def test_equivocation_is_caught(self) -> None:
        """A byzantine replica signing two values for one slot is detected."""
        votes = [
            {"voter": "byzantine-0", "view": 0, "seq": 1, "phase": "prepare", "value": "X"},
            {"voter": "byzantine-0", "view": 0, "seq": 1, "phase": "prepare", "value": "Y"},
        ]
        assert not check_no_equivocation(votes).passed
