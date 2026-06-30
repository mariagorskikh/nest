# SPDX-License-Identifier: Apache-2.0
"""Tests for the PBFT coordination plugin (happy-path core).

Persona note (distributed-systems engineer): the invariants under test are the
ones a BFT agreement core lives or dies on -- all honest replicas commit the
*same* value (agreement), a quorum is exactly ``2f+1`` distinct *verified*
votes, and a fabricated vote cannot manufacture a quorum (byzantine rejection).
View-change is out of scope for this iteration; these tests pin the agreement
core so the later view-change work has a fixed foundation.
"""

from __future__ import annotations

import asyncio

from nest_core.layers.coordination import Coordination
from nest_core.plugins import PluginRegistry
from nest_core.types import AgentId, Task
from nest_plugins_reference.coordination.pbft import (
    PbftCoordination,
    fault_tolerance,
    leader_for_view,
    quorum_size,
    signing_payload,
    value_for_task,
)
from nest_plugins_reference.identity.did_key import DidKeyIdentity


def _cluster(n: int = 4) -> tuple[list[AgentId], dict[AgentId, PbftCoordination]]:
    """Build an ``n``-replica cluster with full did_key key exchange.

    Example::

        ids, coords = _cluster(4)
    """
    ids = [AgentId(f"r{i}") for i in range(n)]
    idents = {aid: DidKeyIdentity(aid, seed=f"seed{i}".encode()) for i, aid in enumerate(ids)}
    for a in ids:
        for b in ids:
            if a != b:
                idents[a].register_peer(b, idents[b].public_key)
    coords = {aid: PbftCoordination(aid, identity=idents[aid], n=n, replicas=ids) for aid in ids}
    return ids, coords


def _run_round(
    ids: list[AgentId],
    coords: dict[AgentId, PbftCoordination],
    task: Task,
) -> dict[AgentId, str | None]:
    """Drive one full propose/participate/resolve/commit round; return commits.

    Example::

        committed = _run_round(ids, coords, Task(id="t1", description="x"))
    """
    leader = coords[ids[0]]
    rnd = asyncio.run(leader.propose(task))
    for aid in ids:
        asyncio.run(coords[aid].participate(rnd))
    view = int(rnd.metadata["view"])
    seq = int(rnd.metadata["seq"])
    committed: dict[AgentId, str | None] = {}
    for aid in ids:
        outcome = asyncio.run(coords[aid].resolve(rnd))
        asyncio.run(coords[aid].commit(outcome))
        committed[aid] = coords[aid].committed_value(view, seq)
    return committed


# ---------------------------------------------------------------------------
# Quorum arithmetic
# ---------------------------------------------------------------------------


class TestQuorumMath:
    def test_quorum_for_4_is_3(self) -> None:
        assert quorum_size(4) == 3
        assert fault_tolerance(4) == 1

    def test_quorum_for_7_is_5(self) -> None:
        assert quorum_size(7) == 5
        assert fault_tolerance(7) == 2

    def test_leader_rotates_round_robin(self) -> None:
        assert leader_for_view(0, 4) == 0
        assert leader_for_view(1, 4) == 1
        assert leader_for_view(5, 4) == 1

    def test_signing_payload_is_slot_bound(self) -> None:
        """Different slot/phase/value -> different signing bytes (no replay)."""
        base = signing_payload(0, 1, "prepare", "X")
        assert base != signing_payload(1, 1, "prepare", "X")
        assert base != signing_payload(0, 2, "prepare", "X")
        assert base != signing_payload(0, 1, "commit", "X")
        assert base != signing_payload(0, 1, "prepare", "Y")


# ---------------------------------------------------------------------------
# Happy path: agreement
# ---------------------------------------------------------------------------


class TestAgreement:
    def test_all_honest_replicas_commit_same_value(self) -> None:
        ids, coords = _cluster(4)
        committed = _run_round(ids, coords, Task(id="t1", description="agree on X"))
        values = set(committed.values())
        assert len(values) == 1
        assert None not in values
        assert committed[ids[0]] == value_for_task(Task(id="t1", description="agree on X"))

    def test_agreement_holds_for_7_replicas(self) -> None:
        ids, coords = _cluster(7)
        committed = _run_round(ids, coords, Task(id="t2", description="Y"))
        assert len(set(committed.values())) == 1
        assert None not in set(committed.values())

    def test_certificate_reaches_quorum(self) -> None:
        ids, coords = _cluster(4)
        leader = coords[ids[0]]
        rnd = asyncio.run(leader.propose(Task(id="t1", description="X")))
        for aid in ids:
            asyncio.run(coords[aid].participate(rnd))
        outcome = asyncio.run(leader.resolve(rnd))
        assert outcome.metadata["committed_value"] is not None
        assert len(outcome.metadata["certificate"]) >= outcome.metadata["quorum"]


# ---------------------------------------------------------------------------
# Byzantine rejection
# ---------------------------------------------------------------------------


class TestByzantineRejection:
    def test_forged_vote_cannot_fake_quorum(self) -> None:
        """A fabricated vote with a bogus signature is dropped, blocking commit."""
        ids, coords = _cluster(4)
        leader = coords[ids[0]]
        rnd = asyncio.run(leader.propose(Task(id="t2", description="Y")))
        # Only two honest votes (below quorum of 3).
        asyncio.run(coords[ids[0]].participate(rnd))
        asyncio.run(coords[ids[1]].participate(rnd))
        # Attacker fabricates a third vote with a garbage signature.
        rnd.metadata["votes"].append(
            {
                "voter": "r2",
                "view": 0,
                "seq": 1,
                "phase": "prepare",
                "value": "t2:Y",
                "sig_value": "deadbeef",
                "sig_algorithm": "sim-rsa-sha256",
            }
        )
        outcome = asyncio.run(leader.resolve(rnd))
        assert outcome.metadata["committed_value"] is None
        assert outcome.metadata["certificate"] == []

    def test_non_leader_pre_prepare_is_not_voted(self) -> None:
        """A pre-prepare whose proposer is not the view's leader gets no vote."""
        ids, coords = _cluster(4)
        # r1 (not leader for view 0) forges a proposal by hand.
        leader = coords[ids[0]]
        rnd = asyncio.run(leader.propose(Task(id="t1", description="X")))
        rnd.metadata["pre_prepare"]["proposer"] = "r1"  # claim wrong leader
        vote = asyncio.run(coords[ids[2]].participate(rnd))
        assert vote.metadata.get("abstain") is True

    def test_commit_refuses_short_certificate(self) -> None:
        """commit() records nothing if the certificate is below quorum."""
        ids, coords = _cluster(4)
        leader = coords[ids[0]]
        rnd = asyncio.run(leader.propose(Task(id="t1", description="X")))
        asyncio.run(coords[ids[0]].participate(rnd))
        asyncio.run(coords[ids[1]].participate(rnd))
        outcome = asyncio.run(leader.resolve(rnd))  # only 2 votes -> no winner
        asyncio.run(leader.commit(outcome))
        assert leader.committed_value(0, 1) is None


# ---------------------------------------------------------------------------
# API fit
# ---------------------------------------------------------------------------


class TestApiFit:
    def test_satisfies_coordination_protocol(self) -> None:
        _, coords = _cluster(4)
        assert isinstance(next(iter(coords.values())), Coordination)

    def test_resolvable_from_registry(self) -> None:
        cls = PluginRegistry().resolve("coordination", "pbft")
        assert cls is PbftCoordination

    def test_value_is_deterministic(self) -> None:
        t = Task(id="t1", description="x")
        assert value_for_task(t) == value_for_task(t)


# ---------------------------------------------------------------------------
# View change: safe leader-failure recovery
# ---------------------------------------------------------------------------


def _prepare_value(
    ids: list[AgentId],
    coords: dict[AgentId, PbftCoordination],
    task: Task,
) -> None:
    """Drive view 0 to the point where every replica is prepared on the value.

    Example::

        _prepare_value(ids, coords, Task(id="t1", description="X"))
    """
    leader = coords[ids[0]]
    rnd = asyncio.run(leader.propose(task))
    for aid in ids:
        asyncio.run(coords[aid].participate(rnd))
    for aid in ids:
        asyncio.run(coords[aid].resolve(rnd))


class TestViewChange:
    def test_new_leader_is_bound_to_prepared_value(self) -> None:
        """The safety core: a prepared value cannot be dropped across a view change."""
        ids, coords = _cluster(4)
        _prepare_value(ids, coords, Task(id="t1", description="agree on X"))
        # Leader r0 fails; r1,r2,r3 request view change to view 1 (leader r1).
        vcs = [coords[ids[i]].request_view_change(0) for i in (1, 2, 3)]
        new_leader = coords[ids[1]]
        nv = new_leader.form_new_view(vcs)
        assert nv is not None
        assert new_leader.bound_value_for(nv, seq=1) == value_for_task(
            Task(id="t1", description="agree on X")
        )

    def test_no_prepared_value_leaves_leader_free(self) -> None:
        """If nothing was prepared, the new leader is not bound for that seq."""
        ids, coords = _cluster(4)
        vcs = [coords[ids[i]].request_view_change(0) for i in (1, 2, 3)]
        new_leader = coords[ids[1]]
        nv = new_leader.form_new_view(vcs)
        assert nv is not None
        assert new_leader.bound_value_for(nv, seq=1) is None

    def test_new_view_needs_quorum_of_view_changes(self) -> None:
        """Fewer than 2f+1 view-change messages cannot form a new-view."""
        ids, coords = _cluster(4)
        _prepare_value(ids, coords, Task(id="t1", description="X"))
        vcs = [coords[ids[i]].request_view_change(0) for i in (1, 2)]  # only 2 < 3
        assert coords[ids[1]].form_new_view(vcs) is None

    def test_forged_view_change_is_not_counted(self) -> None:
        """A view-change with a bogus signature is dropped from the quorum."""
        ids, coords = _cluster(4)
        _prepare_value(ids, coords, Task(id="t1", description="X"))
        vcs = [coords[ids[i]].request_view_change(0) for i in (1, 2)]
        # Attacker fabricates a third view-change with a garbage signature.
        forged = dict(vcs[0])
        forged["agent"] = "r3"
        forged["sig_value"] = "deadbeef"
        assert coords[ids[1]].form_new_view([*vcs, forged]) is None

    def test_only_rightful_new_leader_forms_new_view(self) -> None:
        """A replica that is not leader for the new view cannot form a new-view."""
        ids, coords = _cluster(4)
        _prepare_value(ids, coords, Task(id="t1", description="X"))
        vcs = [coords[ids[i]].request_view_change(0) for i in (1, 2, 3)]
        # r2 is not the leader for view 1 (that is r1); it must refuse.
        assert coords[ids[2]].form_new_view(vcs) is None
