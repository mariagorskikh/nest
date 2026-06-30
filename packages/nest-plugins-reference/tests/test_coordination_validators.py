# SPDX-License-Identifier: Apache-2.0
"""Tests for the four adversarial coordination validators.

Persona note (distributed-systems engineer): a validator that only passes clean
traces is worthless — the whole point is catching the attack. So every check is
tested in both directions: it must PASS an honest trace and FAIL a byzantine one.
The honest records are produced by the real PBFT plugin; the byzantine ones are
hand-forged to model a specific attack.
"""

from __future__ import annotations

import asyncio

from nest_core.types import AgentId, Task
from nest_plugins_reference.coordination.pbft import (
    PbftCoordination,
    SignedVote,
)
from nest_plugins_reference.identity.did_key import DidKeyIdentity
from nest_plugins_reference.validators.coordination_validators import (
    check_no_conflicting_commits,
    check_no_equivocation,
    check_no_forged_quorum,
    check_no_stuck_view,
    validate_coordination,
)


def _cluster(n: int = 4):
    ids = [AgentId(f"r{i}") for i in range(n)]
    idents = {aid: DidKeyIdentity(aid, seed=f"seed{i}".encode()) for i, aid in enumerate(ids)}
    for a in ids:
        for b in ids:
            if a != b:
                idents[a].register_peer(b, idents[b].public_key)
    coords = {aid: PbftCoordination(aid, identity=idents[aid], n=n, replicas=ids) for aid in ids}
    return ids, idents, coords


def _honest_trace(ids, coords):
    """Run one honest round; return (commit_records, vote_records)."""
    leader = coords[ids[0]]
    rnd = asyncio.run(leader.propose(Task(id="t1", description="agree on X")))
    for aid in ids:
        asyncio.run(coords[aid].participate(rnd))
    commits = []
    for aid in ids:
        outcome = asyncio.run(coords[aid].resolve(rnd))
        asyncio.run(coords[aid].commit(outcome))
        meta = outcome.metadata
        if meta["committed_value"] is not None:
            commits.append(
                {
                    "agent": str(aid),
                    "view": meta["view"],
                    "seq": meta["seq"],
                    "value": meta["committed_value"],
                    "certificate": meta["certificate"],
                }
            )
    votes = list(rnd.metadata["votes"])
    return commits, votes


def _verify_fn(idents):
    """Build a verify_fn closure over the cluster's identities."""

    def verify(payload: bytes, sv: SignedVote) -> bool:
        # Any identity can verify since all peers are registered everywhere.
        any_ident = next(iter(idents.values()))
        return bool(any_ident.verify(payload, sv.signature, sv.voter))

    return verify


# ---------------------------------------------------------------------------
# 1. Conflicting commits
# ---------------------------------------------------------------------------


class TestConflictingCommits:
    def test_passes_honest(self) -> None:
        ids, _, coords = _cluster(4)
        commits, _ = _honest_trace(ids, coords)
        assert check_no_conflicting_commits(commits).passed

    def test_catches_conflict(self) -> None:
        commits = [
            {"agent": "r0", "view": 0, "seq": 1, "value": "X", "certificate": []},
            {"agent": "r1", "view": 0, "seq": 1, "value": "Y", "certificate": []},
        ]
        assert not check_no_conflicting_commits(commits).passed


# ---------------------------------------------------------------------------
# 2. Forged quorum
# ---------------------------------------------------------------------------


class TestForgedQuorum:
    def test_passes_honest(self) -> None:
        ids, idents, coords = _cluster(4)
        commits, _ = _honest_trace(ids, coords)
        assert check_no_forged_quorum(commits, _verify_fn(idents), n=4).passed

    def test_catches_short_certificate(self) -> None:
        ids, idents, coords = _cluster(4)
        commits, _ = _honest_trace(ids, coords)
        # Truncate the certificate below quorum.
        commits[0]["certificate"] = commits[0]["certificate"][:2]
        assert not check_no_forged_quorum(commits, _verify_fn(idents), n=4).passed

    def test_catches_garbage_signature(self) -> None:
        ids, idents, coords = _cluster(4)
        commits, _ = _honest_trace(ids, coords)
        # Replace one signature with garbage; it should fail verification and
        # drop the certificate below quorum.
        commits[0]["certificate"] = [
            dict(v, sig_value="deadbeef") for v in commits[0]["certificate"]
        ]
        assert not check_no_forged_quorum(commits, _verify_fn(idents), n=4).passed


# ---------------------------------------------------------------------------
# 3. Equivocation
# ---------------------------------------------------------------------------


class TestEquivocation:
    def test_passes_honest(self) -> None:
        ids, _, coords = _cluster(4)
        _, votes = _honest_trace(ids, coords)
        assert check_no_equivocation(votes).passed

    def test_catches_double_vote(self) -> None:
        votes = [
            {"voter": "r2", "view": 0, "seq": 1, "phase": "prepare", "value": "X"},
            {"voter": "r2", "view": 0, "seq": 1, "phase": "prepare", "value": "Y"},
        ]
        assert not check_no_equivocation(votes).passed

    def test_same_value_twice_is_fine(self) -> None:
        votes = [
            {"voter": "r2", "view": 0, "seq": 1, "phase": "prepare", "value": "X"},
            {"voter": "r2", "view": 0, "seq": 1, "phase": "prepare", "value": "X"},
        ]
        assert check_no_equivocation(votes).passed


# ---------------------------------------------------------------------------
# 4. Stuck view
# ---------------------------------------------------------------------------


class TestStuckView:
    def test_passes_with_commits(self) -> None:
        commits = [{"agent": "r0", "view": 0, "seq": 1, "value": "X", "certificate": []}]
        assert check_no_stuck_view(commits, rounds_attempted=1).passed

    def test_passes_with_view_change(self) -> None:
        assert check_no_stuck_view([], rounds_attempted=2, view_changes=1).passed

    def test_catches_stall(self) -> None:
        assert not check_no_stuck_view([], rounds_attempted=5, view_changes=0).passed

    def test_no_rounds_is_vacuously_fine(self) -> None:
        assert check_no_stuck_view([], rounds_attempted=0).passed


# ---------------------------------------------------------------------------
# Suite
# ---------------------------------------------------------------------------


class TestSuite:
    def test_all_pass_on_honest_run(self) -> None:
        ids, idents, coords = _cluster(4)
        commits, votes = _honest_trace(ids, coords)
        reports = validate_coordination(commits, votes, _verify_fn(idents), n=4, rounds_attempted=1)
        assert all(r.passed for r in reports), [r.detail for r in reports if not r.passed]
