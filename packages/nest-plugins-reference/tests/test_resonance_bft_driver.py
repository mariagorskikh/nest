# SPDX-License-Identifier: Apache-2.0
# pyright: reportPrivateUsage=false
"""Driver-level unit tests for the ResonanceBFT scenario agents.

The scenario driver deserialises peer messages off the transport.  A Byzantine
sender's payload is byte-XOR garbled by the simulator, so every parse site must
treat the body as untrusted: malformed input is silently dropped, never allowed
to raise out of ``on_message`` (the spec's explicit anti-pattern —
"must not deserialize garbage as a vote").  See issue LI-02.
"""

from __future__ import annotations

import asyncio
import json
import random
from typing import Any

import pytest
from nest_core.types import AgentId
from nest_plugins_reference.coordination.resonance_bft import ResonanceBFT
from nest_plugins_reference.scenarios.resonance_bft_consensus import ResonanceReplicaAgent


class FakeCtx:
    """Minimal AgentContext stub recording outbound traffic."""

    def __init__(self, agent_id: AgentId) -> None:
        self._agent_id = agent_id
        self._rng = random.Random(0)
        self.sent: list[tuple[AgentId, bytes]] = []
        self.broadcasts: list[bytes] = []

    @property
    def agent_id(self) -> AgentId:
        return self._agent_id

    @property
    def time(self) -> float:
        return 0.0

    @property
    def rng(self) -> random.Random:
        return self._rng

    @property
    def plugins(self) -> dict[str, Any]:
        return {}

    async def send(self, to: AgentId, payload: bytes) -> None:
        self.sent.append((to, payload))

    async def broadcast(self, payload: bytes) -> None:
        self.broadcasts.append(payload)

    async def schedule(self, delay: float, payload: bytes) -> None:  # pragma: no cover - unused
        pass


_GARBAGE = [
    b"\xff\x00\x9c\x01\xa7rubbish",  # invalid utf-8 / not json
    b"123",  # valid json, wrong type (not an object)
    b"not json at all",  # plain text
    b'{"aid": "f1"}',  # valid object but missing required keys
    b"",  # empty
]


_ROSTER = ["leader-0", "f1", "f2", "f3"]


def _leader_with_open_round() -> tuple[ResonanceReplicaAgent, FakeCtx]:
    """A replica that is the view-0 leader, with a proposed round open (self._round set)."""
    coord = ResonanceBFT(agent_id=AgentId("leader-0"), seed=42, expected_n=4)
    leader = ResonanceReplicaAgent(AgentId("leader-0"), coord, _ROSTER, rounds=1)
    ctx = FakeCtx(AgentId("leader-0"))
    asyncio.run(leader.on_start(ctx))  # round 1, view 0 → leader-0 proposes + seals its own eval
    return leader, ctx


def _follower(name: str = "f1") -> ResonanceReplicaAgent:
    coord = ResonanceBFT(agent_id=AgentId(name), seed=1, expected_n=4)
    return ResonanceReplicaAgent(AgentId(name), coord, _ROSTER, rounds=1)


class TestDriverDeserialisationGuards:
    @pytest.mark.parametrize("body", _GARBAGE)
    def test_leader_survives_garbled_evaluation(self, body: bytes) -> None:
        leader, _ = _leader_with_open_round()
        assert leader._round is not None
        before = dict(leader._round.metadata.get("evaluations", {}))
        ctx = FakeCtx(AgentId("leader-0"))
        # Must not raise, and must not accept the garbage as an evaluation.
        asyncio.run(leader.on_message(ctx, AgentId("f1"), b"E|" + body))
        after = leader._round.metadata.get("evaluations", {})
        assert after == before

    @pytest.mark.parametrize("body", _GARBAGE)
    def test_follower_survives_garbled_round(self, body: bytes) -> None:
        follower = _follower()
        ctx = FakeCtx(AgentId("f1"))
        asyncio.run(follower.on_message(ctx, AgentId("leader-0"), b"R|" + body))
        assert ctx.sent == []  # nothing replied to a garbled proposal

    @pytest.mark.parametrize("body", _GARBAGE)
    def test_follower_survives_garbled_outcome(self, body: bytes) -> None:
        follower = _follower()
        ctx = FakeCtx(AgentId("f1"))
        # Must not raise while applying a garbled committed outcome.
        asyncio.run(follower.on_message(ctx, AgentId("leader-0"), b"O|" + body))

    @pytest.mark.parametrize(
        "extra",
        [
            {},  # missing both aid and rec
            {"aid": "f1"},  # missing rec
            {"rec": {"semantic": [0.0]}},  # missing aid
        ],
    )
    def test_leader_drops_dict_with_valid_round_id_but_missing_keys(
        self, extra: dict[str, Any]
    ) -> None:
        """A dict that carries the correct round_id but lacks 'aid'/'rec' is still garbage:
        it must be dropped, never crash on record['aid'] / record['rec'] (LI-02 hardening)."""
        import json

        leader, _ = _leader_with_open_round()
        assert leader._round is not None
        before = dict(leader._round.metadata.get("evaluations", {}))
        body = json.dumps({"round_id": leader._round.id, **extra}).encode()
        ctx = FakeCtx(AgentId("leader-0"))
        asyncio.run(leader.on_message(ctx, AgentId("f1"), b"E|" + body))  # must not raise
        assert leader._round.metadata.get("evaluations", {}) == before

    def _submit_eval(self, leader: ResonanceReplicaAgent, sender: str, aid: Any, rec: Any) -> None:
        import json

        assert leader._round is not None
        body = json.dumps({"round_id": leader._round.id, "aid": aid, "rec": rec}).encode()
        asyncio.run(leader.on_message(FakeCtx(AgentId("leader-0")), AgentId(sender), b"E|" + body))

    def test_rejects_non_string_aid(self) -> None:
        """Review finding 1: a non-string aid becomes a dict key that resolve() later
        sorts against string aids -> TypeError crashes the whole run. It must be rejected
        so it never enters evaluations."""
        leader, _ = _leader_with_open_round()
        assert leader._round is not None
        before = dict(leader._round.metadata["evaluations"])
        self._submit_eval(leader, "f1", 42, {})
        assert leader._round.metadata["evaluations"] == before  # 42 never stored

    def test_rejects_aid_not_matching_sender(self) -> None:
        """Review finding 2: a Byzantine follower must not submit under another agent's id
        (vote overwrite / framing) — the claimed aid must equal the transport sender."""
        leader, _ = _leader_with_open_round()
        assert leader._round is not None
        self._submit_eval(leader, "f1", "f2", {"semantic": [1.0]})
        assert "f2" not in leader._round.metadata["evaluations"]

    def test_rejects_flood_of_foreign_aids(self) -> None:
        """Review finding 2: flooding fresh fake aids would inflate present/quorum_needed
        (liveness DoS). None may be accepted since none match the sender."""
        leader, _ = _leader_with_open_round()
        assert leader._round is not None
        before = len(leader._round.metadata["evaluations"])
        for i in range(50):
            self._submit_eval(leader, "f1", f"ghost{i}", {})
        assert len(leader._round.metadata["evaluations"]) == before

    @pytest.mark.parametrize("bad_rec", ["x", 123, ["a"], None, True])
    def test_rejects_non_dict_rec(self, bad_rec: Any) -> None:
        """Second-review finding A: a `rec` that is present but not a dict (authenticated
        aid, valid round_id) is stored verbatim and later crashes resolve() ->
        _reconcile_bow_semantics ('str'.get(...)), killing the whole run. Must be dropped."""
        leader, _ = _leader_with_open_round()
        assert leader._round is not None
        before = dict(leader._round.metadata["evaluations"])
        self._submit_eval(leader, "f1", "f1", bad_rec)
        assert leader._round.metadata["evaluations"] == before  # non-dict rec never stored

    def test_leader_survives_deeply_nested_json(self) -> None:
        """Second-review finding B: deeply nested JSON raises RecursionError (a RuntimeError
        subclass), not ValueError/TypeError, so the old guard let it escape on_message."""
        leader, _ = _leader_with_open_round()
        assert leader._round is not None
        body = b"E|" + b"[" * 3000 + b"]" * 3000
        # Must not raise:
        asyncio.run(leader.on_message(FakeCtx(AgentId("leader-0")), AgentId("f1"), body))

    def test_reconcile_bow_semantics_safe_on_non_dict_record(self) -> None:
        """Defense in depth for review finding A: _reconcile_bow_semantics is the first
        thing resolve() touches on the raw evaluations (before tamper exclusion), so it must
        not raise on a non-dict record even though the driver guard normally prevents one."""
        from nest_plugins_reference.coordination.resonance_bft._vectors import (
            _reconcile_bow_semantics,
        )

        evals: dict[str, Any] = {
            "bad": "not-a-dict",
            "ok": {"vocab": ["hello", "world"], "semantic": [1.0, 2.0]},
        }
        sem, _width = _reconcile_bow_semantics(evals, None)  # must not raise
        assert sem["bad"] == []  # non-dict degrades to an empty semantic vector

    def test_leader_still_accepts_a_valid_evaluation(self) -> None:
        # Guard must not break the happy path: a well-formed E| record is accepted.
        leader, _ = _leader_with_open_round()
        assert leader._round is not None
        rnd = leader._round
        follower_coord = ResonanceBFT(agent_id=AgentId("f1"), seed=1, expected_n=4)
        asyncio.run(follower_coord.participate(rnd.model_copy(deep=True)))
        # Re-participate on a fresh copy to obtain a valid sealed record for f1.
        copy = rnd.model_copy(deep=True)
        asyncio.run(follower_coord.participate(copy))
        rec: dict[str, Any] = copy.metadata["evaluations"]["f1"]
        import json

        body = json.dumps({"aid": "f1", "round_id": rnd.id, "rec": rec}).encode()
        ctx = FakeCtx(AgentId("leader-0"))
        asyncio.run(leader.on_message(ctx, AgentId("f1"), b"E|" + body))
        assert "f1" in leader._round.metadata["evaluations"]


class TestViewChangeAuthentication:
    """Crafted-message defenses on the view-change receive paths (LI-06 review findings).

    A single peer must not be able to hijack a victim's view via a forged timeout, a spoofed
    NV| announcement, an out-of-budget view jump, or a stale-round re-proposal.
    """

    def _follower_on_round1(self, name: str = "f1") -> ResonanceReplicaAgent:
        coord = ResonanceBFT(agent_id=AgentId(name), seed=1, expected_n=4)
        rep = ResonanceReplicaAgent(AgentId(name), coord, _ROSTER, rounds=1)
        asyncio.run(rep.on_start(FakeCtx(AgentId(name))))  # now on round 1, view 0
        return rep

    def test_forged_timeout_from_peer_is_ignored(self) -> None:
        rep = self._follower_on_round1()
        # A T| that arrives from another agent (not a self-schedule) must not rotate the view.
        asyncio.run(rep.on_message(FakeCtx(AgentId("f1")), AgentId("attacker"), b"T|1|0"))
        assert rep._view == 0
        # A genuine self-scheduled timeout DOES advance the view.
        asyncio.run(rep.on_message(FakeCtx(AgentId("f1")), AgentId("f1"), b"T|1|0"))
        assert rep._view == 1

    def test_spoofed_new_view_by_mismatch_is_ignored(self) -> None:
        rep = self._follower_on_round1()
        body = b"NV|" + json.dumps({"round_no": 1, "view": 9, "by": "leader-0"}).encode()
        # "by" != sender → spoofed announcement, dropped.
        asyncio.run(rep.on_message(FakeCtx(AgentId("f1")), AgentId("attacker"), body))
        assert rep._view == 0

    def test_new_view_requires_f_plus_1_distinct_senders(self) -> None:
        rep = self._follower_on_round1()  # n=4, f=1 → needs 2 distinct NV| to adopt from network

        def nv(by: str) -> bytes:
            return b"NV|" + json.dumps({"round_no": 1, "view": 2, "by": by}).encode()

        asyncio.run(rep.on_message(FakeCtx(AgentId("f1")), AgentId("f2"), nv("f2")))
        assert rep._view == 0  # a single peer cannot advance us
        asyncio.run(rep.on_message(FakeCtx(AgentId("f1")), AgentId("f3"), nv("f3")))
        assert rep._view == 2  # f+1 distinct vouchers → adopt

    def test_new_view_beyond_rotation_budget_is_ignored(self) -> None:
        rep = self._follower_on_round1()  # max_view_changes default 2n = 8
        huge = b"NV|" + json.dumps({"round_no": 1, "view": 10_000, "by": "f2"}).encode()
        asyncio.run(rep.on_message(FakeCtx(AgentId("f1")), AgentId("f2"), huge))
        assert rep._view == 0  # a huge view past the budget cannot wedge the round

    def test_round_proposal_for_wrong_round_no_is_ignored(self) -> None:
        # A stale round re-proposed by a (legitimate-for-its-view) leader must not overwrite the
        # victim's current round — bind the proposal to the receiver's round_no.
        from nest_plugins_reference.scenarios.resonance_bft_consensus import _round_task

        rep = self._follower_on_round1()  # on round 1
        assert rep._round is None
        leader_coord = ResonanceBFT(agent_id=AgentId("leader-0"), seed=0, expected_n=4)
        stale = asyncio.run(
            leader_coord.propose(_round_task(5, _ROSTER), view_number=0, all_agents=_ROSTER)
        )
        ctx = FakeCtx(AgentId("f1"))
        asyncio.run(
            rep.on_message(ctx, AgentId("leader-0"), b"R|" + stale.model_dump_json().encode())
        )
        assert rep._round is None and ctx.sent == []  # round-5 proposal dropped on a round-1 node


class TestTwoPhaseSafety:
    """LI-07: the mechanisms that make "no two honest agents commit conflicting values" hold."""

    def _follower(self, name: str = "f1") -> ResonanceReplicaAgent:
        coord = ResonanceBFT(agent_id=AgentId(name), seed=1, expected_n=4)
        rep = ResonanceReplicaAgent(AgentId(name), coord, _ROSTER, rounds=1)
        asyncio.run(rep.on_start(FakeCtx(AgentId(name))))
        return rep

    def test_honest_replica_prepare_votes_once_per_view(self) -> None:
        # An honest replica cannot be induced to prepare-vote two different winners in one view —
        # the basis of same-view agreement (two winners can't each gather 2f+1 honest votes).
        rep = self._follower()
        ctx = FakeCtx(AgentId("f1"))
        asyncio.run(rep._cast_vote(ctx, "rid", 0, "prepare", "winner-X"))
        asyncio.run(rep._cast_vote(ctx, "rid", 0, "prepare", "winner-Y"))
        prepare_votes = [p for p in ctx.broadcasts if p.startswith(b"V|")]
        assert len(prepare_votes) == 1  # the second, conflicting vote is refused

    def test_forged_vote_not_counted_toward_quorum(self) -> None:
        # The leader aggregates votes; a vote with a bad signature must not count.
        leader, _ = _leader_with_open_round()
        assert leader._round is not None
        rid, view, winner = leader._round.id, leader._view, "w"
        forged = {
            "round_no": 1,
            "view": view,
            "round_id": rid,
            "phase": "prepare",
            "winner": winner,
            "aid": "f1",
            "sig": "00" * 64,
            "pub": "aa" * 32,
        }
        ctx = FakeCtx(AgentId("leader-0"))
        asyncio.run(leader.on_message(ctx, AgentId("f1"), b"V|" + json.dumps(forged).encode()))
        assert not leader._votes.get((rid, view, "prepare", winner))  # forged vote uncounted

    def test_crafted_qc_message_cannot_poison_the_lock(self) -> None:
        """Review A1: the old design broadcast a quorum certificate a single agent could forge
        (fake aids) to poison a victim's lock forever.  Votes are now broadcast and counted
        locally, so QC| carries no authority — a crafted QC| leaves the lock untouched."""
        rep = self._follower()
        assert rep._locked_winner is None
        qc = {
            "round_no": 1,
            "view": 0,
            "round_id": "x",
            "winner": "evil",
            "votes": [{"aid": f"ghost{i}", "sig": "00" * 64, "pub": "aa" * 32} for i in range(7)],
        }
        ctx = FakeCtx(AgentId("f1"))
        asyncio.run(rep.on_message(ctx, AgentId("leader-0"), b"QC|" + json.dumps(qc).encode()))
        assert rep._locked_winner is None  # crafted QC did not lock us

    def test_vote_from_non_roster_sender_not_counted(self) -> None:
        """Review A1/A3: a vote counts only from a real roster member — a fabricated aid (even a
        self-consistently signed one) is not counted toward a quorum."""
        leader, _ = _leader_with_open_round()
        assert leader._round is not None
        rid = leader._round.id
        # sign a genuine vote but under a non-roster aid "ghost" (sender must match aid, so the
        # attacker sends as itself claiming an aid not in the roster).
        outsider = ResonanceBFT(agent_id=AgentId("ghost"), seed=99, expected_n=4)
        sig, pub = outsider.sign_vote(rid, 0, "prepare", "w")
        v = {
            "round_no": 1,
            "view": 0,
            "round_id": rid,
            "phase": "prepare",
            "winner": "w",
            "aid": "ghost",
            "sig": sig,
            "pub": pub,
        }
        ctx = FakeCtx(AgentId("leader-0"))
        asyncio.run(leader.on_message(ctx, AgentId("ghost"), b"V|" + json.dumps(v).encode()))
        assert not leader._votes.get((rid, 0, "prepare", "w"))  # non-roster vote uncounted

    def test_future_round_buffer_ignores_non_leader_and_bounds_range(self) -> None:
        """Verification-review fix: the future-round R| buffer must authenticate the sender as the
        legit leader and stay within the configured round count — a peer cannot flood it (DoS)."""
        from nest_plugins_reference.scenarios.resonance_bft_consensus import _round_task

        coord = ResonanceBFT(agent_id=AgentId("f1"), seed=1, expected_n=4)
        rep = ResonanceReplicaAgent(AgentId("f1"), coord, _ROSTER, rounds=1)  # 1 round total
        asyncio.run(rep.on_start(FakeCtx(AgentId("f1"))))  # on round 1
        leader_coord = ResonanceBFT(agent_id=AgentId("leader-0"), seed=0, expected_n=4)
        # A round beyond the configured total (99 > rounds=1), from a NON-leader → not buffered.
        r99 = asyncio.run(
            leader_coord.propose(_round_task(99, _ROSTER), view_number=0, all_agents=_ROSTER)
        )
        ctx = FakeCtx(AgentId("f1"))
        asyncio.run(rep.on_message(ctx, AgentId("f2"), b"R|" + r99.model_dump_json().encode()))
        assert rep._pending_round == {}  # non-leader / out-of-range future round not buffered
