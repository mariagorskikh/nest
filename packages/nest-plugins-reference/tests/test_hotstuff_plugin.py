# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the HotStuff coordination plugin, wire format, and agents."""

from __future__ import annotations

import random
from typing import Any

import pytest
from nest_core.scenarios_builtin.bft_hotstuff import (
    MaliciousLeaderAgent,
    ReplicaAgent,
    instantiate_identity,
)
from nest_core.types import AgentId, Task
from nest_plugins_reference.coordination import hotstuff_wire
from nest_plugins_reference.coordination.hotstuff import HotStuff
from nest_plugins_reference.coordination.hotstuff_wire import QuorumCert, VoteRecord
from nest_plugins_reference.identity.did_key import DidKeyIdentity


class _FakeAgentContext:
    """Minimal stand-in for the simulator's AgentContext, for direct unit tests."""

    def __init__(self, agent_id: AgentId, plugins: dict[str, Any]) -> None:
        self.agent_id = agent_id
        self.time = 0.0
        self.rng = random.Random(1)
        self.plugins = plugins
        self.sent: list[tuple[AgentId, bytes]] = []

    async def send(self, to: AgentId, payload: bytes) -> None:
        self.sent.append((to, payload))

    async def broadcast(self, payload: bytes) -> None:
        self.sent.append((AgentId("*"), payload))

    async def schedule(self, delay: float, payload: bytes) -> None:
        self.sent.append((AgentId(f"self-after-{delay}"), payload))


def _make_identities(replica_ids: list[AgentId]) -> dict[AgentId, DidKeyIdentity]:
    plugins: dict[str, Any] = {"identity": DidKeyIdentity}
    instantiate_identity(plugins, replica_ids)
    agent_plugins: dict[AgentId, dict[str, Any]] = plugins.pop("_agent_plugins")
    return {rid: agent_plugins[rid]["identity"] for rid in replica_ids}


# ---------------------------------------------------------------------------
# Coordination-protocol conformance wrapper
# ---------------------------------------------------------------------------


class TestHotStuffCoordinationWrapper:
    @pytest.mark.asyncio
    async def test_propose_participate_resolve_commit(self) -> None:
        leader = HotStuff(AgentId("r0"), f=1)
        replica1 = HotStuff(AgentId("r1"), f=1)
        replica2 = HotStuff(AgentId("r2"), f=1)

        task = Task(id="t1", description="agree on a value")
        rnd = await leader.propose(task)

        await leader.participate(rnd)
        await replica1.participate(rnd)
        await replica2.participate(rnd)

        outcome = await leader.resolve(rnd)
        assert outcome.task.id == "t1"
        assert outcome.winner == AgentId("r0")
        await leader.commit(outcome)

    @pytest.mark.asyncio
    async def test_resolve_below_quorum_has_no_winner(self) -> None:
        leader = HotStuff(AgentId("r0"), f=2)
        task = Task(id="t1", description="agree")
        rnd = await leader.propose(task)
        await leader.participate(rnd)

        outcome = await leader.resolve(rnd)
        assert outcome.winner is None


# ---------------------------------------------------------------------------
# Wire format: round-trip and malformed-input handling
# ---------------------------------------------------------------------------


class TestHotStuffWireFormat:
    def test_vote_round_trip(self) -> None:
        h = hotstuff_wire.block_hash(3, "42")
        body = hotstuff_wire.encode_vote("prepare", 3, h)
        msg = hotstuff_wire.decode_vote(body.decode())
        assert msg is not None
        assert msg.phase == "prepare"
        assert msg.view == 3
        assert msg.block_hash == h

    def test_prepare_round_trip_no_qc(self) -> None:
        body = hotstuff_wire.encode_prepare(1, "42", None)
        msg = hotstuff_wire.decode_prepare(body.decode())
        assert msg is not None
        assert msg.view == 1
        assert msg.value == "42"
        assert msg.justify_qc is None

    def test_prepare_round_trip_with_inline_qc(self) -> None:
        qc = QuorumCert(
            phase="prepare",
            view=1,
            block_hash="abcd",
            votes=(VoteRecord(voter="r0", signature_hex="a1b2"),),
        )
        body = hotstuff_wire.encode_prepare(2, "99", qc)
        msg = hotstuff_wire.decode_prepare(body.decode())
        assert msg is not None
        assert msg.justify_qc is not None
        assert msg.justify_qc.view == 1
        assert msg.justify_qc.votes == (VoteRecord(voter="r0", signature_hex="a1b2"),)

    def test_qc_broadcast_round_trip(self) -> None:
        votes = [VoteRecord(voter=f"r{i}", signature_hex=f"sig{i}") for i in range(3)]
        body = hotstuff_wire.encode_qc_broadcast("commit", 4, "deadbeef", 1, votes)
        msg = hotstuff_wire.decode_qc_broadcast(body.decode())
        assert msg is not None
        assert msg.phase == "commit"
        assert msg.f == 1
        assert set(msg.votes) == set(votes)

    def test_new_view_round_trip(self) -> None:
        body = hotstuff_wire.encode_new_view(5, None)
        msg = hotstuff_wire.decode_new_view(body.decode())
        assert msg is not None
        assert msg.view == 5
        assert msg.highest_qc is None

    def test_signature_split_round_trip(self) -> None:
        wire = hotstuff_wire.with_signature(b"vote:prepare:1:abcd", "a1b2c3")
        body, sig = hotstuff_wire.split_signature(wire.decode())
        assert body == "vote:prepare:1:abcd"
        assert sig == bytes.fromhex("a1b2c3")

    def test_signature_split_missing_suffix(self) -> None:
        body, sig = hotstuff_wire.split_signature("vote:prepare:1:abcd")
        assert body == "vote:prepare:1:abcd"
        assert sig is None

    @pytest.mark.parametrize(
        "garbage",
        [
            "",
            "not-a-hotstuff-message",
            "prepare:notanint:abcd:42:none",
            "prepare:1:abcd:42",
            "vote:prepare:notanint:abcd",
            "vote:bogus-phase:1:abcd",
            "qc:prepare:1:abcd:notanint:r0=ab",
            "qc:prepare:1:abcd:1:r0",
            "new-view:notanint:none",
        ],
    )
    def test_decoders_never_raise_on_malformed_input(self, garbage: str) -> None:
        assert hotstuff_wire.decode_prepare(garbage) is None
        assert hotstuff_wire.decode_vote(garbage) is None
        assert hotstuff_wire.decode_qc_broadcast(garbage) is None
        assert hotstuff_wire.decode_new_view(garbage) is None


# ---------------------------------------------------------------------------
# ReplicaAgent: QC formation, idempotency, view-change
# ---------------------------------------------------------------------------


class TestReplicaAgentQcFormation:
    @pytest.mark.asyncio
    async def test_leader_forms_prepare_qc_at_threshold_not_before(self) -> None:
        replica_ids = [AgentId(f"replica-{i}") for i in range(4)]  # f=1, quorum=3
        identities = _make_identities(replica_ids)
        leader_id = replica_ids[0]  # leader_for_view(0)
        leader = ReplicaAgent(leader_id, replica_ids, f=1, view_timeout_ticks=1000)
        ctx = _FakeAgentContext(leader_id, {"identity": identities[leader_id]})

        await leader.on_start(ctx)
        prepare_wire = next(payload for to, payload in ctx.sent if to == leader_id)
        body, _sig = hotstuff_wire.split_signature(prepare_wire.decode())
        prepare = hotstuff_wire.decode_prepare(body)
        assert prepare is not None

        def qc_count() -> int:
            return sum(1 for _to, p in ctx.sent if p.decode().startswith("qc:prepare:"))

        for i in range(2):
            voter = replica_ids[i + 1]
            vote_body = hotstuff_wire.encode_vote("prepare", 0, prepare.block_hash)
            sig_hex = identities[voter].sign(vote_body).value.hex()
            wire = hotstuff_wire.with_signature(vote_body, sig_hex)
            await leader.on_message(ctx, voter, wire)

        assert qc_count() == 0, "QC must not form below the 2f+1 threshold"

        voter = replica_ids[3]
        vote_body = hotstuff_wire.encode_vote("prepare", 0, prepare.block_hash)
        sig_hex = identities[voter].sign(vote_body).value.hex()
        wire = hotstuff_wire.with_signature(vote_body, sig_hex)
        await leader.on_message(ctx, voter, wire)

        count_at_threshold = qc_count()
        assert count_at_threshold == len(replica_ids), "QC must form exactly at the 2f+1 threshold"

        # A duplicate/late vote must not form a second QC (one broadcast per recipient, not two).
        await leader.on_message(ctx, voter, wire)
        assert qc_count() == count_at_threshold, "Re-delivering a vote must not double-form a QC"

    @pytest.mark.asyncio
    async def test_leader_rejects_unsigned_vote(self) -> None:
        replica_ids = [AgentId(f"replica-{i}") for i in range(4)]
        identities = _make_identities(replica_ids)
        leader_id = replica_ids[0]
        leader = ReplicaAgent(leader_id, replica_ids, f=1, view_timeout_ticks=1000)
        ctx = _FakeAgentContext(leader_id, {"identity": identities[leader_id]})
        await leader.on_start(ctx)

        unsigned = hotstuff_wire.encode_vote("prepare", 0, hotstuff_wire.block_hash(0, "1"))
        await leader.on_message(ctx, replica_ids[1], unsigned)

        assert not any(p.decode().startswith("qc:") for _to, p in ctx.sent)

    @pytest.mark.asyncio
    async def test_garbled_payload_is_silently_dropped(self) -> None:
        replica_ids = [AgentId(f"replica-{i}") for i in range(4)]
        identities = _make_identities(replica_ids)
        leader_id = replica_ids[0]
        leader = ReplicaAgent(leader_id, replica_ids, f=1, view_timeout_ticks=1000)
        ctx = _FakeAgentContext(leader_id, {"identity": identities[leader_id]})

        garbage = bytes(b ^ 0xFF for b in b"prepare:0:abcd:42:none|sig:deadbeef")
        await leader.on_message(ctx, replica_ids[1], garbage)  # must not raise


# ---------------------------------------------------------------------------
# MaliciousLeaderAgent: equivocation
# ---------------------------------------------------------------------------


class TestMaliciousLeaderEquivocates:
    @pytest.mark.asyncio
    async def test_sends_two_distinct_proposals_to_disjoint_groups(self) -> None:
        replica_ids = [AgentId(f"replica-{i}") for i in range(4)]
        identities = _make_identities(replica_ids)
        leader_id = replica_ids[0]
        leader = MaliciousLeaderAgent(leader_id, replica_ids, f=1, view_timeout_ticks=1000)
        ctx = _FakeAgentContext(leader_id, {"identity": identities[leader_id]})

        await leader.on_start(ctx)

        prepares = [
            hotstuff_wire.decode_prepare(hotstuff_wire.split_signature(p.decode())[0])
            for _to, p in ctx.sent
            if p.decode().startswith("prepare:")
        ]
        block_hashes = {p.block_hash for p in prepares if p is not None}
        assert len(block_hashes) == 2, "the malicious leader must equivocate on its own turn"
