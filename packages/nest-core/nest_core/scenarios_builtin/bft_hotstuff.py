# SPDX-License-Identifier: Apache-2.0
"""Partition-tolerant BFT consensus -- linear 2-phase HotStuff.

Every replica runs the same state machine (``ReplicaAgent``): it can
propose, vote, form Quorum Certificates, and become leader after a
view-change, since round-robin leader rotation means any replica may be
asked to lead a future view. This differs deliberately from
``nest_core.scenarios_builtin.consensus``'s fixed ``LeaderAgent``/
``FollowerAgent`` split, which never rotates leadership.

Protocol shape (2-phase, not the original 3-phase HotStuff): PREPARE then
COMMIT, each gathering its own 2f+1-vote Quorum Certificate out of 3f+1
total replicas. Safety across view-changes comes from the standard
locked-QC rule (never vote prepare for a view below what you've already
locked), not from the phase count -- the third phase in the original paper
buys cross-view pipelining/throughput, which is out of scope here.

The ``Coordination``-protocol-shaped plugin (``nest_plugins_reference.
coordination.hotstuff.HotStuff``) is a separate, non-networked conformance
wrapper -- it is not used by this factory, matching the precedent set by
``contract_net``/``consensus.py``. The real wire protocol lives entirely in
this module.

Example::

    agents = bft_hotstuff_factory(config, plugins)
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from nest_plugins_reference.coordination import hotstuff_wire
from nest_plugins_reference.coordination.hotstuff_wire import QuorumCert, VoteRecord

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId, Signature


class ReplicaAgent(StateMachineAgent):
    """Honest HotStuff replica: proposes (when leader), votes, forms QCs.

    Example::

        replica = ReplicaAgent(AgentId("replica-0"), replica_ids, f=2)
    """

    def __init__(
        self,
        agent_id: AgentId,
        replica_ids: Sequence[AgentId],
        f: int,
        view_timeout_ticks: int = 40,
    ) -> None:
        self._agent_id = agent_id
        self._replica_ids = sorted(replica_ids)
        self._f = f
        self._quorum = 2 * f + 1
        self._view_timeout_ticks = view_timeout_ticks
        self._current_view = 0
        self._locked_qc: QuorumCert | None = None
        self._voted_prepare: dict[int, str] = {}
        self._voted_commit: dict[int, str] = {}
        self._prepare_votes: dict[tuple[int, str], dict[str, str]] = {}
        self._commit_votes: dict[tuple[int, str], dict[str, str]] = {}
        self._prepare_qc_formed: set[tuple[int, str]] = set()
        self._commit_qc_formed: set[tuple[int, str]] = set()
        self._new_view_msgs: dict[int, dict[str, QuorumCert | None]] = {}
        self._proposed_for_view: set[int] = set()
        self._committed: dict[int, tuple[str, int, int]] = {}
        self._current_value_for_view: dict[int, str] = {}

    def _leader_for_view(self, view: int) -> AgentId:
        return self._replica_ids[view % len(self._replica_ids)]

    def _is_leader(self, view: int) -> bool:
        return self._leader_for_view(view) == self._agent_id

    async def on_start(self, ctx: AgentContext) -> None:
        """Schedule the view-0 timeout and propose if leading view 0.

        Example::

            await replica.on_start(ctx)
        """
        await ctx.schedule(self._view_timeout_ticks, f"view-timeout:{self._current_view}".encode())
        if self._is_leader(self._current_view):
            await self._propose(ctx, self._current_view, justify_qc=None)

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Dispatch an incoming wire message or self-scheduled timeout.

        Malformed or byzantine-garbled payloads are silently dropped --
        never raises.

        Example::

            await replica.on_message(ctx, AgentId("replica-1"), b"vote:prepare:1:abcd|sig:..")
        """
        text = payload.decode("utf-8", errors="replace")
        if text.startswith("view-timeout:"):
            await self._handle_timeout(ctx, text)
            return
        body, sig = hotstuff_wire.split_signature(text)
        if body.startswith("prepare:"):
            await self._handle_prepare(ctx, sender, body, sig)
        elif body.startswith("vote:"):
            await self._handle_vote(ctx, sender, body, sig)
        elif body.startswith("qc:"):
            await self._handle_qc(ctx, sender, body, sig)
        elif body.startswith("new-view:"):
            await self._handle_new_view(ctx, sender, body, sig)

    async def _propose(self, ctx: AgentContext, view: int, justify_qc: QuorumCert | None) -> None:
        if view in self._proposed_for_view:
            return
        self._proposed_for_view.add(view)
        value = str(ctx.rng.randint(1, 100))
        self._current_value_for_view[view] = value
        body = hotstuff_wire.encode_prepare(view, value, justify_qc)
        await self._send_signed(ctx, body, self._replica_ids)

    async def _send_signed(
        self, ctx: AgentContext, body: bytes, recipients: Sequence[AgentId]
    ) -> None:
        identity = ctx.plugins.get("identity")
        sig_hex = identity.sign(body).value.hex() if identity is not None else ""
        wire = hotstuff_wire.with_signature(body, sig_hex)
        for rid in recipients:
            await ctx.send(rid, wire)

    def _verify(
        self, ctx: AgentContext, claimed_signer: AgentId, body: str, sig: bytes | None
    ) -> bool:
        if sig is None:
            return False
        identity = ctx.plugins.get("identity")
        if identity is None:
            return False
        signature = Signature(signer=claimed_signer, value=sig, algorithm="sim-rsa-sha256")
        return bool(identity.verify(body.encode(), signature, claimed_signer))

    def _qc_is_valid(self, ctx: AgentContext, qc: QuorumCert) -> bool:
        required = 2 * self._f + 1
        seen: set[str] = set()
        valid = 0
        payload = hotstuff_wire.encode_vote(qc.phase, qc.view, qc.block_hash).decode()
        for vote in qc.votes:
            if vote.voter in seen:
                continue
            seen.add(vote.voter)
            try:
                sig_bytes = bytes.fromhex(vote.signature_hex)
            except ValueError:
                continue
            if self._verify(ctx, AgentId(vote.voter), payload, sig_bytes):
                valid += 1
        return valid >= required

    async def _handle_timeout(self, ctx: AgentContext, text: str) -> None:
        try:
            view = int(text.split(":", 1)[1])
        except (IndexError, ValueError):
            return
        if view != self._current_view or view in self._committed:
            return
        await self._advance_view(ctx)

    async def _advance_view(self, ctx: AgentContext) -> None:
        new_view = self._current_view + 1
        self._current_view = new_view
        body = hotstuff_wire.encode_new_view(new_view, self._locked_qc)
        leader = self._leader_for_view(new_view)
        await self._send_signed(ctx, body, [leader])
        await ctx.schedule(self._view_timeout_ticks, f"view-timeout:{new_view}".encode())

    async def _handle_prepare(
        self, ctx: AgentContext, sender: AgentId, body: str, sig: bytes | None
    ) -> None:
        msg = hotstuff_wire.decode_prepare(body)
        if msg is None or not self._verify(ctx, sender, body, sig):
            return
        if sender != self._leader_for_view(msg.view) or msg.view < self._current_view:
            return
        if msg.justify_qc is not None and not self._qc_is_valid(ctx, msg.justify_qc):
            return
        if (
            self._locked_qc is not None
            and msg.justify_qc is not None
            and msg.justify_qc.view < self._locked_qc.view
        ):
            return
        if msg.view > self._current_view:
            self._current_view = msg.view
            await ctx.schedule(self._view_timeout_ticks, f"view-timeout:{msg.view}".encode())
        if self._voted_prepare.get(msg.view) is not None:
            return
        self._voted_prepare[msg.view] = msg.block_hash
        self._current_value_for_view[msg.view] = msg.value
        vote_body = hotstuff_wire.encode_vote("prepare", msg.view, msg.block_hash)
        await self._send_signed(ctx, vote_body, [sender])

    async def _handle_vote(
        self, ctx: AgentContext, sender: AgentId, body: str, sig: bytes | None
    ) -> None:
        msg = hotstuff_wire.decode_vote(body)
        if msg is None or sig is None or not self._verify(ctx, sender, body, sig):
            return
        if not self._is_leader(msg.view):
            return
        key = (msg.view, msg.block_hash)
        bucket = self._prepare_votes if msg.phase == "prepare" else self._commit_votes
        votes = bucket.setdefault(key, {})
        votes[str(sender)] = sig.hex()
        if len(votes) < self._quorum:
            return
        formed = self._prepare_qc_formed if msg.phase == "prepare" else self._commit_qc_formed
        if key in formed:
            return
        formed.add(key)
        records = tuple(VoteRecord(voter=v, signature_hex=s) for v, s in votes.items())
        qc_body = hotstuff_wire.encode_qc_broadcast(
            msg.phase, msg.view, msg.block_hash, self._f, records
        )
        await self._send_signed(ctx, qc_body, self._replica_ids)

    async def _handle_qc(
        self, ctx: AgentContext, sender: AgentId, body: str, sig: bytes | None
    ) -> None:
        msg = hotstuff_wire.decode_qc_broadcast(body)
        if msg is None or not self._verify(ctx, sender, body, sig):
            return
        if sender != self._leader_for_view(msg.view) or msg.f != self._f:
            return
        qc = QuorumCert(phase=msg.phase, view=msg.view, block_hash=msg.block_hash, votes=msg.votes)
        if not self._qc_is_valid(ctx, qc):
            return
        if msg.phase == "prepare":
            await self._on_prepare_qc_received(ctx, qc)
        else:
            await self._on_commit_qc_received(ctx, qc)

    async def _on_prepare_qc_received(self, ctx: AgentContext, qc: QuorumCert) -> None:
        if self._locked_qc is None or qc.view >= self._locked_qc.view:
            self._locked_qc = qc
        if self._voted_commit.get(qc.view) is not None:
            return
        self._voted_commit[qc.view] = qc.block_hash
        vote_body = hotstuff_wire.encode_vote("commit", qc.view, qc.block_hash)
        await self._send_signed(ctx, vote_body, [self._leader_for_view(qc.view)])

    async def _on_commit_qc_received(self, ctx: AgentContext, qc: QuorumCert) -> None:
        if qc.view not in self._committed:
            value = self._current_value_for_view.get(qc.view, "")
            accepts = len(qc.votes)
            total = len(self._replica_ids)
            self._committed[qc.view] = (value, accepts, total)
            result_body = hotstuff_wire.encode_result(qc.view, qc.block_hash, accepts, total, value)
            await self._send_signed(ctx, result_body, self._replica_ids)
        next_view = qc.view + 1
        if next_view > self._current_view:
            self._current_view = next_view
            await ctx.schedule(self._view_timeout_ticks, f"view-timeout:{next_view}".encode())
        if self._is_leader(next_view):
            await self._propose(ctx, next_view, justify_qc=qc)

    async def _handle_new_view(
        self, ctx: AgentContext, sender: AgentId, body: str, sig: bytes | None
    ) -> None:
        msg = hotstuff_wire.decode_new_view(body)
        if msg is None or not self._verify(ctx, sender, body, sig):
            return
        if msg.highest_qc is not None and not self._qc_is_valid(ctx, msg.highest_qc):
            return
        if not self._is_leader(msg.view):
            return
        bucket = self._new_view_msgs.setdefault(msg.view, {})
        bucket[str(sender)] = msg.highest_qc
        if len(bucket) < self._quorum or msg.view in self._proposed_for_view:
            return
        highest: QuorumCert | None = None
        for qc in bucket.values():
            if qc is not None and (highest is None or qc.view > highest.view):
                highest = qc
        if self._current_view < msg.view:
            self._current_view = msg.view
            await ctx.schedule(self._view_timeout_ticks, f"view-timeout:{msg.view}".encode())
        await self._propose(ctx, msg.view, justify_qc=highest)


class MaliciousLeaderAgent(ReplicaAgent):
    """A replica that equivocates only on its own leader turns.

    When this replica is leader for a view, it sends two different PREPARE
    proposals (different value, different block hash) to disjoint halves of
    the replica set -- the literal "leader sending different proposals to
    different followers" failure mode the hackathon's equivocation
    validator must catch. Outside of its own leader turns it behaves like
    an honest ``ReplicaAgent``: voting, forming QCs, and view-changing
    normally, so the scenario exercises exactly one failure mode at a time.

    Example::

        leader = MaliciousLeaderAgent(AgentId("replica-1"), replica_ids, f=2)
    """

    async def _propose(self, ctx: AgentContext, view: int, justify_qc: QuorumCert | None) -> None:
        if view in self._proposed_for_view:
            return
        self._proposed_for_view.add(view)
        half = len(self._replica_ids) // 2
        group_a = self._replica_ids[:half] or list(self._replica_ids)
        group_b = self._replica_ids[half:] or list(self._replica_ids)
        value_a = str(ctx.rng.randint(1, 100))
        value_b = str(ctx.rng.randint(101, 200))
        self._current_value_for_view[view] = value_a
        body_a = hotstuff_wire.encode_prepare(view, value_a, justify_qc)
        body_b = hotstuff_wire.encode_prepare(view, value_b, justify_qc)
        await self._send_signed(ctx, body_a, group_a)
        await self._send_signed(ctx, body_b, group_b)


def instantiate_identity(plugins: dict[str, Any], all_ids: Sequence[AgentId]) -> None:
    """Wire a per-agent signed ``DidKeyIdentity`` with full peer cross-registration.

    Mirrors ``nest_core.scenarios_builtin.marketplace``'s identity-wiring
    block: every replica must sign its own votes/proposals and verify every
    peer's signatures, so each gets its own identity instance with all
    peers registered, stored under ``plugins["_agent_plugins"]`` for the
    runner to apply as a per-agent override.

    Example::

        instantiate_identity(plugins, [AgentId("replica-0"), AgentId("replica-1")])
    """
    identity_cls = plugins.get("identity")
    if identity_cls is None or not isinstance(identity_cls, type):
        return
    agent_plugins: dict[AgentId, dict[str, Any]] = plugins.setdefault("_agent_plugins", {})
    identities: dict[AgentId, Any] = {aid: identity_cls(aid, seed=b"sim-seed") for aid in all_ids}
    for aid, ident in identities.items():
        for peer_id, peer_ident in identities.items():
            if peer_id != aid:
                ident.register_peer(peer_id, peer_ident.public_key)
    for aid, ident in identities.items():
        agent_plugins.setdefault(aid, {})["identity"] = ident
    plugins.pop("identity", None)


def bft_hotstuff_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create HotStuff replica agents and wire per-agent signed identities.

    Reads ``task.config.f`` (defaults to ``(count - 1) // 3``),
    ``task.config.view_timeout_ticks`` (default 40), and
    ``task.config.malicious_agents`` (a list of replica id strings to
    instantiate as ``MaliciousLeaderAgent`` instead of ``ReplicaAgent``).

    Example::

        agents = bft_hotstuff_factory(config, plugins)
    """
    task_config = config.task.config
    count = config.agents.count
    f = int(task_config.get("f", (count - 1) // 3))
    view_timeout_ticks = int(task_config.get("view_timeout_ticks", 40))
    malicious_names: set[str] = set(task_config.get("malicious_agents", []))

    replica_ids = [AgentId(f"replica-{i}") for i in range(count)]
    instantiate_identity(plugins, replica_ids)

    agents: dict[AgentId, StateMachineAgent] = {}
    for rid in replica_ids:
        if str(rid) in malicious_names:
            agents[rid] = MaliciousLeaderAgent(
                rid, replica_ids, f=f, view_timeout_ticks=view_timeout_ticks
            )
        else:
            agents[rid] = ReplicaAgent(rid, replica_ids, f=f, view_timeout_ticks=view_timeout_ticks)
    return agents
