# SPDX-License-Identifier: Apache-2.0
"""PBFT coordination plugin — Castro-Liskov Byzantine fault-tolerant consensus.

Persona note (distributed-systems engineer): the property I am paid to defend is
*agreement under a lying minority* — with up to ``f`` byzantine replicas out of
``3f+1``, no two honest replicas commit different values for the same slot. The
default :class:`~nest_plugins_reference.coordination.contract_net.ContractNet`
is a single-round bid; it has no quorum, no signatures, and no notion of a
conflicting commit, so it cannot even represent the failure I care about.

This module implements the **happy-path** core of PBFT: the three-phase
pre-prepare / prepare / commit pipeline, gated by ``2f+1`` quorums of
*signed* votes. View-change (leader failure recovery) is intentionally deferred
to a later iteration; what ships here is the agreement core and its quorum
certificates, which the existing ``consensus`` scenario can drive.

The safety argument, in one sentence: any two quorums of ``2f+1`` out of
``3f+1`` replicas intersect in at least one honest replica, and an honest
replica signs only one value per ``(view, seq)`` slot — so two conflicting
commit certificates cannot both exist.

Votes are signed with the identity layer (``did_key``). An unsigned vote is
worthless here: a byzantine agent could otherwise fabricate "replica 3 voted V"
out of thin air. A quorum certificate is therefore a *set of signatures from
distinct agents*, each verifiable against that agent's public key.

Example::

    leader = PbftCoordination(AgentId("r0"), identity=id0, n=4)
    rnd = await leader.propose(Task(id="t1", description="agree on X"))
    vote = await replica.participate(rnd)
    outcome = await leader.resolve(rnd)
    await leader.commit(outcome)
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from nest_core.types import (
    AgentId,
    Outcome,
    Round,
    Signature,
    Task,
    Vote,
)

#: Phase tags. ``prepare`` and ``commit`` are the two voting phases; the
#: happy-path engine collects both kinds of signed vote into the Round.
PHASE_PRE_PREPARE = "pre-prepare"
PHASE_PREPARE = "prepare"
PHASE_COMMIT = "commit"
PHASE_VIEW_CHANGE = "view-change"
PHASE_NEW_VIEW = "new-view"


def quorum_size(n: int) -> int:
    """Return the PBFT quorum threshold ``2f+1`` for ``n = 3f+1`` replicas.

    With ``f = (n - 1) // 3`` byzantine tolerance, a quorum is ``2f + 1``. Any
    two such quorums intersect in at least one honest replica — the core of the
    safety argument.

    Example::

        quorum_size(4)  # f=1 -> 3
        quorum_size(7)  # f=2 -> 5
    """
    f = (n - 1) // 3
    return 2 * f + 1


def fault_tolerance(n: int) -> int:
    """Return ``f``, the number of byzantine replicas tolerated for ``n`` total.

    Example::

        fault_tolerance(4)  # -> 1
        fault_tolerance(7)  # -> 2
    """
    return (n - 1) // 3


def leader_for_view(view: int, n: int) -> int:
    """Return the index of the leader (primary) for ``view``, round-robin.

    Example::

        leader_for_view(0, 4)  # -> 0
        leader_for_view(5, 4)  # -> 1
    """
    return view % n


def signing_payload(view: int, seq: int, phase: str, value: str) -> bytes:
    """Canonical bytes a vote signature is computed over.

    Binding all four fields means a signature for ``(v, n, prepare, V)`` cannot
    be replayed as a vote for a different view, sequence, phase, or value.

    Example::

        signing_payload(0, 1, "prepare", "X")
    """
    return json.dumps(
        {"view": view, "seq": seq, "phase": phase, "value": value},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def view_change_payload(
    new_view: int, agent: AgentId, prepared: dict[int, dict[str, Any]]
) -> bytes:
    """Canonical bytes a view-change message is signed over.

    Binds the target ``new_view``, the requesting ``agent``, and a digest of the
    agent's prepared set, so a view-change vote cannot be forged for another
    agent or replayed for a different view.

    Example::

        view_change_payload(1, AgentId("r1"), {1: {"view": 0, "value": "X"}})
    """
    digest = sorted((seq, str(p["view"]), str(p["value"])) for seq, p in prepared.items())
    return json.dumps(
        {"new_view": new_view, "agent": str(agent), "prepared": digest},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


@dataclass(frozen=True)
class SignedVote:
    """A single replica's signed vote in one phase of one slot.

    Example::

        sv = SignedVote(voter=AgentId("r1"), view=0, seq=1, phase="prepare",
                        value="X", signature=sig)
    """

    voter: AgentId
    view: int
    seq: int
    phase: str
    value: str
    signature: Signature

    def to_metadata(self) -> dict[str, Any]:
        """Serialize to a JSON-friendly dict for storage in ``round.metadata``.

        Example::

            round.metadata["votes"].append(sv.to_metadata())
        """
        return {
            "voter": str(self.voter),
            "view": self.view,
            "seq": self.seq,
            "phase": self.phase,
            "value": self.value,
            "sig_value": self.signature.value.hex(),
            "sig_algorithm": self.signature.algorithm,
        }

    @classmethod
    def from_metadata(cls, data: dict[str, Any]) -> SignedVote:
        """Rebuild a :class:`SignedVote` from its stored metadata dict.

        Example::

            sv = SignedVote.from_metadata(round.metadata["votes"][0])
        """
        return cls(
            voter=AgentId(str(data["voter"])),
            view=int(data["view"]),
            seq=int(data["seq"]),
            phase=str(data["phase"]),
            value=str(data["value"]),
            signature=Signature(
                signer=AgentId(str(data["voter"])),
                value=bytes.fromhex(str(data["sig_value"])),
                algorithm=str(data["sig_algorithm"]),
            ),
        )


def value_for_task(task: Task) -> str:
    """Derive the deterministic value the replicas agree on from a task.

    The task *is* the client request in this rig; agreeing on a stable digest
    of it keeps the trace byte-identical across runs with the same seed.

    Example::

        value_for_task(Task(id="t1", description="x"))  # -> "t1:x"
    """
    return f"{task.id}:{task.description}"


class PbftCoordination:
    """Castro-Liskov PBFT coordination (happy-path core).

    One instance per agent. ``identity`` is the agent's ``did_key`` plugin, used
    to sign its own votes and verify peers'. ``n`` is the total replica count
    (``3f+1``); the quorum ``2f+1`` is derived from it.

    Example::

        coord = PbftCoordination(AgentId("r0"), identity=id0, n=4)
        rnd = await coord.propose(Task(id="t1", description="agree on X"))
    """

    def __init__(
        self,
        agent_id: AgentId,
        identity: Any = None,
        n: int = 4,
        view: int = 0,
        replicas: list[AgentId] | None = None,
    ) -> None:
        self._agent_id = agent_id
        self._identity = identity
        self._n = n
        self._view = view
        self._seq = 0
        self._replicas = sorted(replicas) if replicas else []
        # Committed certificates, keyed by (view, seq), recorded at commit time.
        self._committed: dict[tuple[int, int], list[dict[str, Any]]] = {}
        # Highest prepared value per seq: seq -> (view, value, prepare-proof).
        # A replica is "prepared" once it has seen a 2f+1 prepare-quorum; this is
        # the evidence it carries into a view-change so a committed value can't
        # be dropped by the next leader.
        self._prepared: dict[int, dict[str, Any]] = {}

    async def propose(self, task: Task) -> Round:
        """Leader pre-prepare: fix the slot, choose the value, sign, broadcast.

        Creates the Round that carries the protocol state between agents. The
        signed pre-prepare is written to ``round.metadata["pre_prepare"]`` so
        every replica can verify it came from the rightful leader for this view.

        Example::

            rnd = await coord.propose(Task(id="t1", description="x"))
        """
        self._seq += 1
        seq = self._seq
        value = value_for_task(task)
        payload = signing_payload(self._view, seq, PHASE_PRE_PREPARE, value)
        signature = self._identity.sign(payload)

        rnd = Round(
            id=f"v{self._view}-n{seq}",
            task=task,
            participants=[self._agent_id],
            metadata={
                "view": self._view,
                "seq": seq,
                "n": self._n,
                "quorum": quorum_size(self._n),
                "value": value,
                "leader": str(self._agent_id),
                "replicas": [str(r) for r in self._replicas] or [str(self._agent_id)],
                "pre_prepare": {
                    "view": self._view,
                    "seq": seq,
                    "value": value,
                    "proposer": str(self._agent_id),
                    "sig_value": signature.value.hex(),
                    "sig_algorithm": signature.algorithm,
                },
                "votes": [],
            },
        )
        return rnd

    def _verify_pre_prepare(self, round: Round) -> bool:
        """Return True iff the Round's pre-prepare is from the rightful, signed leader.

        Two independent checks: the proposer must be the round-robin leader for
        the view, and the leader's signature over the pre-prepare payload must
        verify against the leader's known public key. A replica that cannot
        verify (unknown key, bad signature, wrong proposer) must not vote.

        Example::

            if coord._verify_pre_prepare(rnd): ...
        """
        meta = round.metadata
        pp = meta.get("pre_prepare")
        if not pp:
            return False
        view = int(meta["view"])
        seq = int(meta["seq"])
        n = int(meta["n"])
        value = str(meta["value"])
        proposer = AgentId(str(pp["proposer"]))

        # (a) proposer must be the rightful leader for this view.
        participants = self._participant_index(round)
        expected_leader_idx = leader_for_view(view, n)
        if participants.get(proposer) != expected_leader_idx:
            return False

        # (b) the leader's signature must verify.
        sig = Signature(
            signer=proposer,
            value=bytes.fromhex(str(pp["sig_value"])),
            algorithm=str(pp["sig_algorithm"]),
        )
        payload = signing_payload(view, seq, PHASE_PRE_PREPARE, value)
        return bool(self._identity.verify(payload, sig, proposer))

    def _participant_index(self, round: Round) -> dict[AgentId, int]:
        """Map each replica id to its stable index for leader-election math.

        Uses the sorted ``replicas`` list recorded on the round (or the leader
        plus participants as a fallback), so every agent computes the same
        leader for a given view without global mutable state.

        Example::

            idx = coord._participant_index(rnd)
        """
        replicas = round.metadata.get("replicas")
        if replicas:
            ids = [AgentId(str(r)) for r in replicas]
        else:
            ids = sorted({AgentId(str(round.metadata["leader"]))} | set(round.participants))
        return {aid: i for i, aid in enumerate(sorted(ids))}

    async def participate(self, round: Round) -> Vote:
        """Replica step: verify the pre-prepare, then cast a signed prepare vote.

        On the happy path a replica that accepts the pre-prepare signs
        ``(view, seq, prepare, value)`` and appends the vote to
        ``round.metadata["votes"]``. If the pre-prepare cannot be verified, the
        replica abstains (an empty-value vote) rather than endorsing it.

        Example::

            vote = await coord.participate(rnd)
        """
        meta = round.metadata
        view = int(meta["view"])
        seq = int(meta["seq"])
        value = str(meta["value"])

        if not self._verify_pre_prepare(round):
            return Vote(
                voter=self._agent_id,
                round_id=round.id,
                value="",
                metadata={"abstain": True},
            )

        payload = signing_payload(view, seq, PHASE_PREPARE, value)
        signature = self._identity.sign(payload)
        sv = SignedVote(
            voter=self._agent_id,
            view=view,
            seq=seq,
            phase=PHASE_PREPARE,
            value=value,
            signature=signature,
        )
        votes: list[dict[str, Any]] = meta.setdefault("votes", [])
        votes.append(sv.to_metadata())
        if self._agent_id not in round.participants:
            round.participants.append(self._agent_id)
        return Vote(voter=self._agent_id, round_id=round.id, value=value)

    def _verify_vote(self, sv: SignedVote) -> bool:
        """Return True iff a vote's signature verifies against the voter's key.

        Independent of how the vote arrived: ``resolve`` trusts nothing that was
        merely *placed* in the metadata, only what cryptographically verifies.
        This is what stops a byzantine agent from fabricating a quorum.

        Example::

            ok = coord._verify_vote(sv)
        """
        payload = signing_payload(sv.view, sv.seq, sv.phase, sv.value)
        return bool(self._identity.verify(payload, sv.signature, sv.voter))

    async def resolve(self, round: Round) -> Outcome:
        """Count independently-verified votes; commit a value iff it has a quorum.

        Every stored vote is re-verified here (not trusted from when it was
        cast). Valid votes are grouped by value, counting *distinct* voters; a
        value reaching ``2f+1`` distinct verified voters commits, and exactly
        those signed votes form the commit quorum certificate on the Outcome. If
        no value reaches quorum, the Outcome has no winner.

        Example::

            outcome = await coord.resolve(rnd)
        """
        meta = round.metadata
        quorum = int(meta["quorum"])

        # Group verified votes by value, one vote per (voter, value).
        by_value: dict[str, dict[AgentId, dict[str, Any]]] = {}
        for raw in meta.get("votes", []):
            sv = SignedVote.from_metadata(raw)
            if not self._verify_vote(sv):
                continue
            by_value.setdefault(sv.value, {})[sv.voter] = raw

        winner_value: str | None = None
        certificate: list[dict[str, Any]] = []
        for value, voters in by_value.items():
            if len(voters) >= quorum:
                winner_value = value
                certificate = list(voters.values())
                break

        # Reaching a prepare-quorum means this replica is now "prepared" on the
        # value. Record it (and its proof) so a later view-change can carry it
        # forward and bind the next leader.
        if winner_value is not None:
            view = int(meta["view"])
            seq = int(meta["seq"])
            prev = self._prepared.get(seq)
            if prev is None or view >= int(prev["view"]):
                self._prepared[seq] = {
                    "view": view,
                    "value": winner_value,
                    "proof": certificate,
                }

        leader = AgentId(str(meta["leader"]))
        return Outcome(
            round_id=round.id,
            winner=leader if winner_value is not None else None,
            task=round.task,
            metadata={
                "view": int(meta["view"]),
                "seq": int(meta["seq"]),
                "committed_value": winner_value,
                "quorum": quorum,
                "certificate": certificate,
            },
        )

    def _certificate_is_valid(
        self, value: str, quorum: int, certificate: list[dict[str, Any]]
    ) -> bool:
        """Return True iff a certificate has ``>= quorum`` distinct valid votes for ``value``.

        A replica re-checks the certificate itself rather than trusting that an
        Outcome's claimed quorum is real — the forged-quorum defense. Every
        signature must verify and every voter must be distinct.

        Example::

            ok = coord._certificate_is_valid("X", 3, outcome.metadata["certificate"])
        """
        seen: set[AgentId] = set()
        for raw in certificate:
            sv = SignedVote.from_metadata(raw)
            if sv.value != value or not self._verify_vote(sv):
                continue
            seen.add(sv.voter)
        return len(seen) >= quorum

    async def commit(self, outcome: Outcome) -> None:
        """Finalize a commit only if its certificate independently reaches quorum.

        Re-verifies the certificate's signatures before recording the commit;
        an Outcome whose certificate does not actually carry ``2f+1`` valid
        distinct votes is refused (nothing is recorded). On success the
        ``(view, seq) -> certificate`` mapping is stored for audit/trace.

        Example::

            await coord.commit(outcome)
        """
        meta = outcome.metadata
        value = meta.get("committed_value")
        if value is None:
            return
        quorum = int(meta["quorum"])
        certificate = meta.get("certificate", [])
        if not self._certificate_is_valid(str(value), quorum, certificate):
            return
        key = (int(meta["view"]), int(meta["seq"]))
        self._committed[key] = certificate

    def committed_value(self, view: int, seq: int) -> str | None:
        """Return the value this replica committed for a slot, or None.

        Example::

            v = coord.committed_value(0, 1)
        """
        cert = self._committed.get((view, seq))
        if not cert:
            return None
        return SignedVote.from_metadata(cert[0]).value

    # ------------------------------------------------------------------
    # View change (half a): a replica requests moving to the next view,
    # carrying proof of what it prepared so nothing committed can be lost.
    # ------------------------------------------------------------------

    def request_view_change(
        self, current_view: int, reason: str = "leader-timeout"
    ) -> dict[str, Any]:
        """Produce this replica's signed view-change message for ``current_view + 1``.

        The message carries the replica's prepared set (value + proof per seq) so
        the next leader can see every value that may have reached commit and is
        bound to re-propose it. Signed over ``view_change_payload`` so it cannot
        be forged for another replica or replayed for a different view.

        Example::

            vc = replica.request_view_change(0)
        """
        new_view = current_view + 1
        payload = view_change_payload(new_view, self._agent_id, self._prepared)
        signature = self._identity.sign(payload)
        return {
            "new_view": new_view,
            "agent": str(self._agent_id),
            "reason": reason,
            "prepared": {
                str(seq): {
                    "view": int(p["view"]),
                    "value": str(p["value"]),
                    "proof": p["proof"],
                }
                for seq, p in self._prepared.items()
            },
            "sig_value": signature.value.hex(),
            "sig_algorithm": signature.algorithm,
        }

    def _verify_view_change(self, vc: dict[str, Any]) -> bool:
        """Return True iff a view-change message is correctly signed by its sender.

        Rebuilds the prepared digest from the message and checks the signature
        against the sender's key — an unsigned or tampered view-change is
        ignored, the same trust rule used for votes.

        Example::

            ok = leader._verify_view_change(vc)
        """
        agent = AgentId(str(vc["agent"]))
        prepared = {
            int(seq): {"view": int(p["view"]), "value": str(p["value"])}
            for seq, p in vc.get("prepared", {}).items()
        }
        payload = view_change_payload(int(vc["new_view"]), agent, prepared)
        sig = Signature(
            signer=agent,
            value=bytes.fromhex(str(vc["sig_value"])),
            algorithm=str(vc["sig_algorithm"]),
        )
        return bool(self._identity.verify(payload, sig, agent))

    # ------------------------------------------------------------------
    # View change (half b): the new leader forms a new-view that BINDS to any
    # value that was prepared, so a value committed in an old view is never
    # dropped or overwritten. This is the safety core of view-change.
    # ------------------------------------------------------------------

    def form_new_view(self, view_changes: list[dict[str, Any]]) -> dict[str, Any] | None:
        """Form a signed new-view from ``2f+1`` verified view-change messages.

        Binding rule: for each seq, take the prepared value with the highest
        view across all collected view-changes; the new leader is *bound* to
        re-propose that value. A seq nobody prepared is left free. Returns None
        if fewer than ``2f+1`` valid, distinct view-change messages are present
        or if this replica is not the leader for the target view.

        Example::

            nv = new_leader.form_new_view([vc1, vc2, vc3])
        """
        if not view_changes:
            return None
        new_view = int(view_changes[0]["new_view"])
        quorum = quorum_size(self._n)

        # Collect verified, distinct-sender view-changes for this target view.
        valid: dict[AgentId, dict[str, Any]] = {}
        for vc in view_changes:
            if int(vc["new_view"]) != new_view:
                continue
            if not self._verify_view_change(vc):
                continue
            valid[AgentId(str(vc["agent"]))] = vc
        if len(valid) < quorum:
            return None

        # This replica must be the rightful leader for the new view.
        idx = {aid: i for i, aid in enumerate(self._replicas)}
        if idx.get(self._agent_id) != leader_for_view(new_view, self._n):
            return None

        # Binding: per seq, pick the prepared value with the highest view.
        bound: dict[int, dict[str, Any]] = {}
        for vc in valid.values():
            for seq_s, p in vc.get("prepared", {}).items():
                seq = int(seq_s)
                cand_view = int(p["view"])
                if seq not in bound or cand_view > int(bound[seq]["view"]):
                    bound[seq] = {"view": cand_view, "value": str(p["value"]), "proof": p["proof"]}

        payload = json.dumps(
            {
                "new_view": new_view,
                "leader": str(self._agent_id),
                "bound": sorted((s, b["value"]) for s, b in bound.items()),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        signature = self._identity.sign(payload)

        # Adopt the new view locally so subsequent proposes use it.
        self._view = new_view

        return {
            "new_view": new_view,
            "leader": str(self._agent_id),
            "view_changes": list(valid.values()),
            "bound": {str(s): b for s, b in bound.items()},
            "sig_value": signature.value.hex(),
            "sig_algorithm": signature.algorithm,
        }

    def bound_value_for(self, new_view_msg: dict[str, Any], seq: int) -> str | None:
        """Return the value the new leader is bound to re-propose for ``seq``, if any.

        Example::

            v = leader.bound_value_for(nv, seq=1)
        """
        b = new_view_msg.get("bound", {}).get(str(seq))
        return str(b["value"]) if b else None
