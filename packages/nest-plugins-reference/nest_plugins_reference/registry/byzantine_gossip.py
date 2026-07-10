# SPDX-License-Identifier: Apache-2.0
"""Byzantine-resistant gossip registry plugin — scaffold (Task 1 of the series).

``nest_plugins_reference.registry.gossip.GossipRegistry`` gives us
eventually-consistent discovery under honest-but-partitioned failures: every
agent gossips its local view over the transport, and the simulator's
partition logic naturally blocks cross-partition propagation.  It assumes,
however, that every participant plays by the rules — same publisher never
signs two conflicting write tags at the same version, no agent forges
another agent's cards, and no agent tries to starve a victim's view by only
ever gossiping with a captured subset of peers.

This plugin is the byzantine-hardened counterpart.  Task 1 scaffolded the
class and proved it satisfies ``nest_core.layers.registry.Registry`` — the
view/merge/wire-format machinery is a deliberate copy of
``GossipRegistry``'s structure, while the network-wide primitives
(``GossipNetwork``, ``GOSSIP_PREFIX``, ``OP_DIGEST``, ``OP_PUSH``,
``_WriteTag``) are imported and reused as-is so both plugins share one
notion of "peer set" and "write ordering."

Task 2 (this task) adds the core moat: **every card is signed at
registration and re-verified on every gossip hop, not just once at
registration time.**  Prior art for signed cards exists (``#67``:
registration-only signing — a publisher signs its card when it first
registers).  That is necessary but not sufficient: ``#67``'s check runs
exactly once, at the source, and nothing downstream re-checks a card as it
hops through the gossip mesh.  A compromised or malicious relay agent can
forge a card claiming another agent's identity (impersonation) or mutate a
previously-honest card's bytes in transit (forgery) and any peer that only
trusts "it must be fine, gossip is honest-but-partitioned" will merge it
straight into its view.  This plugin closes that gap: ``handle_gossip``'s
``OP_PUSH`` branch verifies ``identity.verify(canonical_write_bytes(card,
tag.version, tombstone), sig, card.agent_id)`` for every incoming card and
drops (never ``_apply``s) anything that is unsigned, claims a signer other
than its own ``agent_id`` (impersonation), or fails cryptographic
verification (forgery/mutation) — recording ``(agent_id, reason)`` in
``self.rejections`` for judge/validator legibility with reason codes
``missing_signature``, ``signer_mismatch``, and ``bad_signature``, mirroring
``#67``'s taxonomy.

Critically, the signature binds not just the card's *content* but also its
**write tag (version) and tombstone bit**.  Content-only signing (sign
``agent_id``/``name``/``capabilities``/``endpoint``, nothing else) leaves a
gap of its own: the wire-supplied ``_WriteTag`` and ``tombstone`` in an
``OP_PUSH`` entry are merged verbatim once the *card* checks out, so a relay
with **no private key at all** can replay a genuinely-signed card under a
forged, inflated ``version`` (winning last-writer-wins against the
publisher's real future writes, i.e. blocking updates) or with a flipped
``tombstone`` bit (resurrecting a deregistered agent — an "un-delete" — or
silently deleting a live one).  Binding the signature to
``(content, version, tombstone)`` closes that: a replayed card with a
tampered tag or tombstone now fails verification and is dropped as
``bad_signature``, exactly like a forged/mutated card.

Task 3 (this task) closes the gap the module docstring above used to end
on: a publisher who signs two *different*, both validly-signed cards at the
same version (equivocation). Signature verification alone cannot detect
that — both cards individually pass every check Task 2 added, and ``#67``'s
registration-only signing would happily accept either one too, since it
only ever checks a card against *itself*, never against the publisher's
other writes. That is exactly the invariant registration-signing cannot
provide: **both equivocating cards are validly signed by their claimed
publisher.** The only way to catch this is to compare a publisher's writes
to each other, not to a signature. This plugin keeps a witness map from
``(publisher_id, version)`` to a content hash of the first verified write it
saw at that key; a second *verified* card at the same key with a
*different* hash proves the publisher signed two conflicting writes, which
is only possible if the publisher itself is byzantine (a relay cannot forge
this — see ``canonical_write_bytes``, version and tombstone are signed).
The publisher is quarantined on the spot: its card is evicted from the
local view, the conflict is recorded in ``self.equivocations``, and every
subsequent card from that publisher — genuinely signed or not — is refused
without re-litigating the question.

The witness map only fires at a node that actually *receives* both
conflicting cards, so detection is only as strong as propagation. A
**disjoint-delivery** equivocator exploits exactly that gap: it sends
card1 only to group A and card2 only to group B with no common recipient,
so no single node ever sees both directly. A digest keyed on
``(version, publisher_id)`` alone would judge A's ``(E, v1)`` and B's
``(E, v1)`` as already in sync (equal tag) and never exchange the
conflicting card — the split would be permanent and no honest node would
ever witness it. This plugin's digest therefore carries a **content hash**
per entry (``content_hash``), so ``_compute_missing`` treats a
same-version-but-different-content entry as something to hand over: each
side pushes the other its conflicting copy, some honest node sees both
cards, and the witness map fires (see ``_compute_missing``/``_digest`` and
``test_disjoint_delivery_equivocation_is_caught``). A same-version
SAME-content retransmission has an equal hash and is still idempotent — not
re-exchanged, not a conflict.

Content-hash-in-digest alone, however, is NOT enough to make detection
*mesh-wide* once there are N>2 honest nodes and multiple equivocators. The
moment a node witnesses the conflict it **evicts** the card, which drops it
from ``_digest`` — so that node stops relaying the conflicting copy onward.
Under disjoint delivery a node that received only one side, whose reachable
counterparts (holding the other side) all evict before the other card
propagates to it, is left permanently holding a validly-signed equivocated
card it never detects — "eviction halts relay" (reproduced at N=10, five
equivocators: a whole group strands identically at 40 and 500 rounds; see
``test_disjoint_multi_equivocator_no_stranding``). The card-exchange path
guarantees only that *some* node witnesses the conflict, not that *every*
node does.

The fix is to gossip the equivocation **proof**, not just the card. When a
node detects an equivocation for publisher ``E`` at version ``v`` it holds
two conflicting, individually-signature-valid writes for ``(E, v)`` — that
pair is a self-verifying proof (``_equivocation_proofs``, kept in a
canonical hash order so every node's proof bytes match). The proof is NOT
removed when the card is evicted, so it keeps propagating: the ``OP_DIGEST``
payload advertises each node's known-byzantine set, and a peer replies
(``OP_EQPROOF``) with any proof that peer holds and the sender lacks. On
receipt (``_ingest_proof``) a node independently re-verifies BOTH signatures
via the identity layer and confirms the two writes are the same ``(E, v)``
with different content hashes (``_verify_proof``) before quarantining ``E``
— so a relay CANNOT fabricate a proof to frame an honest publisher (an
honest ``E`` never signs two conflicting cards, and a mutated side fails its
signature; see ``REASON_BAD_PROOF`` and
``test_fabricated_equivocation_proof_does_not_frame_honest_publisher``).
This closes eviction-halts-relay: even a stranded node eventually receives
the proof from any honest neighbor and quarantines ``E``, so ALL honest
nodes converge on "E quarantined, evicted" regardless of delivery topology.
The one residual honest caveat: the honest sub-network must be **connected**
(not partitioned) for the proof to reach everyone, and convergence is
**eventual** — there is a transient window, while the proof is still in
flight, during which some honest nodes have quarantined ``E`` and others
have not yet. See ``VERIFICATION.md``.

Task 4 (this task) closes the last gap the earlier tasks left open: Tasks
2-3 only decide whether a card that *arrives* at this agent is trustworthy
(signed, not forged, not equivocating). They do nothing to guarantee a card
*arrives* at all. ``gossip_round`` picked ``fanout`` peers **uniformly at
random** from the full peer set every round -- exactly like the plain
``GossipRegistry`` it copies. If a byzantine-controlled subset of peers is
large enough (or the draw is merely unlucky), every peer this agent gossips
with in a given round can be byzantine, and since each round redraws
independently with no memory of who was contacted before, an adversary that
holds enough of the peer set (or enough sybil identities in it) can keep an
honest agent eclipsed from a specific honest publisher's cards indefinitely
-- no signature or equivocation check ever gets a chance to run because the
honest card never shows up in an ``OP_PUSH``.

This plugin's ``gossip_round`` fixes that by drawing from two disjoint
pools every round instead of one: a deterministic **anchor set** -- the
lexicographically-first ``ceil(fanout / 2)`` peers by ``AgentId``, recomputed
identically every round from the current peer list -- plus ``floor(fanout /
2)`` peers drawn from the *remaining* peers via the agent's seeded
``ctx.rng`` (see ``_sample_eclipse_resistant``). As long as at least one
anchor slot is held by an honest peer, that peer is contacted **every
single round**, not just when the random draw happens to land on it, so an
honest publisher's signed, verified card is guaranteed to eventually reach
this agent through that fixed contact rather than depending on random luck
each round. This is a **heuristic, not a proof**: the anchor set is
positional (lexicographically-first by ``AgentId`` among this agent's
current peers), not identity-vetted, so a topology where the adversary
controls every one of the lexicographically-first ``ceil(fanout / 2)``
``AgentId``s among a given victim's peers defeats the guarantee for that
victim specifically -- see ``VERIFICATION.md`` for that caveat, and
``test_eclipse_resistance_keeps_honest_contact`` /
``test_eclipse_resistant_sampling_is_deterministic`` for the adversarial
and determinism tests. Determinism is preserved throughout: same seed, same
peer set -> byte-identical chosen list, exactly like the uniform sampler it
replaces.

Example::

    from nest_plugins_reference.identity.did_key import DidKeyIdentity
    from nest_plugins_reference.registry.gossip import GossipNetwork

    net = GossipNetwork(agent_ids=[AgentId("a"), AgentId("b")])
    identity = DidKeyIdentity(AgentId("a"), seed=b"s")
    reg = ByzantineGossipRegistry(AgentId("a"), net, identity)
    await reg.register(AgentCard(agent_id=AgentId("a"), name="A"))
"""

from __future__ import annotations

import hashlib
import json
import math
import random
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

from nest_core.types import AgentCard, AgentId, Query, Signature

from nest_plugins_reference.registry.gossip import (
    GOSSIP_PREFIX,
    OP_DIGEST,
    OP_PUSH,
    GossipNetwork,
    _WriteTag,  # pyright: ignore[reportPrivateUsage]
)

if TYPE_CHECKING:
    from nest_core.layers.identity import Identity
    from nest_core.sim.agent import AgentContext


_ProofWrite = tuple[AgentCard, _WriteTag, bool]
"""One side of an equivocation proof: a ``(card, tag, tombstone)`` write whose
embedded signature verifies on its own. A proof is a pair of these that
conflict (same ``(publisher, version)``, different content hash).

Example::

    write: _ProofWrite = (card, _WriteTag(1, AgentId("e")), False)
"""


REASON_MISSING_SIGNATURE = "missing_signature"
"""Rejection reason: card carries no ``metadata["sig"]`` at all.

Example::

    reg.rejections.append((AgentId("a"), REASON_MISSING_SIGNATURE))
"""

REASON_SIGNER_MISMATCH = "signer_mismatch"
"""Rejection reason: ``sig.signer`` names a different agent than ``card.agent_id``
(impersonation — the card claims someone else's identity).

Example::

    reg.rejections.append((AgentId("a"), REASON_SIGNER_MISMATCH))
"""

REASON_BAD_SIGNATURE = "bad_signature"
"""Rejection reason: signature is present and claims the right signer, but
fails cryptographic verification (forgery, or a mutated-in-transit card).

Example::

    reg.rejections.append((AgentId("a"), REASON_BAD_SIGNATURE))
"""

REASON_QUARANTINED = "quarantined"
"""Rejection reason: ``card.agent_id`` was already caught equivocating (see
``ByzantineGossipRegistry.equivocations``) and is permanently quarantined.
Every subsequent card from this publisher is refused on sight — even one
that would itself verify cleanly — because a publisher proven to sign
conflicting writes once cannot be trusted to have stopped.

Example::

    reg.rejections.append((AgentId("e"), REASON_QUARANTINED))
"""

REASON_BAD_PROOF = "bad_equivocation_proof"
"""Rejection reason: an ``OP_EQPROOF`` equivocation proof for a publisher did
NOT independently verify — the two writes are not both validly signed by the
publisher, are not at the same version, or do not actually conflict (equal
content hash). This is the anti-framing guard on the proof-gossip path: a
relay with no key for an honest publisher ``E`` cannot fabricate a conflicting
signed-write pair for ``E`` (an honest ``E`` never signs two conflicting
cards), so a bogus proof is dropped here and ``E`` is NOT quarantined.

Example::

    reg.rejections.append((AgentId("e"), REASON_BAD_PROOF))
"""

OP_EQPROOF = b"Q"
"""Wire op (``byzantine_gossip``'s own extension, not in reference ``gossip.py``):
push of one or more equivocation PROOFs — each a pair of conflicting,
individually-signature-valid writes for a single ``(publisher, version)``.
Sent in reply to an ``OP_DIGEST`` whose advertised known-byzantine set does
not yet include a publisher this node can prove byzantine, so the proof
propagates mesh-wide independently of card eviction.

Example::

    payload = GOSSIP_PREFIX + OP_EQPROOF + _encode_proofs([(AgentId("e"), proof)])
"""


@dataclass
class _Versioned:
    """A stored card plus its write tag and a tombstone bit.

    Local copy of ``GossipRegistry``'s ``_Versioned`` structure — kept
    separate (not imported) so later tasks can extend it with a signature
    field without touching the plain gossip plugin.

    Example::

        v = _Versioned(card=card, tag=_WriteTag(1, AgentId("a")), tombstone=False)
    """

    card: AgentCard
    tag: _WriteTag
    tombstone: bool = False


class ByzantineGossipRegistry:
    """Per-agent gossip registry with signed, re-verified-on-every-hop cards.

    Satisfies ``nest_core.layers.registry.Registry``: ``register``,
    ``lookup``, ``subscribe``, ``deregister``.  Delegates to the same
    local-view / last-writer-wins merge logic as
    ``nest_plugins_reference.registry.gossip.GossipRegistry``, but
    ``register``/``deregister`` sign every write via the injected
    ``Identity`` — content plus version plus tombstone — and
    ``handle_gossip`` verifies that signature (fresh, against
    ``card.agent_id`` and the wire-supplied version/tombstone) before
    merging an inbound card — see the module docstring for why
    registration-only, content-only signing (``#67``) is not enough.
    ``handle_gossip`` also witnesses every verified write against
    ``(publisher_id, version)`` and quarantines a publisher caught signing
    two different cards at the same version (equivocation) — see
    ``equivocations`` and the module docstring. ``gossip_round`` mixes a
    deterministic anchor peer set with seeded-random peers so a bounded
    byzantine fraction cannot fully surround (eclipse) an honest agent's
    inbound honest data — see ``_sample_eclipse_resistant`` and the module
    docstring's Task 4 section.

    Driver agents call ``gossip_round(ctx)`` on a schedule and forward
    inbound ``GOSSIP_PREFIX``-marked payloads to
    ``handle_gossip(sender, payload, ctx)``, exactly as with
    ``GossipRegistry``.

    Example::

        net = GossipNetwork(agent_ids=[AgentId("a"), AgentId("b")])
        identity = DidKeyIdentity(AgentId("a"), seed=b"s")
        reg = ByzantineGossipRegistry(AgentId("a"), net, identity)
        await reg.register(AgentCard(agent_id=AgentId("a"), name="A"))
        cards = await reg.lookup(Query())  # returns local view only
    """

    def __init__(self, agent_id: AgentId, network: GossipNetwork, identity: Identity) -> None:
        self._agent_id = agent_id
        self._network = network
        self._identity = identity
        self._view: dict[AgentId, _Versioned] = {}
        self.rejections: list[tuple[AgentId, str]] = []
        """Ledger of cards dropped during gossip merge: ``(agent_id, reason)``
        pairs, in the order they were rejected.  ``reason`` is one of
        ``REASON_MISSING_SIGNATURE``, ``REASON_SIGNER_MISMATCH``,
        ``REASON_BAD_SIGNATURE``, ``REASON_QUARANTINED``.  Exposed for
        validators/tests, not part of the ``Registry`` Protocol.

        Example::

            assert reg.rejections == [(AgentId("a"), "bad_signature")]
        """
        self.equivocations: list[tuple[AgentId, int]] = []
        """Ledger of proven equivocations: ``(publisher_id, version)`` pairs,
        in detection order.  A publisher lands here when this registry sees
        **two independently-verified** cards from it at the same version
        whose content differs — proof the publisher itself signed two
        conflicting writes, since ``canonical_write_bytes`` binds the
        signature to ``(content, version, tombstone)`` and a non-publisher
        relay cannot forge that.  This is the invariant registration-only
        signing (``#67``) cannot provide: both cards that trigger an entry
        here are validly signed by their claimed publisher — the defect is
        not a bad signature, it is two good ones that contradict each
        other.  Exposed for validators/tests, not part of the ``Registry``
        Protocol.

        Example::

            assert reg.equivocations == [(AgentId("e"), 1)]
        """
        self._quarantined: set[AgentId] = set()
        """Publishers with at least one entry in ``equivocations``.  Checked
        at the top of the ``OP_PUSH`` loop so every later card from a
        quarantined publisher is refused (``REASON_QUARANTINED``) without
        even attempting verification — quarantine is permanent for the
        lifetime of this registry instance, not a one-shot conflict
        resolution.
        """
        self._seen: dict[tuple[AgentId, int], str] = {}
        """Witness map: ``(publisher_id, version) -> content_hash`` for the
        first verified card this registry processed at that key.
        ``content_hash`` is ``sha256(canonical_write_bytes(card, version,
        tombstone)).hexdigest()`` — hashing the full write (not just
        ``canonical_card_bytes``) so a publisher that signs a live card and
        a tombstone at the same version is also caught, not only a
        content-vs-content conflict.  A retransmission of the *identical*
        write (same hash) is not equivocation and is left alone; see
        ``_witness_write``.
        """
        self._first_write: dict[tuple[AgentId, int], tuple[AgentCard, _WriteTag, bool]] = {}
        """First verified write ``(card, tag, tombstone)`` seen at each
        ``(publisher_id, version)`` key — the counterpart the witness map needs
        to reconstruct a self-verifying equivocation PROOF the moment a
        conflicting second write arrives (``_seen`` alone keeps only the hash).
        Grows in lockstep with ``_seen`` and, like it, is never pruned.
        """
        self._equivocation_proofs: dict[AgentId, tuple[_ProofWrite, _ProofWrite]] = {}
        """Self-verifying equivocation proofs: ``publisher_id -> (write_a,
        write_b)`` where each write is a ``(card, tag, tombstone)`` triple that
        individually passes ``_verify_card`` and the two conflict (same
        ``(publisher, version)``, different content hash).  The two writes are
        stored in a canonical order (by content hash, see ``_canonical_proof``)
        so every node holds byte-identical proof bytes regardless of which side
        it saw first.  **Survives card eviction** — this is the whole fix: a
        node that has evicted an equivocator's card keeps the proof so it still
        relays the conflict onward via ``OP_EQPROOF``, closing the
        eviction-halts-relay stranding gap under disjoint multi-equivocator
        delivery.  Invariant: ``set(self._equivocation_proofs) ==
        self._quarantined`` (every quarantine path stores a proof).  Exposed
        for validators/tests, not part of the ``Registry`` Protocol.

        Example::

            assert set(reg._equivocation_proofs) == {AgentId("e")}
        """

    # ------------------------------------------------------------------
    # Registry protocol
    # ------------------------------------------------------------------

    async def register(self, card: AgentCard) -> None:
        """Register ``card`` locally, signed; gossip propagates it on the next round.

        Allocates this write's version first, then signs
        ``canonical_write_bytes(card, version, tombstone=False)`` with this
        agent's ``Identity`` and stores the signature in
        ``card.metadata["sig"]`` (a fresh ``AgentCard`` — the caller's
        instance is not mutated) so every peer that later receives this
        card via gossip can verify it came from ``card.agent_id``, was not
        altered in transit, and carries the version/tombstone the publisher
        actually wrote — not one a relay forged on the wire.

        Example::

            await reg.register(AgentCard(agent_id=AgentId("a"), name="A"))
        """
        tag = _WriteTag(
            version=self._network.next_version(card.agent_id),
            publisher_id=card.agent_id,
        )
        signed_card = _sign_card(card, tag.version, tombstone=False, identity=self._identity)
        self._apply(signed_card, tag, tombstone=False)

    async def lookup(self, query: Query) -> list[AgentCard]:
        """Return cards matching ``query`` from the **local** view.

        Example::

            cards = await reg.lookup(Query(capabilities=["sell"]))
        """
        return [v.card for v in self._view.values() if not v.tombstone and _matches(v.card, query)]

    async def subscribe(self, query: Query) -> AsyncIterator[AgentCard]:
        """Yield cards matching ``query`` from the local view, then end.

        Example::

            async for card in reg.subscribe(query):
                print(card.name)
        """
        for card in await self.lookup(query):
            yield card

    async def deregister(self, agent: AgentId) -> None:
        """Tombstone ``agent`` locally; gossip propagates the tombstone.

        Allocates the new (tombstoning) version and re-signs
        ``canonical_write_bytes(existing_card, version, tombstone=True)`` so
        the deletion itself is authenticated — a relay cannot flip
        ``tombstone`` back to ``False`` on the wire and "un-delete" the
        agent, since that would no longer match the signed write.

        Example::

            await reg.deregister(AgentId("a"))
        """
        existing = self._view.get(agent)
        if existing is None:
            return
        tag = _WriteTag(
            version=self._network.next_version(agent),
            publisher_id=agent,
        )
        signed_card = _sign_card(
            existing.card, tag.version, tombstone=True, identity=self._identity
        )
        self._apply(signed_card, tag, tombstone=True)

    # ------------------------------------------------------------------
    # Gossip mechanics
    # ------------------------------------------------------------------

    async def gossip_round(self, ctx: AgentContext) -> None:
        """Run one round of push-pull anti-entropy with eclipse-resistant peer sampling.

        Unlike ``GossipRegistry.gossip_round`` (pure uniform sampling),
        picks ``fanout`` peers via ``_sample_eclipse_resistant``: a
        deterministic anchor set (the lexicographically-first
        ``ceil(fanout / 2)`` peers by ``AgentId``) plus ``floor(fanout / 2)``
        seeded-random peers from the rest. See the module docstring's Task 4
        section for the eclipse threat model this defends against and its
        honest limit (the anchor guarantee is heuristic, not a proof).

        The digest also advertises this node's known-byzantine set (publishers
        it holds an equivocation proof for) so a peer replies with only the
        proofs this node is still missing — that is how equivocation proofs
        ride anti-entropy mesh-wide, independent of card eviction.

        Example::

            await reg.gossip_round(ctx)
        """
        peers = self._network.peers_of(self._agent_id)
        if not peers:
            return
        fanout = min(self._network.fanout, len(peers))
        chosen = _sample_eclipse_resistant(ctx.rng, peers, fanout)
        digest = self._digest()
        payload = GOSSIP_PREFIX + OP_DIGEST + _encode(digest, self._known_byzantine())
        for peer in chosen:
            await ctx.send(peer, payload)

    async def handle_gossip(self, sender: AgentId, payload: bytes, ctx: AgentContext) -> bool:
        """Process a gossip message from ``sender``.

        Returns ``True`` if the payload was a gossip message (and was
        consumed), ``False`` otherwise.  ``OP_PUSH`` entries are verified
        before merge against ``canonical_write_bytes(card, tag.version,
        tombstone)`` — binding the signature to the wire-supplied version
        and tombstone bit, not just the card content — so unsigned,
        impersonating, forged/mutated, replayed-with-a-forged-version, or
        tombstone-flipped entries are all dropped and recorded in
        ``self.rejections`` instead of being applied.  A quarantined
        publisher's cards are refused outright (``REASON_QUARANTINED``,
        skipping verification entirely).  Otherwise-valid cards are then
        witnessed against ``(publisher, version)``: a second, verified, but
        *content-differing* card at an already-witnessed key proves
        equivocation — both cards are validly signed, so no signature check
        alone can catch this — and quarantines the publisher on the spot
        (see ``equivocations`` and the module docstring).

        An ``OP_EQPROOF`` message carries equivocation PROOFs (pairs of
        conflicting signed writes). Each is independently re-verified via
        ``_ingest_proof`` — both signatures must pass and the two writes must
        genuinely conflict — before the publisher is quarantined, so a relay
        cannot forge a proof to frame an honest publisher. This is what makes
        the equivocation defense mesh-wide even under disjoint delivery: the
        proof survives card eviction and keeps propagating, so a node stranded
        with only one side of the conflict still learns the publisher is
        byzantine from any honest neighbor.

        Example::

            handled = await reg.handle_gossip(sender, payload, ctx)
        """
        if not payload.startswith(GOSSIP_PREFIX):
            return False
        body = payload[len(GOSSIP_PREFIX) :]
        if not body:
            return True
        op, rest = body[:1], body[1:]
        if op == OP_DIGEST:
            sender_digest, sender_known_byz = _decode_digest(rest)
            missing = self._compute_missing(sender_digest)
            if missing:
                push_payload = GOSSIP_PREFIX + OP_PUSH + _encode_push(missing)
                await ctx.send(sender, push_payload)
            missing_proofs = self._compute_missing_proofs(sender_known_byz)
            if missing_proofs:
                proof_payload = GOSSIP_PREFIX + OP_EQPROOF + _encode_proofs(missing_proofs)
                await ctx.send(sender, proof_payload)
            return True
        if op == OP_PUSH:
            for card, tag, tombstone in _decode_push(rest):
                if card.agent_id in self._quarantined:
                    self.rejections.append((card.agent_id, REASON_QUARANTINED))
                    continue
                reason = _verify_card(card, tag.version, tombstone, self._identity)
                if reason is not None:
                    self.rejections.append((card.agent_id, reason))
                    continue
                if self._witness_write(card, tag, tombstone):
                    continue
                self._apply(card, tag, tombstone=tombstone)
            return True
        if op == OP_EQPROOF:
            for publisher, write_a, write_b in _decode_proofs(rest):
                self._ingest_proof(publisher, write_a, write_b)
            return True
        return True  # Unknown op: consume silently so junk doesn't escape.

    # ------------------------------------------------------------------
    # Inspection (used by validators + tests)
    # ------------------------------------------------------------------

    def view_snapshot(self) -> dict[AgentId, tuple[int, AgentId, bool]]:
        """Return a deterministic snapshot of the local view.

        Same shape as ``GossipRegistry.view_snapshot`` so
        ``check_converged`` composes across both plugins.

        Example::

            snap = reg.view_snapshot()
        """
        return {
            aid: (v.tag.version, v.tag.publisher_id, v.tombstone)
            for aid, v in sorted(self._view.items())
        }

    def content_view(self) -> dict[AgentId, tuple[int, AgentId, bool, str]]:
        """Return a deterministic **content-aware** snapshot of the local view.

        Extends ``view_snapshot()``'s ``(version, publisher_id, tombstone)``
        tuple with a fourth field — ``content_hash(card, version, tombstone)``,
        the SAME per-write fingerprint the witness map (``_witness_write``) and
        the gossip digest (``_digest``) compute — sourced straight from the
        stored view rather than re-derived by the caller. This is the public
        evidence ``check_no_equivocation_accepted`` consumes: two conflicting
        writes an equivocating publisher signed at the same
        ``(publisher, version)`` key produce byte-identical ``view_snapshot()``
        tuples (that is what equivocation *is*), so only the ``content_hash``
        reveals the disagreement. Exposing it as a public accessor lets that
        validator stay a pure function over public output — no reach into
        ``_seen``/``_first_write``, no import of the private ``_WriteTag``, no
        re-implementation of the write codec.

        Unlike ``lookup()`` (which filters tombstones out), this covers **every**
        entry in the local view, tombstoned ones included — so a
        live-card-vs-tombstone equivocation at the same version is representable
        here (the two writes hash differently), closing the tombstone gap a
        ``lookup()``-sourced hash would otherwise leave. ``view_snapshot()``'s
        three-tuple shape is deliberately left unchanged (``check_converged``
        and other callers depend on it); this is an **additive** accessor.

        Example::

            cview = reg.content_view()
            # {AgentId("e"): (1, AgentId("e"), False, "abc123...")}
        """
        return {
            aid: (
                v.tag.version,
                v.tag.publisher_id,
                v.tombstone,
                content_hash(v.card, v.tag.version, v.tombstone),
            )
            for aid, v in sorted(self._view.items())
        }

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _apply(self, card: AgentCard, tag: _WriteTag, *, tombstone: bool) -> None:
        existing = self._view.get(card.agent_id)
        if existing is not None and existing.tag >= tag:
            return
        self._view[card.agent_id] = _Versioned(card=card, tag=tag, tombstone=tombstone)

    def _witness_write(self, card: AgentCard, tag: _WriteTag, tombstone: bool) -> bool:
        """Record ``card`` in the witness map; detect + quarantine equivocation.

        Called only for cards that already **passed signature
        verification** — an unverified card proves nothing about what its
        claimed publisher actually signed, so it must never reach the
        witness map (a relay with no private key could otherwise frame an
        honest publisher for equivocation just by broadcasting garbage
        under its ``agent_id``).

        Looks up ``(card.agent_id, tag.version)`` in ``self._seen``:

        * Not seen before → record this write's hash, allow it through
          (returns ``False``).
        * Seen before with the **same** hash → a harmless retransmission of
          the identical write (gossip is allowed to redeliver); allow it
          through (returns ``False``).
        * Seen before with a **different** hash → proof this publisher
          signed two conflicting writes at the same version. Both are
          validly signed — this is exactly what a signature check cannot
          catch. Builds a self-verifying equivocation proof from the first
          write (kept in ``self._first_write``) and this conflicting one,
          quarantines the publisher via ``_quarantine_with_proof`` (records
          ``(publisher, version)`` in ``self.equivocations``, stores the proof
          so it survives eviction and keeps propagating, evicts the card), and
          returns ``True`` so the caller does not ``_apply`` this card either.

        Example::

            if reg._witness_write(card, tag, tombstone):
                continue  # equivocation: do not apply
        """
        key = (card.agent_id, tag.version)
        this_hash = content_hash(card, tag.version, tombstone)
        seen_hash = self._seen.get(key)
        if seen_hash is None:
            self._seen[key] = this_hash
            self._first_write[key] = (card, tag, tombstone)
            return False
        if seen_hash == this_hash:
            return False
        first_write = self._first_write[key]
        proof = _canonical_proof(first_write, (card, tag, tombstone))
        self._quarantine_with_proof(card.agent_id, tag.version, proof)
        return True

    def _quarantine_with_proof(
        self, publisher: AgentId, version: int, proof: tuple[_ProofWrite, _ProofWrite]
    ) -> None:
        """Quarantine ``publisher`` and store its equivocation ``proof`` (idempotent).

        The single quarantine path shared by direct witnessing
        (``_witness_write``) and proof receipt (``_ingest_proof``): appends
        ``(publisher, version)`` to ``self.equivocations``, adds ``publisher``
        to ``self._quarantined``, stores ``proof`` in
        ``self._equivocation_proofs`` (so this node now RELAYS it, surviving
        card eviction), and evicts any card from ``publisher`` in the local
        view. A no-op if ``publisher`` is already quarantined, so a proof that
        arrives after local detection (or a duplicate proof) neither
        double-records the ledger nor re-litigates the quarantine.

        Example::

            reg._quarantine_with_proof(AgentId("e"), 1, proof)
        """
        if publisher in self._quarantined:
            return
        self.equivocations.append((publisher, version))
        self._quarantined.add(publisher)
        self._equivocation_proofs[publisher] = proof
        self._view.pop(publisher, None)

    def _ingest_proof(self, publisher: AgentId, write_a: _ProofWrite, write_b: _ProofWrite) -> None:
        """Verify an inbound equivocation proof for ``publisher`` and quarantine on success.

        Independently re-verifies BOTH writes' signatures against
        ``publisher`` and confirms they genuinely conflict (same
        ``(publisher, version)``, different content hash) — see
        ``_verify_proof``. Only then is ``publisher`` quarantined. A relay
        with no key for an honest ``publisher`` cannot fabricate a passing
        proof (an honest publisher never signs two conflicting cards), so this
        path CANNOT be used to frame an honest publisher; a proof that fails
        verification is recorded as ``REASON_BAD_PROOF`` and ignored.
        Already-quarantined publishers are skipped (idempotent retransmission).

        Example::

            reg._ingest_proof(AgentId("e"), write_a, write_b)
        """
        if publisher in self._quarantined:
            return
        if not _verify_proof(publisher, write_a, write_b, self._identity):
            self.rejections.append((publisher, REASON_BAD_PROOF))
            return
        proof = _canonical_proof(write_a, write_b)
        self._quarantine_with_proof(publisher, write_a[1].version, proof)

    def _known_byzantine(self) -> list[AgentId]:
        """Publishers this node holds an equivocation proof for, sorted deterministically.

        Advertised in the ``OP_DIGEST`` payload so a peer only sends back the
        proofs this node is still missing. Sorted for byte-stable wire output.

        Example::

            known = reg._known_byzantine()  # [AgentId("e0"), AgentId("e1")]
        """
        return sorted(self._equivocation_proofs)

    def _compute_missing_proofs(
        self, sender_known_byz: set[AgentId]
    ) -> list[tuple[AgentId, _ProofWrite, _ProofWrite]]:
        """Proofs to hand a peer: every proof this node holds the peer lacks.

        Given the peer's advertised known-byzantine set (from its digest),
        returns ``(publisher, write_a, write_b)`` for each publisher this node
        can prove byzantine that the peer does not yet know about. Iterated in
        sorted publisher order so the wire bytes are deterministic.

        Example::

            proofs = reg._compute_missing_proofs({AgentId("e0")})
        """
        out: list[tuple[AgentId, _ProofWrite, _ProofWrite]] = []
        for publisher in sorted(self._equivocation_proofs):
            if publisher in sender_known_byz:
                continue
            write_a, write_b = self._equivocation_proofs[publisher]
            out.append((publisher, write_a, write_b))
        return out

    def _digest(self) -> dict[AgentId, tuple[_WriteTag, str]]:
        """Local view summarised as ``{agent: (write_tag, content_hash)}``.

        Unlike ``GossipRegistry._digest`` (tag only), each entry also carries
        ``content_hash(card, version, tombstone)`` so a peer can tell a
        same-``(version, publisher_id)``-but-different-content card apart from
        an identical one — that is what lets ``_compute_missing`` exchange a
        conflicting equivocation card the bare tag alone would treat as "in
        sync." Do not change this shape without changing ``_encode`` /
        ``_decode_digest`` (byzantine_gossip's own copy) in lockstep; the
        reference ``gossip.py`` codec is deliberately left untouched.

        Example::

            digest = reg._digest()  # {AgentId("a"): (_WriteTag(1, ...), "abc123...")}
        """
        return {
            aid: (v.tag, content_hash(v.card, v.tag.version, v.tombstone))
            for aid, v in self._view.items()
        }

    def _compute_missing(
        self, sender_digest: dict[AgentId, tuple[_WriteTag, str]]
    ) -> list[tuple[AgentCard, _WriteTag, bool]]:
        """Cards to push to a peer given its digest — including conflicting same-version writes.

        Pushes a local card when the peer's digest entry for that agent is
        **absent**, **strictly older** (``sender_tag < local_tag``), OR **the
        same tag but a different content hash** — the equivocation case. That
        last clause is the whole fix: two honest nodes that each accepted a
        different, both-validly-signed card from an equivocator at the
        identical ``(publisher, version)`` key have equal ``_WriteTag``s, so
        without comparing content hashes each would judge the other "in sync"
        and never hand over its conflicting copy, leaving the split permanent.
        A same-tag SAME-hash entry is a genuine idempotent redelivery and is
        NOT re-pushed.

        Example::

            missing = reg._compute_missing({AgentId("e"): (tag, "peer_hash")})
        """
        out: list[tuple[AgentCard, _WriteTag, bool]] = []
        for aid, versioned in self._view.items():
            local_hash = content_hash(versioned.card, versioned.tag.version, versioned.tombstone)
            sender_entry = sender_digest.get(aid)
            if (
                sender_entry is None
                or sender_entry[0] < versioned.tag
                or (sender_entry[0] == versioned.tag and sender_entry[1] != local_hash)
            ):
                out.append((versioned.card, versioned.tag, versioned.tombstone))
        return out


# ---------------------------------------------------------------------------
# Signing + verification
# ---------------------------------------------------------------------------


def canonical_card_bytes(card: AgentCard) -> bytes:
    """Canonical content-only bytes of ``card`` for content comparisons.

    Covers ``agent_id``, ``name``, ``capabilities`` (sorted so declaration
    order is not semantically meaningful), and ``endpoint``. Deliberately
    **excludes** ``metadata`` — that is where the signature itself lives
    (``metadata["sig"]``), so including it would make the signed payload
    depend on the signature, which is circular. Any other data a publisher
    wants integrity-protected belongs in one of the covered fields, not in
    ``metadata``. Structural analogue of ``cid_facts.content_hash``, which
    canonicalizes a ``DatasetMetadata``'s content fields the same way.

    **Not** what gets signed — signing binds the full write, including
    ``version``/``tombstone``; see ``canonical_write_bytes``. This helper
    remains for content-only comparisons (e.g. detecting whether two cards
    have identical content regardless of write metadata).

    Example::

        same_content = canonical_card_bytes(card1) == canonical_card_bytes(card2)
    """
    content: dict[str, object] = {
        "agent_id": str(card.agent_id),
        "name": card.name,
        "capabilities": sorted(card.capabilities),
        "endpoint": card.endpoint,
    }
    return json.dumps(content, sort_keys=True, separators=(",", ":")).encode("utf-8")


def canonical_write_bytes(card: AgentCard, version: int, tombstone: bool) -> bytes:
    """Canonical bytes of a **write** — ``card`` content plus ``version`` and ``tombstone``.

    This is what gets signed and verified, not ``canonical_card_bytes``
    alone. Binding the signature to the write tag and tombstone bit (in
    addition to content) closes a replay hole: without it, a relay holding
    no private key can take a genuinely-signed card and re-broadcast it
    under a forged, inflated ``version`` (winning last-writer-wins against
    the publisher's real future writes) or with a flipped ``tombstone`` bit
    (resurrecting a deregistered agent, or deleting a live one) — the card's
    *content* signature still checks out because content-only signing never
    covered the tag or tombstone in the first place. Still excludes
    ``metadata`` for the same circularity reason as ``canonical_card_bytes``.

    Example::

        sig = identity.sign(canonical_write_bytes(card, version=3, tombstone=False))
    """
    content: dict[str, object] = {
        "agent_id": str(card.agent_id),
        "name": card.name,
        "capabilities": sorted(card.capabilities),
        "endpoint": card.endpoint,
        "version": version,
        "tombstone": tombstone,
    }
    return json.dumps(content, sort_keys=True, separators=(",", ":")).encode("utf-8")


def content_hash(card: AgentCard, version: int, tombstone: bool) -> str:
    """Hex SHA-256 of a write's canonical bytes — the mesh's content fingerprint.

    Exactly ``sha256(canonical_write_bytes(card, version,
    tombstone)).hexdigest()``: the single hash used in three places that MUST
    agree byte-for-byte or equivocation detection silently breaks — the
    witness map (``_witness_write``), the digest wire entry (``_encode`` /
    ``_compute_missing``, so a same-version-but-different-content card is
    exchanged rather than judged "in sync"), and the
    ``check_no_equivocation_accepted`` validator. Because it covers
    ``version`` and ``tombstone`` (via ``canonical_write_bytes``), a live card
    and a tombstone at the same version hash differently and are correctly
    treated as conflicting writes.

    Example::

        h = content_hash(card, version=1, tombstone=False)
    """
    return hashlib.sha256(canonical_write_bytes(card, version, tombstone)).hexdigest()


def _sign_card(card: AgentCard, version: int, tombstone: bool, *, identity: Identity) -> AgentCard:
    """Return a copy of ``card`` with a fresh ``metadata["sig"]`` from ``identity``.

    Signs ``canonical_write_bytes(card, version, tombstone)`` — the whole
    write, not just the content — so a relay cannot replay this card under a
    different version or tombstone state and still pass verification.

    The signature ``value`` is stored hex-encoded (not raw ``bytes``):
    ``AgentCard.metadata`` is a plain ``dict[str, Any]``, and round-tripping
    raw ``bytes`` through ``AgentCard.model_dump(mode="json")`` /
    ``model_validate`` inside an ``Any``-typed field is lossy (pydantic has
    no field-type hint telling it to treat that value as bytes on the way
    back in). Hex keeps the wire payload plain JSON end to end.
    """
    sig = identity.sign(canonical_write_bytes(card, version, tombstone))
    metadata = dict(card.metadata)
    metadata["sig"] = {
        "signer": str(sig.signer),
        "value": sig.value.hex(),
        "algorithm": sig.algorithm,
    }
    return card.model_copy(update={"metadata": metadata})


def _verify_card(card: AgentCard, version: int, tombstone: bool, identity: Identity) -> str | None:
    """Verify ``card``'s embedded signature against ``(version, tombstone)``.

    Returns a rejection reason, or ``None`` if the signature is valid.

    Reason codes mirror ``#67``'s taxonomy: ``REASON_MISSING_SIGNATURE`` (no
    ``metadata["sig"]``), ``REASON_SIGNER_MISMATCH`` (``sig.signer`` names a
    different agent than ``card.agent_id`` — impersonation), or
    ``REASON_BAD_SIGNATURE`` (present, correctly-claimed signer, but fails
    cryptographic verification — forgery, in-transit mutation, or a replay
    under a forged ``version``/``tombstone`` that the publisher never
    actually signed).
    """
    raw_sig_meta = card.metadata.get("sig")
    if not isinstance(raw_sig_meta, dict):
        return REASON_MISSING_SIGNATURE
    sig_meta = cast("dict[str, object]", raw_sig_meta)
    signer_raw = sig_meta.get("signer")
    value_raw = sig_meta.get("value")
    if signer_raw is None or value_raw is None:
        return REASON_MISSING_SIGNATURE
    signer = AgentId(str(signer_raw))
    if signer != card.agent_id:
        return REASON_SIGNER_MISMATCH
    try:
        value = bytes.fromhex(str(value_raw))
    except ValueError:
        return REASON_BAD_SIGNATURE
    algorithm = str(sig_meta.get("algorithm", "ed25519"))
    sig = Signature(signer=signer, value=value, algorithm=algorithm)
    if not identity.verify(canonical_write_bytes(card, version, tombstone), sig, card.agent_id):
        return REASON_BAD_SIGNATURE
    return None


# ---------------------------------------------------------------------------
# Helpers (module-private; structural copy of gossip.py's wire codec)
# ---------------------------------------------------------------------------


def _matches(card: AgentCard, query: Query) -> bool:
    if query.capabilities and not all(cap in card.capabilities for cap in query.capabilities):
        return False
    return not (query.name_pattern and query.name_pattern not in card.name)


def _sample_without_replacement(rng: random.Random, peers: list[AgentId], k: int) -> list[AgentId]:
    """Deterministic sample of ``k`` peers from ``peers`` using ``rng``.

    Structural copy of ``gossip.py``'s Fisher-Yates sampler. Used by
    ``_sample_eclipse_resistant`` for the random half of its draw; no
    longer used directly by ``gossip_round`` (see that function and the
    module docstring's Task 4 section).
    """
    pool = list(peers)
    out: list[AgentId] = []
    for _ in range(k):
        j = rng.randint(0, len(pool) - 1)
        out.append(pool[j])
        pool[j] = pool[-1]
        pool.pop()
    return out


def _sample_eclipse_resistant(rng: random.Random, peers: list[AgentId], k: int) -> list[AgentId]:
    """Eclipse-resistant peer sample: a deterministic anchor set + seeded-random rest.

    Splits ``peers`` into two **disjoint** pools and draws from both every
    round, instead of one pure-uniform draw over the whole set (contrast
    ``_sample_without_replacement``, which this function still uses — for
    the random half only):

    * **Anchor pool**: the lexicographically-first ``ceil(k / 2)`` peers by
      ``AgentId`` (``sorted(peers)[:anchor_count]``). Fully deterministic —
      no ``rng`` involved — so it is the *same* set every round for a given
      peer list. This is the eclipse defense: if even one anchor slot is
      held by an honest peer, that peer is gossiped with on *every* round,
      not just when a random draw happens to land on it.
    * **Random pool**: ``floor(k / 2)`` peers drawn via ``rng`` from the
      peers *not* in the anchor pool (``_sample_without_replacement`` over
      ``sorted(peers)[anchor_count:]``). Keeps some randomised mixing so
      gossip still spreads beyond the fixed anchor contacts.

    ``k`` is capped at ``len(peers)`` first, so ``anchor_count +
    random_count == k <= len(peers)`` always holds and the two pools never
    need to overlap or wrap.

    Deterministic: same ``rng`` state + same ``peers`` list → byte-identical
    output every time (the anchor half never depends on ``rng`` at all, and
    the random half is the same seeded Fisher-Yates draw
    ``_sample_without_replacement`` always was).

    **Threat model (see the module docstring's Task 4 section for the full
    argument):** pure uniform sampling of the whole peer set can, for an
    unlucky seed or a large-enough byzantine fraction, draw a round's peers
    entirely from byzantine agents — eclipsing this agent from a specific
    honest publisher's cards indefinitely, since every round redraws
    independently with no memory. Mixing in a fixed anchor contact bounds
    that: as long as one anchor slot is honest, this agent keeps a stable
    honest contact every round regardless of the random draw. This is a
    **heuristic, not a proof** — the anchor set is positional
    (lexicographically-first ``AgentId``), not identity-vetted, so an
    adversary that controls every one of the lexicographically-first
    ``ceil(k / 2)`` ``AgentId``s among a victim's peers defeats the
    guarantee for that victim. See ``VERIFICATION.md`` for that caveat.

    Example::

        chosen = _sample_eclipse_resistant(ctx.rng, peers, fanout)
        same_again = _sample_eclipse_resistant(random.Random(same_seed), peers, fanout)
        assert chosen == same_again
    """
    k = min(k, len(peers))
    if k <= 0:
        return []
    ordered = sorted(peers)
    anchor_count = math.ceil(k / 2)
    anchors = ordered[:anchor_count]
    remaining = ordered[anchor_count:]
    random_count = k - anchor_count
    random_peers = _sample_without_replacement(rng, remaining, random_count)
    return anchors + random_peers


def _encode(digest: dict[AgentId, tuple[_WriteTag, str]], known_byzantine: list[AgentId]) -> bytes:
    """Encode a content-hash-carrying digest plus a known-byzantine set as canonical JSON.

    Wraps two sections: ``"cards"`` (each entry ``[version, publisher_id,
    content_hash]`` — one field wider than ``gossip.py``'s ``[version,
    publisher_id]`` codec, which this is a deliberate divergent copy of, NOT a
    change to) and ``"byz"`` (the sorted list of publisher ids this node holds
    an equivocation proof for, so the peer skips proofs this node already has).
    ``sort_keys`` plus the pre-sorted ``byz`` list keep the output
    byte-identical for a given state, preserving determinism.

    Example::

        raw = _encode({AgentId("a"): (_WriteTag(1, AgentId("a")), "abc123")}, [AgentId("e")])
    """
    cards = {
        str(aid): [t.version, str(t.publisher_id), chash] for aid, (t, chash) in digest.items()
    }
    obj = {"cards": cards, "byz": [str(aid) for aid in known_byzantine]}
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _decode_digest(raw: bytes) -> tuple[dict[AgentId, tuple[_WriteTag, str]], set[AgentId]]:
    """Decode an ``_encode``d digest into ``({agent: (tag, hash)}, known_byzantine_set)``.

    Inverse of ``_encode``; reads the ``"cards"`` section's three-field
    ``[version, publisher_id, content_hash]`` entries and the ``"byz"``
    known-byzantine id list.

    Example::

        digest, known_byz = _decode_digest(raw)
    """
    obj = json.loads(raw.decode())
    cards = {
        AgentId(aid): (_WriteTag(version=int(v), publisher_id=AgentId(pid)), str(chash))
        for aid, (v, pid, chash) in obj["cards"].items()
    }
    known_byz = {AgentId(str(aid)) for aid in obj["byz"]}
    return cards, known_byz


def _encode_write(write: _ProofWrite) -> dict[str, object]:
    """Encode a single ``(card, tag, tombstone)`` write as a JSON-ready dict.

    Shared by ``_encode_push`` and ``_encode_proofs`` so a proof's writes and
    a pushed card use the identical, replay-stable wire shape.

    Example::

        obj = _encode_write((card, _WriteTag(1, AgentId("e")), False))
    """
    card, tag, tombstone = write
    return {
        "card": card.model_dump(mode="json"),
        "version": tag.version,
        "publisher": str(tag.publisher_id),
        "tombstone": tombstone,
    }


def _decode_write(entry: dict[str, object]) -> _ProofWrite:
    """Decode a single write dict produced by ``_encode_write``.

    Example::

        write = _decode_write({"card": {...}, "version": 1, "publisher": "e", "tombstone": False})
    """
    card = AgentCard.model_validate(entry["card"])
    tag = _WriteTag(
        version=int(entry["version"]),  # type: ignore[arg-type]
        publisher_id=AgentId(str(entry["publisher"])),
    )
    return card, tag, bool(entry["tombstone"])


def _encode_push(items: list[tuple[AgentCard, _WriteTag, bool]]) -> bytes:
    obj = [_encode_write(item) for item in items]
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _decode_push(raw: bytes) -> list[tuple[AgentCard, _WriteTag, bool]]:
    obj: list[dict[str, object]] = json.loads(raw.decode())
    return [_decode_write(entry) for entry in obj]


def _canonical_proof(write_x: _ProofWrite, write_y: _ProofWrite) -> tuple[_ProofWrite, _ProofWrite]:
    """Order two conflicting writes canonically (by content hash) into a proof pair.

    Both witnessing nodes (which may have seen the two sides in opposite
    order) and every node that later receives the proof end up with the SAME
    byte-ordering, so proof bytes are node-independent and replay-stable.

    Example::

        proof = _canonical_proof(write_a, write_b)
    """
    hx = content_hash(write_x[0], write_x[1].version, write_x[2])
    hy = content_hash(write_y[0], write_y[1].version, write_y[2])
    return (write_x, write_y) if hx <= hy else (write_y, write_x)


def _verify_proof(
    publisher: AgentId, write_a: _ProofWrite, write_b: _ProofWrite, identity: Identity
) -> bool:
    """Return whether ``(write_a, write_b)`` is a genuine equivocation proof for ``publisher``.

    True only if BOTH writes are authored by ``publisher`` at the SAME
    version, BOTH signatures independently verify (via ``_verify_card``), and
    the two writes genuinely CONFLICT (different content hash). This is the
    anti-framing core: a relay cannot fabricate a passing proof for an honest
    publisher, because forging it would require two validly-signed conflicting
    cards under that publisher's key — which an honest publisher never
    produces. Mutating or forging one side makes that side's signature fail,
    so the proof is rejected and the publisher is NOT quarantined.

    Example::

        assert _verify_proof(AgentId("e"), write_a, write_b, identity)
    """
    card_a, tag_a, tomb_a = write_a
    card_b, tag_b, tomb_b = write_b
    if tag_a.version != tag_b.version:
        return False
    for card, tag in ((card_a, tag_a), (card_b, tag_b)):
        if card.agent_id != publisher or tag.publisher_id != publisher:
            return False
    if _verify_card(card_a, tag_a.version, tomb_a, identity) is not None:
        return False
    if _verify_card(card_b, tag_b.version, tomb_b, identity) is not None:
        return False
    hash_a = content_hash(card_a, tag_a.version, tomb_a)
    hash_b = content_hash(card_b, tag_b.version, tomb_b)
    return hash_a != hash_b


def _encode_proofs(items: list[tuple[AgentId, _ProofWrite, _ProofWrite]]) -> bytes:
    """Encode equivocation proofs as canonical JSON for an ``OP_EQPROOF`` message.

    Each entry is ``{"publisher": id, "writes": [write_a, write_b]}`` with each
    write in ``_encode_write`` shape. Callers pass items in sorted-publisher
    order and each proof's two writes are already canonically ordered
    (``_canonical_proof``), so the output is byte-stable across replays.

    Example::

        raw = _encode_proofs([(AgentId("e"), write_a, write_b)])
    """
    obj = [
        {"publisher": str(publisher), "writes": [_encode_write(write_a), _encode_write(write_b)]}
        for publisher, write_a, write_b in items
    ]
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _decode_proofs(raw: bytes) -> list[tuple[AgentId, _ProofWrite, _ProofWrite]]:
    """Decode an ``_encode_proofs`` payload into ``(publisher, write_a, write_b)`` tuples.

    Example::

        proofs = _decode_proofs(raw)
    """
    obj: list[dict[str, object]] = json.loads(raw.decode())
    out: list[tuple[AgentId, _ProofWrite, _ProofWrite]] = []
    for entry in obj:
        publisher = AgentId(str(entry["publisher"]))
        writes = cast("list[dict[str, object]]", entry["writes"])
        write_a = _decode_write(writes[0])
        write_b = _decode_write(writes[1])
        out.append((publisher, write_a, write_b))
    return out
