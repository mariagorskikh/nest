# SPDX-License-Identifier: Apache-2.0
"""Conformance + security tests for the byzantine_gossip registry plugin.

Task 1 only proved the plugin resolves via ``PluginRegistry`` and conforms
to the ``Registry`` Protocol. Task 2 adds the actual byzantine-resistance
primitive this plugin exists for: every card is signed at registration and
re-verified before being merged into a peer's view during gossip
propagation. That is a strictly stronger guarantee than a registration-only
signing scheme (prior art: ``#67``) -- ``#67``'s check runs once, at the
publisher's own registration call, so a compromised or malicious gossip
relay can still forge or impersonate cards while *propagating* them and no
downstream verifier ever re-checks them. This plugin re-verifies on every
hop, which is what Tasks 3-4 build byzantine-quarantine and eclipse
resistance on top of.
"""

from __future__ import annotations

import asyncio
import json
import random

from nest_core.layers.registry import Registry
from nest_core.plugins import PluginRegistry
from nest_core.types import AgentCard, AgentId, Query, Signature
from nest_plugins_reference.identity.did_key import DidKeyIdentity
from nest_plugins_reference.registry.byzantine_gossip import (
    OP_EQPROOF,
    ByzantineGossipRegistry,
    _sample_eclipse_resistant,  # pyright: ignore[reportPrivateUsage]
    _sample_without_replacement,  # pyright: ignore[reportPrivateUsage]
    canonical_card_bytes,
    canonical_write_bytes,
)
from nest_plugins_reference.registry.gossip import (
    GOSSIP_PREFIX,
    OP_PUSH,
    GossipNetwork,
    _WriteTag,  # pyright: ignore[reportPrivateUsage]
)


def test_resolves_and_conforms() -> None:
    cls = PluginRegistry().resolve("registry", "byzantine_gossip")
    net = GossipNetwork(agent_ids=[AgentId("a"), AgentId("b")])
    reg = cls(AgentId("a"), net, DidKeyIdentity(AgentId("a"), seed=b"s"))
    assert isinstance(reg, Registry)


class _StubContext:
    """Minimal ``AgentContext`` stand-in.

    The ``OP_PUSH`` branch of ``handle_gossip`` never calls back into the
    context (unlike ``OP_DIGEST``, which replies via ``ctx.send``), so a
    stub that fails loudly if that ever changes is enough for these tests.
    """

    async def send(self, to: AgentId, payload: bytes) -> None:  # pragma: no cover
        msg = "OP_PUSH handling must not need ctx.send"
        raise AssertionError(msg)


def _peered_identities(*agent_ids: str) -> dict[str, DidKeyIdentity]:
    """Build one ``DidKeyIdentity`` per agent id, each knowing every peer's public key."""
    idents = {aid: DidKeyIdentity(AgentId(aid), seed=f"seed-{aid}".encode()) for aid in agent_ids}
    for aid, ident in idents.items():
        for peer_id, peer_ident in idents.items():
            if peer_id != aid:
                ident.register_peer(AgentId(peer_id), peer_ident.public_key)
    return idents


def _push_payload(entries: list[tuple[AgentCard, _WriteTag, bool]]) -> bytes:
    """Hand-encode an ``OP_PUSH`` wire payload -- mirrors ``gossip.py``'s ``_encode_push``."""
    obj = [
        {
            "card": card.model_dump(mode="json"),
            "version": tag.version,
            "publisher": str(tag.publisher_id),
            "tombstone": tombstone,
        }
        for card, tag, tombstone in entries
    ]
    body = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
    return GOSSIP_PREFIX + OP_PUSH + body


# ---------------------------------------------------------------------------
# The core moat: forged/impersonated cards are rejected during propagation
# ---------------------------------------------------------------------------


def test_forged_card_rejected_but_honest_accepted() -> None:
    """Build an honest signed card from A; hand-forge a card claiming A's id.

    Feed both to ``reg_b.handle_gossip`` via one ``OP_PUSH`` payload: the
    honest card must land in ``reg_b``'s view, the forged one must not, and
    the rejection must be recorded as ``("a", "bad_signature")``.
    """
    idents = _peered_identities("a", "b", "m")
    net = GossipNetwork(agent_ids=[AgentId("a"), AgentId("b"), AgentId("m")])
    reg_a = ByzantineGossipRegistry(AgentId("a"), net, idents["a"])
    reg_b = ByzantineGossipRegistry(AgentId("b"), net, idents["b"])

    asyncio.run(reg_a.register(AgentCard(agent_id=AgentId("a"), name="A", capabilities=["sell"])))
    [honest_card] = asyncio.run(reg_a.lookup(Query()))
    honest_tag = _WriteTag(version=1, publisher_id=AgentId("a"))

    # M forges a card claiming to be "a", signed with M's own key but the
    # signature metadata still *claims* signer "a" -- a bad/mutated
    # signature, not just a mismatched claim.
    forged_content = AgentCard(agent_id=AgentId("a"), name="EVIL")
    bogus_sig = idents["m"].sign(canonical_card_bytes(forged_content))
    forged_card = AgentCard(
        agent_id=AgentId("a"),
        name="EVIL",
        metadata={
            "sig": {
                "signer": "a",
                "value": bogus_sig.value.hex(),
                "algorithm": bogus_sig.algorithm,
            }
        },
    )
    forged_tag = _WriteTag(version=1, publisher_id=AgentId("a"))

    payload = _push_payload(
        [
            (honest_card, honest_tag, False),
            (forged_card, forged_tag, False),
        ]
    )

    result = asyncio.run(reg_b.handle_gossip(AgentId("a"), payload, _StubContext()))  # type: ignore[arg-type]

    assert result is True
    snap = reg_b.view_snapshot()
    assert AgentId("a") in snap
    [seen_card] = asyncio.run(reg_b.lookup(Query()))
    assert seen_card.name == "A"  # the forged "EVIL" card never landed
    assert reg_b.rejections == [(AgentId("a"), "bad_signature")]


def test_missing_signature_rejected() -> None:
    idents = _peered_identities("a", "b")
    net = GossipNetwork(agent_ids=[AgentId("a"), AgentId("b")])
    reg_b = ByzantineGossipRegistry(AgentId("b"), net, idents["b"])

    unsigned_card = AgentCard(agent_id=AgentId("a"), name="A")
    tag = _WriteTag(version=1, publisher_id=AgentId("a"))
    payload = _push_payload([(unsigned_card, tag, False)])

    asyncio.run(reg_b.handle_gossip(AgentId("a"), payload, _StubContext()))  # type: ignore[arg-type]

    assert AgentId("a") not in reg_b.view_snapshot()
    assert reg_b.rejections == [(AgentId("a"), "missing_signature")]


def test_signer_mismatch_rejected() -> None:
    """M signs honestly with its own key but attaches the card to A's identity."""
    idents = _peered_identities("a", "b", "m")
    net = GossipNetwork(agent_ids=[AgentId("a"), AgentId("b"), AgentId("m")])
    reg_b = ByzantineGossipRegistry(AgentId("b"), net, idents["b"])

    content = AgentCard(agent_id=AgentId("a"), name="A")
    m_sig = idents["m"].sign(canonical_card_bytes(content))
    impersonating_card = AgentCard(
        agent_id=AgentId("a"),
        name="A",
        metadata={"sig": {"signer": "m", "value": m_sig.value.hex(), "algorithm": m_sig.algorithm}},
    )
    tag = _WriteTag(version=1, publisher_id=AgentId("a"))
    payload = _push_payload([(impersonating_card, tag, False)])

    asyncio.run(reg_b.handle_gossip(AgentId("a"), payload, _StubContext()))  # type: ignore[arg-type]

    assert AgentId("a") not in reg_b.view_snapshot()
    assert reg_b.rejections == [(AgentId("a"), "signer_mismatch")]


# ---------------------------------------------------------------------------
# The write-binding moat: content-only signing is not enough (replay/un-delete)
# ---------------------------------------------------------------------------


def test_replay_with_inflated_version_rejected() -> None:
    """A relay with NO private key replays a genuinely-signed card under a forged higher version.

    Content-only signing (sign ``agent_id``/``name``/``capabilities``/
    ``endpoint`` alone) would let this through: the card's content
    signature still checks out, and the wire-supplied ``_WriteTag`` is
    merged verbatim by last-writer-wins, letting a relay with no signing
    key inflate a publisher's version and block/override their real future
    writes. Binding the signature to ``(content, version, tombstone)``
    closes it.
    """
    idents = _peered_identities("a", "b")
    net = GossipNetwork(agent_ids=[AgentId("a"), AgentId("b")])
    reg_a = ByzantineGossipRegistry(AgentId("a"), net, idents["a"])
    reg_b = ByzantineGossipRegistry(AgentId("b"), net, idents["b"])

    asyncio.run(reg_a.register(AgentCard(agent_id=AgentId("a"), name="A", capabilities=["sell"])))
    [honest_card] = asyncio.run(reg_a.lookup(Query()))

    # M (no private key) replays A's honestly-signed card, forging a much
    # higher version so it wins last-writer-wins against A's real writes.
    forged_tag = _WriteTag(version=999, publisher_id=AgentId("a"))
    payload = _push_payload([(honest_card, forged_tag, False)])

    result = asyncio.run(reg_b.handle_gossip(AgentId("a"), payload, _StubContext()))  # type: ignore[arg-type]

    assert result is True
    assert AgentId("a") not in reg_b.view_snapshot()
    assert reg_b.rejections == [(AgentId("a"), "bad_signature")]


def test_tombstone_flip_rejected() -> None:
    """A relay flips an honest deregister's tombstone bit back to False -- an "un-delete".

    A honestly issued this deregister; its ``metadata["sig"]`` was computed
    over ``canonical_write_bytes(card, version, tombstone=True)``. A relay
    (no private key) forwards the same card+version but flips ``tombstone``
    to ``False`` on the wire, trying to resurrect A in B's view. That must
    fail verification and be dropped, not silently un-delete A.
    """
    idents = _peered_identities("a", "b")
    net = GossipNetwork(agent_ids=[AgentId("a"), AgentId("b")])
    reg_a = ByzantineGossipRegistry(AgentId("a"), net, idents["a"])
    reg_b = ByzantineGossipRegistry(AgentId("b"), net, idents["b"])

    asyncio.run(reg_a.register(AgentCard(agent_id=AgentId("a"), name="A", capabilities=["sell"])))
    asyncio.run(reg_a.deregister(AgentId("a")))
    tombstoned = reg_a._view[AgentId("a")]  # pyright: ignore[reportPrivateUsage]
    assert tombstoned.tombstone is True

    payload = _push_payload([(tombstoned.card, tombstoned.tag, False)])

    result = asyncio.run(reg_b.handle_gossip(AgentId("a"), payload, _StubContext()))  # type: ignore[arg-type]

    assert result is True
    assert AgentId("a") not in reg_b.view_snapshot()  # un-delete did NOT land
    assert reg_b.rejections == [(AgentId("a"), "bad_signature")]


def test_honest_card_mutated_in_transit_rejected() -> None:
    """A relay mutates a capability on an honestly-signed card after signing.

    Covers the module docstring's "mutated in transit" claim, which had no
    dedicated test previously -- ``test_forged_card_rejected_but_honest_accepted``
    only exercises a hand-forged card with a bad signature, not a mutation
    of an otherwise-genuine signed card.
    """
    idents = _peered_identities("a", "b")
    net = GossipNetwork(agent_ids=[AgentId("a"), AgentId("b")])
    reg_a = ByzantineGossipRegistry(AgentId("a"), net, idents["a"])
    reg_b = ByzantineGossipRegistry(AgentId("b"), net, idents["b"])

    asyncio.run(reg_a.register(AgentCard(agent_id=AgentId("a"), name="A", capabilities=["sell"])))
    [honest_card] = asyncio.run(reg_a.lookup(Query()))
    honest_tag = _WriteTag(version=1, publisher_id=AgentId("a"))

    mutated_card = honest_card.model_copy(update={"capabilities": ["buy"]})
    payload = _push_payload([(mutated_card, honest_tag, False)])

    asyncio.run(reg_b.handle_gossip(AgentId("a"), payload, _StubContext()))  # type: ignore[arg-type]

    assert AgentId("a") not in reg_b.view_snapshot()
    assert reg_b.rejections == [(AgentId("a"), "bad_signature")]


# ---------------------------------------------------------------------------
# canonical_card_bytes + register signing
# ---------------------------------------------------------------------------


def test_canonical_card_bytes_excludes_metadata_and_sorts_capabilities() -> None:
    card1 = AgentCard(agent_id=AgentId("a"), name="A", capabilities=["y", "x"], metadata={"n": 1})
    card2 = AgentCard(agent_id=AgentId("a"), name="A", capabilities=["x", "y"], metadata={"n": 2})
    assert canonical_card_bytes(card1) == canonical_card_bytes(card2)


def test_canonical_card_bytes_differs_on_content_change() -> None:
    card1 = AgentCard(agent_id=AgentId("a"), name="A")
    card2 = AgentCard(agent_id=AgentId("a"), name="B")
    assert canonical_card_bytes(card1) != canonical_card_bytes(card2)


# ---------------------------------------------------------------------------
# Equivocation: BOTH cards are validly signed -- registration-signing alone
# (#67) and per-hop re-verification (Task 2) both accept either one in
# isolation. The only way to catch this is noticing that the SAME publisher
# signed TWO DIFFERENT writes at the SAME version.
# ---------------------------------------------------------------------------


def test_equivocation_detected_and_quarantined() -> None:
    """Publisher E validly signs two different cards at the same version.

    Both ``card_1`` and ``card_2`` verify individually -- each carries a
    genuine signature from E over its own ``canonical_write_bytes``. Neither
    is forged, mutated, impersonated, or replayed with a tampered tag, so
    every check from Task 2 (and ``#67``'s registration-only signing) passes
    both of them. The equivocation is only visible by comparing the two
    writes to each other: same ``(publisher, version)``, different content.
    Feeding both to ``reg_b`` via gossip must: record ``(e, version)`` in
    ``equivocations``, quarantine E, evict E's card from the local view, and
    refuse every subsequent card from E -- honest-looking or not.
    """
    idents = _peered_identities("e", "b")
    net = GossipNetwork(agent_ids=[AgentId("e"), AgentId("b")])
    reg_b = ByzantineGossipRegistry(AgentId("b"), net, idents["b"])

    version = 1
    tag = _WriteTag(version=version, publisher_id=AgentId("e"))

    card_1 = AgentCard(agent_id=AgentId("e"), name="E", capabilities=["sell"])
    sig_1 = idents["e"].sign(canonical_write_bytes(card_1, version, False))
    signed_1 = card_1.model_copy(
        update={
            "metadata": {
                "sig": {"signer": "e", "value": sig_1.value.hex(), "algorithm": sig_1.algorithm}
            }
        }
    )

    card_2 = AgentCard(agent_id=AgentId("e"), name="E", capabilities=["buy"])
    sig_2 = idents["e"].sign(canonical_write_bytes(card_2, version, False))
    signed_2 = card_2.model_copy(
        update={
            "metadata": {
                "sig": {"signer": "e", "value": sig_2.value.hex(), "algorithm": sig_2.algorithm}
            }
        }
    )

    # First write arrives via gossip: verifies, lands normally.
    payload_1 = _push_payload([(signed_1, tag, False)])
    result_1 = asyncio.run(reg_b.handle_gossip(AgentId("e"), payload_1, _StubContext()))  # type: ignore[arg-type]
    assert result_1 is True
    assert AgentId("e") in reg_b.view_snapshot()

    # Second, CONFLICTING write at the SAME version arrives: also verifies
    # in isolation, but now the witness map catches the equivocation.
    payload_2 = _push_payload([(signed_2, tag, False)])
    result_2 = asyncio.run(reg_b.handle_gossip(AgentId("e"), payload_2, _StubContext()))  # type: ignore[arg-type]
    assert result_2 is True

    assert reg_b.equivocations == [(AgentId("e"), version)]
    assert AgentId("e") in reg_b._quarantined  # pyright: ignore[reportPrivateUsage]
    assert AgentId("e") not in reg_b.view_snapshot()
    assert asyncio.run(reg_b.lookup(Query())) == []

    # A THIRD, honest-looking card (fresh version, genuinely signed) from E
    # is still refused outright -- quarantine is sticky, not just a one-time
    # conflict resolution.
    tag_3 = _WriteTag(version=2, publisher_id=AgentId("e"))
    card_3 = AgentCard(agent_id=AgentId("e"), name="E", capabilities=["sell"])
    sig_3 = idents["e"].sign(canonical_write_bytes(card_3, tag_3.version, False))
    signed_3 = card_3.model_copy(
        update={
            "metadata": {
                "sig": {"signer": "e", "value": sig_3.value.hex(), "algorithm": sig_3.algorithm}
            }
        }
    )
    payload_3 = _push_payload([(signed_3, tag_3, False)])
    asyncio.run(reg_b.handle_gossip(AgentId("e"), payload_3, _StubContext()))  # type: ignore[arg-type]

    assert AgentId("e") not in reg_b.view_snapshot()
    assert reg_b.rejections[-1] == (AgentId("e"), "quarantined")
    # Quarantine did not spuriously grow the equivocations ledger.
    assert reg_b.equivocations == [(AgentId("e"), version)]


# ---------------------------------------------------------------------------
# Disjoint-delivery equivocation: the equivocator sends card_1 ONLY to node A
# and card_2 ONLY to node B, with NO common recipient. Neither node ever sees
# both cards from the equivocator directly, so detection depends entirely on
# the honest anti-entropy mesh propagating the conflicting same-version card
# between A and B. A digest that carries only ``(version, publisher_id)``
# judges A's ``(e, 1)`` and B's ``(e, 1)`` as "already in sync" (equal tag) and
# NEVER exchanges the conflicting card -- the split is permanent and no honest
# node ever fires the witness map. Carrying a content hash in the digest makes
# a same-version-but-different-content entry something to exchange, so each
# side hands the other its copy and BOTH independently detect + quarantine E.
# ---------------------------------------------------------------------------


class _QueuedContext:
    """Routing context that ENQUEUES sends instead of delivering them inline.

    ``_RoutingContext`` above delivers a payload straight into the target's
    ``handle_gossip`` (depth-first), so two messages can never be "in flight"
    at once. The real ``InMemoryTransport`` (see
    ``nest_core.sim.transport``) instead pushes every send onto the
    simulator's event queue and drains it breadth-first, so a message A sends
    to B and a message B sends to A genuinely cross -- both are computed from
    each sender's pre-delivery state before either is processed. That
    crossing is exactly what lets two nodes holding conflicting same-version
    cards each hand the other its copy in one round; this stand-in models it
    faithfully with a shared FIFO queue.

    Example::

        queue: list[tuple[AgentId, AgentId, bytes]] = []
        ctx = _QueuedContext(AgentId("a"), random.Random(0), regs, ctxs, queue)
    """

    def __init__(
        self,
        agent_id: AgentId,
        rng: random.Random,
        registries: dict[AgentId, ByzantineGossipRegistry],
        contexts: dict[AgentId, _QueuedContext],
        queue: list[tuple[AgentId, AgentId, bytes]],
    ) -> None:
        self.agent_id = agent_id
        self.rng = rng
        self._registries = registries
        self._contexts = contexts
        self._queue = queue

    async def send(self, to: AgentId, payload: bytes) -> None:
        self._queue.append((to, self.agent_id, payload))


async def _drain(
    queue: list[tuple[AgentId, AgentId, bytes]],
    registries: dict[AgentId, ByzantineGossipRegistry],
    contexts: dict[AgentId, _QueuedContext],
) -> None:
    """Deliver every queued message FIFO, letting handlers enqueue their replies.

    Example::

        await _drain(queue, registries, contexts)
    """
    while queue:
        to, sender, payload = queue.pop(0)
        await registries[to].handle_gossip(sender, payload, contexts[to])  # type: ignore[arg-type]


def _signed_card(
    ident: DidKeyIdentity, publisher: AgentId, version: int, capabilities: list[str]
) -> AgentCard:
    """Build a genuinely-signed card for ``publisher`` over its full write.

    Example::

        card = _signed_card(idents["e"], AgentId("e"), 1, ["sell"])
    """
    content = AgentCard(agent_id=publisher, name=str(publisher), capabilities=capabilities)
    sig = ident.sign(canonical_write_bytes(content, version, False))
    return content.model_copy(
        update={
            "metadata": {
                "sig": {
                    "signer": str(publisher),
                    "value": sig.value.hex(),
                    "algorithm": sig.algorithm,
                }
            }
        }
    )


def test_disjoint_delivery_equivocation_is_caught() -> None:
    """Equivocator E hits A and B with conflicting v1 cards; only the mesh can catch it.

    E signs ``card_1`` (``["sell"]``) and ``card_2`` (``["buy"]``) at the SAME
    version 1 -- both individually valid. ``card_1`` is delivered ONLY to node
    A and ``card_2`` ONLY to node B (no common recipient), so neither node can
    detect the equivocation from its own inbox. A and B then run honest gossip
    rounds with each other over a queued (message-crossing) transport. With
    the content hash carried in the digest, A advertises ``(e, 1, hash_1)`` and
    B advertises ``(e, 1, hash_2)``; each treats the other's same-version
    -different-hash entry as something to exchange, hands over its card, and
    both independently fire the witness map. Result: BOTH ledgers record
    ``(e, 1)``, E is quarantined at both, and E is absent from both views.

    RED before the content-hash-in-digest fix (equal ``(version,
    publisher_id)`` tags look "in sync", the conflicting card never
    propagates, the split is permanent); GREEN after.
    """
    idents = _peered_identities("a", "b", "e")
    net = GossipNetwork(agent_ids=[AgentId("a"), AgentId("b")])  # E is not a gossip peer
    reg_a = ByzantineGossipRegistry(AgentId("a"), net, idents["a"])
    reg_b = ByzantineGossipRegistry(AgentId("b"), net, idents["b"])
    registries = {AgentId("a"): reg_a, AgentId("b"): reg_b}
    queue: list[tuple[AgentId, AgentId, bytes]] = []
    contexts: dict[AgentId, _QueuedContext] = {}
    for aid in (AgentId("a"), AgentId("b")):
        contexts[aid] = _QueuedContext(aid, random.Random(0), registries, contexts, queue)

    tag = _WriteTag(version=1, publisher_id=AgentId("e"))
    card_1 = _signed_card(idents["e"], AgentId("e"), 1, ["sell"])
    card_2 = _signed_card(idents["e"], AgentId("e"), 1, ["buy"])

    # Disjoint delivery: card_1 ONLY to A, card_2 ONLY to B.
    async def _deliver(reg: ByzantineGossipRegistry, card: AgentCard, aid: AgentId) -> None:
        await reg.handle_gossip(AgentId("e"), _push_payload([(card, tag, False)]), contexts[aid])  # type: ignore[arg-type]

    asyncio.run(_deliver(reg_a, card_1, AgentId("a")))
    asyncio.run(_deliver(reg_b, card_2, AgentId("b")))

    # Pre-gossip: a genuine, permanent-looking split -- A sees "sell", B "buy".
    assert AgentId("e") in reg_a.view_snapshot()
    assert AgentId("e") in reg_b.view_snapshot()
    assert reg_a.equivocations == []
    assert reg_b.equivocations == []

    async def _rounds() -> None:
        for _ in range(4):
            await reg_a.gossip_round(contexts[AgentId("a")])  # type: ignore[arg-type]
            await reg_b.gossip_round(contexts[AgentId("b")])  # type: ignore[arg-type]
            await _drain(queue, registries, contexts)

    asyncio.run(_rounds())

    # BOTH honest nodes independently detect + quarantine E and converge to "E absent".
    assert reg_a.equivocations == [(AgentId("e"), 1)]
    assert reg_b.equivocations == [(AgentId("e"), 1)]
    assert AgentId("e") in reg_a._quarantined  # pyright: ignore[reportPrivateUsage]
    assert AgentId("e") in reg_b._quarantined  # pyright: ignore[reportPrivateUsage]
    assert AgentId("e") not in reg_a.view_snapshot()
    assert AgentId("e") not in reg_b.view_snapshot()


# ---------------------------------------------------------------------------
# Disjoint MULTI-equivocator at scale: the earlier content-hash-in-digest fix
# closes the N=2 / single-equivocator case, but NOT disjoint delivery with
# N>2 honest nodes and several equivocators. Once a node detects an
# equivocation it EVICTS the card, dropping it from `_digest`, so it stops
# relaying the conflicting copy onward. Under disjoint delivery (card1 -> group
# A only, card2 -> group B only, no common recipient) a node that received only
# one side, whose reachable counterparts holding the other side all evict
# before the other card reaches it, is left PERMANENTLY holding a validly
# -signed equivocated card it never detects. The fix is to gossip the
# equivocation PROOF (the two conflicting signed writes) independently of card
# eviction, so a stranded node still learns the publisher is byzantine from any
# honest neighbor. This test reproduces the auditor's scenario (N=10, 5
# equivocators, seed 1 strands the whole of group A permanently -- identical at
# 40 and 500 rounds) and asserts the post-fix property: EVERY honest node
# quarantines EVERY equivocator, none is stranded, and no honest publisher is
# falsely quarantined.
# ---------------------------------------------------------------------------


def test_disjoint_multi_equivocator_no_stranding() -> None:
    """N=10 honest, 5 equivocators, disjoint delivery: no honest node is stranded.

    Each equivocator ``eK`` signs ``card1`` (``["sell"]``) and ``card2``
    (``["buy"]``) at the SAME version 1 -- both individually valid. ``card1``
    is delivered ONLY to group A (``h00``..``h04``) and ``card2`` ONLY to group
    B (``h05``..``h09``), with no common recipient. Every honest node also
    registers its own honest card. The honest nodes then run many gossip rounds
    over the message-crossing ``_QueuedContext`` transport.

    RED before the proof-gossip fix: at seed 1 the whole of group A strands --
    each of ``h00``..``h04`` permanently holds all five equivocated cards and
    detects none, because group B evicts (and thus stops relaying) the
    conflicting copies before they reach group A. GREEN after: the equivocation
    proof propagates independently of card eviction, so EVERY honest node
    quarantines EVERY equivocator, no honest node retains any equivocated card,
    and NO honest publisher is falsely quarantined.
    """
    honest = [f"h{i:02d}" for i in range(10)]
    equivocators = [f"e{i}" for i in range(5)]
    idents = _peered_identities(*honest, *equivocators)
    net = GossipNetwork(agent_ids=[AgentId(h) for h in honest])  # equivocators are not peers
    registries = {AgentId(h): ByzantineGossipRegistry(AgentId(h), net, idents[h]) for h in honest}
    queue: list[tuple[AgentId, AgentId, bytes]] = []
    contexts: dict[AgentId, _QueuedContext] = {}
    for h in honest:
        contexts[AgentId(h)] = _QueuedContext(
            AgentId(h), random.Random(1), registries, contexts, queue
        )

    group_a = [AgentId(h) for h in honest[:5]]
    group_b = [AgentId(h) for h in honest[5:]]

    async def _drive() -> None:
        # Every honest node registers a genuine card -- these must NEVER be
        # mistaken for equivocation (no false positive).
        for h in honest:
            await registries[AgentId(h)].register(
                AgentCard(agent_id=AgentId(h), name=h.upper(), capabilities=["sell"])
            )

        # Disjoint delivery: card1 ONLY to group A, card2 ONLY to group B.
        for e in equivocators:
            tag = _WriteTag(version=1, publisher_id=AgentId(e))
            card_1 = _signed_card(idents[e], AgentId(e), 1, ["sell"])
            card_2 = _signed_card(idents[e], AgentId(e), 1, ["buy"])
            for aid in group_a:
                await registries[aid].handle_gossip(
                    AgentId(e),
                    _push_payload([(card_1, tag, False)]),
                    contexts[aid],  # type: ignore[arg-type]
                )
            for bid in group_b:
                await registries[bid].handle_gossip(
                    AgentId(e),
                    _push_payload([(card_2, tag, False)]),
                    contexts[bid],  # type: ignore[arg-type]
                )

        for _ in range(40):
            for h in honest:
                await registries[AgentId(h)].gossip_round(contexts[AgentId(h)])  # type: ignore[arg-type]
            await _drain(queue, registries, contexts)

    asyncio.run(_drive())

    equivocator_ids = {AgentId(e) for e in equivocators}
    honest_ids = {AgentId(h) for h in honest}
    for h in honest:
        reg = registries[AgentId(h)]
        caught = {pid for pid, _v in reg.equivocations}
        assert caught == equivocator_ids, (
            f"{h} caught {sorted(map(str, caught))}, expected every equivocator "
            f"{sorted(map(str, equivocator_ids))} -- a stranded node did not detect the conflict"
        )
        snap = reg.view_snapshot()
        still_held = sorted(str(a) for a in equivocator_ids & snap.keys())
        assert not still_held, (
            f"{h} still holds equivocated card(s) {still_held} "
            f"-- stranded (eviction halted relay before the conflict reached it)"
        )
        # No honest publisher was falsely quarantined, and every honest card
        # converged into this node's view.
        assert not (caught & honest_ids), f"{h} falsely quarantined an honest publisher: {caught}"
        assert honest_ids <= snap.keys(), f"{h} is missing honest cards after convergence"


_TestWrite = tuple[AgentCard, _WriteTag, bool]


def _proof_payload(entries: list[tuple[AgentId, _TestWrite, _TestWrite]]) -> bytes:
    """Hand-encode an ``OP_EQPROOF`` wire payload -- mirrors ``byzantine_gossip._encode_proofs``.

    Example::

        payload = _proof_payload([(AgentId("e"), write_a, write_b)])
    """

    def _write(entry: _TestWrite) -> dict[str, object]:
        card, tag, tombstone = entry
        return {
            "card": card.model_dump(mode="json"),
            "version": tag.version,
            "publisher": str(tag.publisher_id),
            "tombstone": tombstone,
        }

    obj = [
        {"publisher": str(publisher), "writes": [_write(write_a), _write(write_b)]}
        for publisher, write_a, write_b in entries
    ]
    body = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
    return GOSSIP_PREFIX + OP_EQPROOF + body


def test_fabricated_equivocation_proof_does_not_frame_honest_publisher() -> None:
    """A relay forges an equivocation proof for honest E -> E is NOT quarantined.

    Anti-framing guard on the proof-gossip path. Honest publisher E signs
    exactly ONE card at version 1 (it never equivocates). A relay M -- holding
    no signing key for E -- tries to frame E by pushing an ``OP_EQPROOF`` whose
    two writes are E's one real signed card plus a second, mutated card at the
    same version (its signature no longer matches its tampered content). Since
    ``_ingest_proof`` independently re-verifies BOTH signatures, the forged
    side fails, the proof is rejected as ``REASON_BAD_PROOF``, and E is neither
    quarantined nor recorded as an equivocator. A relay cannot manufacture a
    valid conflicting-signature pair for E, so it cannot use the proof path to
    poison an honest publisher's standing.
    """
    idents = _peered_identities("e", "b", "m")
    net = GossipNetwork(agent_ids=[AgentId("e"), AgentId("b"), AgentId("m")])
    reg_b = ByzantineGossipRegistry(AgentId("b"), net, idents["b"])

    tag = _WriteTag(version=1, publisher_id=AgentId("e"))
    real_card = _signed_card(idents["e"], AgentId("e"), 1, ["sell"])
    # Fabricated second write: mutate the real card's content but keep its old
    # signature, so it no longer verifies (a relay with no key for E cannot
    # produce a genuine second signature).
    forged_card = real_card.model_copy(update={"capabilities": ["buy"]})

    payload = _proof_payload([(AgentId("e"), (real_card, tag, False), (forged_card, tag, False))])
    result = asyncio.run(reg_b.handle_gossip(AgentId("m"), payload, _StubContext()))  # type: ignore[arg-type]

    assert result is True
    assert AgentId("e") not in reg_b._quarantined  # pyright: ignore[reportPrivateUsage]
    assert reg_b.equivocations == []
    assert reg_b._equivocation_proofs == {}  # pyright: ignore[reportPrivateUsage]
    assert reg_b.rejections == [(AgentId("e"), "bad_equivocation_proof")]

    # E's genuine single card still merges normally afterwards -- E was not
    # poisoned by the framing attempt.
    ok = asyncio.run(
        reg_b.handle_gossip(AgentId("e"), _push_payload([(real_card, tag, False)]), _StubContext())  # type: ignore[arg-type]
    )
    assert ok is True
    [seen] = asyncio.run(reg_b.lookup(Query()))
    assert seen.agent_id == AgentId("e")
    assert seen.capabilities == ["sell"]


# ---------------------------------------------------------------------------
# No-false-positive: the other half of the equivocation-quarantine claim --
# an HONEST publisher must never be caught by the equivocation witness map.
# ---------------------------------------------------------------------------


def test_honest_multiwrite_history_not_equivocation() -> None:
    """Honest publisher A does register -> deregister -> register; all three writes gossiped.

    Each write uses the network's shared monotonic ``next_version()``, so
    every ``(publisher, version)`` key the witness map sees is distinct --
    equivocation requires the *same* key with *different* content, which
    never happens here. This locks in that a legitimate multi-write history
    (including a tombstone) is never mistaken for the same-version conflict
    ``test_equivocation_detected_and_quarantined`` exercises.
    """
    idents = _peered_identities("a", "b")
    net = GossipNetwork(agent_ids=[AgentId("a"), AgentId("b")])
    reg_a = ByzantineGossipRegistry(AgentId("a"), net, idents["a"])
    reg_b = ByzantineGossipRegistry(AgentId("b"), net, idents["b"])

    asyncio.run(reg_a.register(AgentCard(agent_id=AgentId("a"), name="A", capabilities=["sell"])))
    v1 = reg_a._view[AgentId("a")]  # pyright: ignore[reportPrivateUsage]
    payload_1 = _push_payload([(v1.card, v1.tag, v1.tombstone)])
    result_1 = asyncio.run(reg_b.handle_gossip(AgentId("a"), payload_1, _StubContext()))  # type: ignore[arg-type]
    assert result_1 is True

    asyncio.run(reg_a.deregister(AgentId("a")))
    v2 = reg_a._view[AgentId("a")]  # pyright: ignore[reportPrivateUsage]
    assert v2.tombstone is True
    payload_2 = _push_payload([(v2.card, v2.tag, v2.tombstone)])
    result_2 = asyncio.run(reg_b.handle_gossip(AgentId("a"), payload_2, _StubContext()))  # type: ignore[arg-type]
    assert result_2 is True

    asyncio.run(reg_a.register(AgentCard(agent_id=AgentId("a"), name="A", capabilities=["buy"])))
    v3 = reg_a._view[AgentId("a")]  # pyright: ignore[reportPrivateUsage]
    assert v3.tombstone is False
    assert v3.tag.version == 3  # distinct monotonic version at every step, never reused
    payload_3 = _push_payload([(v3.card, v3.tag, v3.tombstone)])
    result_3 = asyncio.run(reg_b.handle_gossip(AgentId("a"), payload_3, _StubContext()))  # type: ignore[arg-type]
    assert result_3 is True

    assert reg_b.equivocations == []
    assert AgentId("a") not in reg_b._quarantined  # pyright: ignore[reportPrivateUsage]
    [seen_card] = asyncio.run(reg_b.lookup(Query()))
    assert seen_card.capabilities == ["buy"]  # last honest write landed, nothing evicted


def test_identical_card_retransmission_is_idempotent() -> None:
    """The SAME signed card at the SAME version, delivered twice, is not equivocation.

    Gossip is allowed to redeliver a push verbatim (retries, overlapping
    fanout, etc.). ``_witness_write`` treats a second arrival with an
    *identical* content hash at an already-seen ``(publisher, version)`` key
    as a harmless retransmission -- only a *different* hash at that key is
    proof of conflicting writes. This pins that idempotent redelivery never
    trips quarantine.
    """
    idents = _peered_identities("a", "b")
    net = GossipNetwork(agent_ids=[AgentId("a"), AgentId("b")])
    reg_a = ByzantineGossipRegistry(AgentId("a"), net, idents["a"])
    reg_b = ByzantineGossipRegistry(AgentId("b"), net, idents["b"])

    asyncio.run(reg_a.register(AgentCard(agent_id=AgentId("a"), name="A", capabilities=["sell"])))
    [honest_card] = asyncio.run(reg_a.lookup(Query()))
    honest_tag = _WriteTag(version=1, publisher_id=AgentId("a"))
    payload = _push_payload([(honest_card, honest_tag, False)])

    result_1 = asyncio.run(reg_b.handle_gossip(AgentId("a"), payload, _StubContext()))  # type: ignore[arg-type]
    result_2 = asyncio.run(reg_b.handle_gossip(AgentId("a"), payload, _StubContext()))  # type: ignore[arg-type]

    assert result_1 is True
    assert result_2 is True
    assert reg_b.equivocations == []
    assert AgentId("a") not in reg_b._quarantined  # pyright: ignore[reportPrivateUsage]
    [seen_card] = asyncio.run(reg_b.lookup(Query()))
    assert seen_card.name == "A"


def test_register_signs_card_with_verifiable_signature() -> None:
    idents = _peered_identities("a")
    net = GossipNetwork(agent_ids=[AgentId("a")])
    reg = ByzantineGossipRegistry(AgentId("a"), net, idents["a"])

    asyncio.run(reg.register(AgentCard(agent_id=AgentId("a"), name="A")))
    [card] = asyncio.run(reg.lookup(Query()))
    snap = reg.view_snapshot()
    version, _publisher, tombstone = snap[AgentId("a")]

    sig_meta = card.metadata["sig"]
    assert sig_meta["signer"] == "a"
    sig = Signature(
        signer=AgentId(sig_meta["signer"]),
        value=bytes.fromhex(sig_meta["value"]),
        algorithm=sig_meta["algorithm"],
    )
    # The signature binds the whole write (content + version + tombstone),
    # not just canonical_card_bytes -- see test_replay_with_inflated_version_rejected
    # and test_tombstone_flip_rejected for why that matters.
    assert idents["a"].verify(canonical_write_bytes(card, version, tombstone), sig, AgentId("a"))


# ---------------------------------------------------------------------------
# Task 4: eclipse-resistant peer sampling -- gossip_round must not be
# eclipsable by a byzantine-heavy random draw. Tasks 2-3 only decide whether
# an ARRIVING card is trustworthy; they do nothing if the honest card never
# arrives because gossip_round happened to sample only byzantine peers.
# ---------------------------------------------------------------------------


class _RoutingContext:
    """Minimal ``AgentContext`` stand-in that actually routes gossip messages.

    ``_StubContext`` above forbids ``ctx.send`` outright because the
    existing ``handle_gossip``-only tests never trigger it. ``gossip_round``
    always calls ``ctx.send`` for every chosen peer, and a digest reply may
    call ``ctx.send`` back again (the ``OP_PUSH`` response) -- so exercising
    a real ``gossip_round`` needs a context that actually delivers. This
    stand-in delivers a payload straight into the target registry's
    ``handle_gossip``, using the *target's own* context (so its potential
    reply resolves too), without spinning up the full simulator.
    """

    def __init__(
        self,
        agent_id: AgentId,
        rng: random.Random,
        registries: dict[AgentId, ByzantineGossipRegistry],
        contexts: dict[AgentId, _RoutingContext],
    ) -> None:
        self.agent_id = agent_id
        self.rng = rng
        self._registries = registries
        self._contexts = contexts

    async def send(self, to: AgentId, payload: bytes) -> None:
        await self._registries[to].handle_gossip(
            self.agent_id,
            payload,
            self._contexts[to],  # type: ignore[arg-type]
        )


def test_eclipse_resistance_keeps_honest_contact() -> None:
    """Victim ``v`` has peers ``[h, m1, m2, m3]`` (``h`` honest, the ``m``s byzantine/silent).

    Seed 5 is brute-forced so that ``_sample_without_replacement`` (the pure
    -uniform reference sampler ``gossip.py`` and pre-Task-4 code both use)
    drawing 3-of-4 peers from ``[h, m1, m2, m3]`` excludes ``h`` entirely --
    a real eclipse: with that draw, ``v`` never contacts the one peer that
    holds the honest publisher's card, no matter how many further rounds
    pass (each round redraws independently). ``h`` is lexicographically
    first among ``v``'s peers, so it always lands in the anchor half of
    ``_sample_eclipse_resistant`` regardless of what the random half draws
    -- the mixed sampler must still contact ``h`` for this exact seed, and
    the honest card must therefore converge into ``v``'s view.
    """
    ids = [AgentId("v"), AgentId("h"), AgentId("m1"), AgentId("m2"), AgentId("m3")]
    idents = _peered_identities("v", "h", "m1", "m2", "m3")
    net = GossipNetwork(agent_ids=ids)  # DEFAULT_FANOUT == 3; peers_of(v) == [h, m1, m2, m3]
    seed = 5

    # --- Reference: pure-uniform sampling really does eclipse v for this seed ---
    peers_of_v = net.peers_of(AgentId("v"))
    pure_uniform_chosen = _sample_without_replacement(random.Random(seed), peers_of_v, 3)
    assert AgentId("h") not in pure_uniform_chosen

    # --- Real gossip_round + push-pull round, driven through the mixed sampler ---
    registries = {aid: ByzantineGossipRegistry(aid, net, idents[str(aid)]) for aid in ids}
    contexts: dict[AgentId, _RoutingContext] = {}
    for aid in ids:
        contexts[aid] = _RoutingContext(
            agent_id=aid, rng=random.Random(seed), registries=registries, contexts=contexts
        )

    asyncio.run(
        registries[AgentId("h")].register(
            AgentCard(agent_id=AgentId("h"), name="H", capabilities=["sell"])
        )
    )

    asyncio.run(registries[AgentId("v")].gossip_round(contexts[AgentId("v")]))  # type: ignore[arg-type]

    snap = registries[AgentId("v")].view_snapshot()
    assert AgentId("h") in snap  # honest card converged -- v was NOT eclipsed
    [seen] = asyncio.run(registries[AgentId("v")].lookup(Query()))
    assert seen.name == "H"


def test_eclipse_resistant_sampling_is_deterministic() -> None:
    """Same seed + same peer set -> byte-identical chosen peer list, every time."""
    peers = [AgentId("h"), AgentId("m1"), AgentId("m2"), AgentId("m3"), AgentId("m4")]

    first = _sample_eclipse_resistant(random.Random(123), peers, 3)
    second = _sample_eclipse_resistant(random.Random(123), peers, 3)
    assert first == second

    # Anchor half (ceil(3/2) == 2, lexicographically-first) never depends on rng.
    assert first[:2] == sorted(peers)[:2]

    # A different seed may change the random half but never the anchor half.
    third = _sample_eclipse_resistant(random.Random(999), peers, 3)
    assert third[:2] == first[:2]
