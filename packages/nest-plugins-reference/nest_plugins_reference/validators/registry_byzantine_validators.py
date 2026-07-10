# SPDX-License-Identifier: Apache-2.0
"""Mandated adversarial validators for the byzantine gossip registry (Task 5).

Three attacks the reference ``gossip``/``in_memory`` plugins silently allow,
each with a validator that FAILs against the reference plugin and PASSes
against ``byzantine_gossip`` -- the charter's bar for "adversarial" (mirrors
``gossip_validators.py``'s framing and unit-test style):

1. **Forged/unsigned cards reaching a view.** ``gossip``/``in_memory`` never
   sign or verify anything (see ``nest_plugins_reference.registry.gossip``
   and ``.in_memory``), so ANY card -- genuine, forged, or mutated in
   transit -- is merged on sight. ``check_no_forged_card_in_view`` asserts
   every card an honest agent's view holds carries a signature that
   verifies under its claimed publisher's identity, over the exact bytes
   ``byzantine_gossip.canonical_write_bytes(card, version, tombstone)``
   binds (that module's Task 2 section). Reference plugins fail this by
   construction -- they never attach ``metadata["sig"]`` at all, so every
   entry is "unsigned" regardless of whether an actual forgery was
   attempted.
2. **Equivocation silently resolved instead of caught.** A byzantine
   publisher can validly sign two *different* cards at the same
   ``(publisher, version)`` key. ``gossip``'s last-writer-wins merge
   (``existing.tag >= tag`` short-circuits any further write at an
   already-seen key) means whichever conflicting card a given node's gossip
   happens to deliver *first* silently and permanently wins there --
   different honest nodes can end up permanently disagreeing about that
   publisher's content, with no ledger anywhere recording that a conflict
   ever happened, since the bare ``ViewSnapshot`` tuple carries no content.
   ``check_no_equivocation_accepted`` requires that whenever two honest
   agents' views disagree on the content behind the same ``(publisher,
   version)`` key, at least one agent's equivocation ledger recorded it --
   ``byzantine_gossip``'s witness map (Task 3) guarantees this;
   ``gossip``/``in_memory`` have no such ledger at all.
3. **Eclipse: an honest agent fed only byzantine/rejected data.**
   ``gossip``'s ``gossip_round`` draws fanout peers uniformly at random
   every round with no memory of past contacts; an unlucky draw (or a
   large-enough byzantine peer fraction) can exclude a victim's only honest
   peer indefinitely -- see ``byzantine_gossip``'s Task 4 section and
   ``test_eclipse_resistance_keeps_honest_contact``, which brute-forces
   exactly such a seed. ``check_no_eclipse`` asserts every honest agent's
   view holds at least one live card from another honest publisher;
   ``byzantine_gossip``'s deterministic anchor-peer sampling guarantees
   this heuristically (see that module's caveat), pure-uniform sampling
   does not.

All three are pure functions over per-agent evidence -- snapshots, cards,
and ledgers -- so they compose the same way ``gossip_validators.py``'s
validators do: unit tests build the evidence by hand (this module's test
file), integration tests snapshot real registries, and trace replays
rebuild the same shapes from recorded events. See each function's docstring
for exactly how its parameters map onto real registry state.

Example::

    from nest_plugins_reference.validators.registry_byzantine_validators import (
        check_no_eclipse,
        check_no_equivocation_accepted,
        check_no_forged_card_in_view,
    )

    report = check_no_forged_card_in_view(views, identities, cards)
    assert report.passed, report.detail
"""

from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING, cast

from nest_core.types import Signature

from nest_plugins_reference.registry.byzantine_gossip import canonical_write_bytes
from nest_plugins_reference.validators.gossip_validators import ValidatorReport, ViewSnapshot

if TYPE_CHECKING:
    from collections.abc import Mapping

    from nest_core.layers.identity import Identity
    from nest_core.types import AgentCard, AgentId

EquivocationView = dict["AgentId", dict["AgentId", tuple[int, "AgentId", bool, "str | None"]]]
"""Per-viewer view extended with a content fingerprint: ``{published_agent_id:
(version, publisher_id, tombstone, content_hash)}``.

This is exactly the shape ``ByzantineGossipRegistry.content_view()`` returns,
so a caller wires the validator with ``{viewer: reg.content_view()}`` --
symmetric to how ``check_no_forged_card_in_view``/``check_no_eclipse`` take
``{viewer: reg.view_snapshot()}``. It is ``view_snapshot()``'s ``(version,
publisher_id, tombstone)`` tuple plus a fourth ``content_hash`` field:
``view_snapshot()`` deliberately omits content, so two agents who each
accepted a *different*, both validly-signed, card from an equivocating
publisher at the identical ``(publisher, version)`` key would produce
byte-identical three-tuples for that key even though their views actually
disagree. ``content_hash`` closes that gap; it is the same
``content_hash(card, version, tombstone)`` the plugin's witness map computes
internally, obtained straight from ``reg.content_view()`` (which covers
tombstoned entries too) rather than re-derived by the caller, or built by
hand in tests.

``content_hash`` may be ``None`` when the caller knows an entry existed at
that ``(publisher, version)`` key but could not recover its content to hash
it (a plugin with no content accessor whose ``lookup()`` filters out a
tombstoned side). That is distinct from omitting the ``(publisher,
version)`` key entirely (which means this viewer simply has no information
about it at all, the normal and harmless state of a partial gossip view): a
present-but-``None`` entry is evidence that *something* happened here whose
content is unverifiable, and ``check_no_equivocation_accepted`` treats it
accordingly -- it can never be silently folded into "no disagreement".

Example::

    view: EquivocationView = {AgentId("b"): {AgentId("e"): (1, AgentId("e"), False, "abc...")}}
"""


def _signature_valid(
    card: AgentCard,
    version: int,
    tombstone: bool,
    publisher_id: AgentId,
    identity: Identity,
) -> bool:
    """Return whether ``card``'s embedded signature verifies as a write by ``publisher_id``.

    Mirrors ``byzantine_gossip._verify_card``'s checks (signature present,
    correctly self-claimed signer, cryptographically valid over
    ``canonical_write_bytes(card, version, tombstone)``) but collapses them
    to a boolean -- this module's validators report evidence dicts, not
    per-card rejection reason codes.

    Example::

        assert _signature_valid(card, 1, False, AgentId("a"), identity)
    """
    raw = card.metadata.get("sig")
    if not isinstance(raw, dict):
        return False
    sig_meta = cast("dict[str, object]", raw)
    signer_raw = sig_meta.get("signer")
    value_raw = sig_meta.get("value")
    if signer_raw is None or value_raw is None:
        return False
    if str(signer_raw) != str(publisher_id) or str(signer_raw) != str(card.agent_id):
        return False
    try:
        value = bytes.fromhex(str(value_raw))
    except ValueError:
        return False
    algorithm = str(sig_meta.get("algorithm", "ed25519"))
    sig = Signature(signer=publisher_id, value=value, algorithm=algorithm)
    return identity.verify(canonical_write_bytes(card, version, tombstone), sig, publisher_id)


def check_no_forged_card_in_view(
    views: dict[AgentId, ViewSnapshot],
    identities: Mapping[AgentId, Identity],
    cards: dict[AgentId, AgentCard],
) -> ValidatorReport:
    """Assert every card an honest agent's view holds verifies under its claimed publisher.

    ``views`` is per-viewer (``{viewer: {published_agent_id: (version,
    publisher_id, tombstone)}}`` -- the exact shape both
    ``GossipRegistry.view_snapshot()`` and
    ``ByzantineGossipRegistry.view_snapshot()`` return). ``identities`` maps
    publisher -> the ``Identity`` that can verify signatures claiming to be
    from it. ``cards`` maps published-agent-id -> the actual ``AgentCard``
    instance circulating for it (with ``metadata["sig"]`` if any was ever
    attached) -- sourced by hand in tests, or in a live run from any
    registry's ``lookup()`` (gossip propagates the same physical bytes to
    every acceptor, so one observed instance per agent id is enough to
    check what that id's viewers actually merged).

    Returns ``passed=True`` iff every view entry's card carries a signature
    that verifies under ``canonical_write_bytes(card, version, tombstone)``
    for its claimed publisher, AND every view entry could actually be
    checked. A view entry whose card is missing from ``cards`` or whose
    publisher is missing from ``identities`` cannot be judged either way --
    it is reported under ``evidence["unverifiable"]`` -- but "cannot be
    judged" is never a pass: an unverifiable entry FAILs the report exactly
    like a proven forgery does, because a real forged card behind an
    under-populated ``cards``/``identities`` input would otherwise be masked
    as clean. Absence of evidence is not evidence of safety.

    Against the reference ``gossip``/``in_memory`` plugins this always
    FAILs: neither ever calls ``identity.sign``/``.verify``, so no card
    they merge ever carries ``metadata["sig"]`` at all -- every entry is
    "unsigned" regardless of whether a forgery was even attempted. Against
    ``byzantine_gossip`` this PASSes for any card that actually reached a
    view: ``handle_gossip`` verifies before ``_apply`` (Task 2), so an
    unverified card never lands in the view in the first place.

    Example::

        report = check_no_forged_card_in_view(views, identities, cards)
        assert report.passed, report.detail
    """
    offenders: list[tuple[str, str]] = []
    unverifiable: list[tuple[str, str]] = []
    for viewer, snapshot in views.items():
        for agent_id, (version, publisher_id, tombstone) in snapshot.items():
            card = cards.get(agent_id)
            identity = identities.get(publisher_id)
            if card is None or identity is None:
                unverifiable.append((str(viewer), str(agent_id)))
                continue
            if not _signature_valid(card, version, tombstone, publisher_id, identity):
                offenders.append((str(viewer), str(publisher_id)))
    if offenders or unverifiable:
        details: list[str] = []
        if offenders:
            details.append(
                f"{len(offenders)} view entries hold a card that fails to verify "
                "under its claimed publisher's identity"
            )
        if unverifiable:
            details.append(
                f"{len(unverifiable)} view entries could not be checked at all "
                "(missing card or missing identity) and are therefore not passed"
            )
        return ValidatorReport(
            passed=False,
            detail="; ".join(details),
            evidence={"offenders": offenders[:20], "unverifiable": unverifiable[:20]},
        )
    return ValidatorReport(
        passed=True,
        detail="every view entry's card verifies under its claimed publisher's identity",
        evidence={},
    )


def check_no_equivocation_accepted(
    equivocation_ledgers: dict[AgentId, list[tuple[AgentId, int]]],
    views: EquivocationView,
) -> ValidatorReport:
    """Assert every honest-view content disagreement at a ``(publisher, version)`` key was caught.

    ``equivocation_ledgers`` is per-agent -- each value is what that agent's
    ``ByzantineGossipRegistry.equivocations`` holds (``(publisher_id,
    version)`` pairs it proved were signed twice with different content), or
    the empty list for a reference plugin that has no such ledger at all
    (``getattr(reg, "equivocations", [])``). ``views`` is the content-aware
    shape (see ``EquivocationView``) because the plain ``ViewSnapshot``
    tuple is identical for two conflicting same-version writes and cannot
    reveal the disagreement on its own.

    Both inputs come from the plugin's **public** interface: the ledger from
    ``reg.equivocations`` and the view from ``reg.content_view()`` (a
    per-entry content hash alongside the ``view_snapshot()`` fields). This is
    a pure function over that public output -- exactly like
    ``check_no_forged_card_in_view``/``check_no_eclipse`` over
    ``view_snapshot()`` -- with no reach into privately-stashed plugin state,
    no import of the private ``_WriteTag``, and no re-implementation of the
    write codec to re-derive the hash.

    For every ``(publisher, version)`` key where two or more *distinct*
    content hashes appear across the honest agents' views -- proof the
    publisher equivocated and different nodes' last-writer-wins merges kept
    different writes -- at least one agent's ledger must record that key.
    The check is network-wide, not per-viewer: it does not require the
    specific disagreeing viewers to be the ones who detected it, only that
    *someone* honest did.

    Symmetric to ``check_no_forged_card_in_view``: "cannot verify" is never
    a pass. Any view entry whose ``content_hash`` is ``None`` (an entry the
    caller knows existed at that key but could not hash -- see
    ``EquivocationView``) means the validator cannot actually confirm
    whether that key disagreed with the rest of the network or not. A
    naive comparison would fold a lone unresolvable entry into "only one
    hash seen, no disagreement" and pass -- exactly the fake green a real,
    one-sided split produces when the conflicting write was evicted or
    tombstoned on one side and no ledger recorded it. Any such key not
    already covered by a recorded equivocation therefore FAILs the report,
    named under ``evidence["unverifiable_equivocations"]``, regardless of
    whether a concrete second hash was ever observed.

    Against the reference ``gossip``/``in_memory`` plugins this always
    FAILs when an equivocation actually happens: neither has an
    equivocation ledger at all, so a real content split across nodes --
    ``existing.tag >= tag`` means whichever conflicting write a node's
    gossip delivers first silently and permanently wins there -- goes
    completely unrecorded. Against ``byzantine_gossip`` this PASSes: the
    witness map (Task 3) quarantines the publisher and records the key the
    moment a second, content-differing, verified write is seen by any
    agent.

    Sourcing the view from ``ByzantineGossipRegistry.content_view()`` covers
    tombstoned entries too (it reads the local view directly, not ``lookup()``,
    which filters tombstones), so an equivocation between a live card and a
    tombstone at the same version -- which ``byzantine_gossip``'s witness map
    already hashes the full write for -- is representable in the evidence. A
    caller that instead hand-builds the view from a plugin with no such
    accessor (``lookup()`` only) may not recover a tombstoned side's hash; it
    supplies ``content_hash=None`` for it, which this validator treats as
    unverifiable (never a silent pass), not as absence.

    Example::

        views = {aid: reg.content_view() for aid, reg in registries.items()}
        report = check_no_equivocation_accepted(ledgers, views)
        assert report.passed, report.detail
    """
    disagreements: dict[tuple[str, int], set[str]] = defaultdict(set)
    unverifiable_keys: set[tuple[str, int]] = set()
    for snapshot in views.values():
        for _agent_id, (version, publisher_id, _tombstone, content_hash) in snapshot.items():
            key = (str(publisher_id), version)
            if content_hash is None:
                unverifiable_keys.add(key)
                continue
            disagreements[key].add(content_hash)

    recorded: set[tuple[str, int]] = {
        (str(publisher_id), version)
        for ledger in equivocation_ledgers.values()
        for publisher_id, version in ledger
    }

    undetected = sorted(
        key for key, hashes in disagreements.items() if len(hashes) > 1 and key not in recorded
    )
    unverifiable = sorted(key for key in unverifiable_keys if key not in recorded)
    if undetected or unverifiable:
        details: list[str] = []
        if undetected:
            details.append(
                f"{len(undetected)} (publisher, version) key(s) show honest views silently "
                "disagreeing on content with no equivocation recorded"
            )
        if unverifiable:
            details.append(
                f"{len(unverifiable)} (publisher, version) key(s) hold an entry whose content "
                "could not be verified (hash unavailable) and no equivocation was recorded for "
                "it -- absence of evidence is not evidence of safety, so it is not passed"
            )
        return ValidatorReport(
            passed=False,
            detail="; ".join(details),
            evidence={
                "undetected_equivocations": undetected,
                "unverifiable_equivocations": unverifiable,
            },
        )
    return ValidatorReport(
        passed=True,
        detail="every honest-view content disagreement was caught and recorded as an equivocation",
    )


def check_no_eclipse(
    views: dict[AgentId, ViewSnapshot],
    honest_ids: set[AgentId],
    byzantine_ids: set[AgentId],
) -> ValidatorReport:
    """Assert every honest agent's view holds at least one live card from another honest publisher.

    ``views`` is per-viewer ``ViewSnapshot`` (as returned by either
    registry's ``view_snapshot()``). ``honest_ids``/``byzantine_ids``
    partition the agent population for this check; an agent id absent from
    both is treated as neither a source nor a possible victim.

    An honest agent with **zero** other honest agents to reach
    (``honest_ids - {agent}`` empty) is trivially exempt -- there is nothing
    for it to be eclipsed from. Otherwise, FAILs for any honest agent whose
    view contains no live (non-tombstoned) entry whose publisher is another
    honest agent -- i.e. it was fed *only* byzantine/rejected data, a full
    eclipse. This is deliberately the weaker "reached at least one honest
    publisher" bar, not "reached every honest publisher": that mirrors
    ``byzantine_gossip``'s own heuristic guarantee (one anchor slot,
    contacted every round) rather than claiming a stronger property it does
    not actually provide.

    Against the reference ``gossip`` plugin under an eclipse-favourable
    topology/seed this FAILs: ``gossip_round`` draws fanout peers uniformly
    at random every round with no memory of past contacts, so an unlucky
    draw (or a large-enough byzantine peer fraction) can exclude a victim's
    only honest peer indefinitely -- see
    ``test_eclipse_resistance_keeps_honest_contact``, which brute-forces
    exactly such a seed for ``_sample_without_replacement``. Against
    ``byzantine_gossip`` this PASSes: the deterministic anchor half of
    ``_sample_eclipse_resistant`` guarantees a fixed contact every round, so
    as long as one anchor slot is honest, that peer's card eventually
    converges in -- heuristic, not a proof; see that module's Task 4
    caveat about an adversary controlling every anchor slot for a specific
    victim.

    Example::

        report = check_no_eclipse(views, honest_ids, byzantine_ids)
        assert report.passed, report.detail
    """
    eclipsed: list[str] = []
    for agent_id in sorted(honest_ids):
        reachable_honest_peers = honest_ids - {agent_id}
        if not reachable_honest_peers:
            continue
        snapshot = views.get(agent_id, {})
        seen_honest_publishers = {
            publisher_id
            for _entry_id, (_version, publisher_id, tombstone) in snapshot.items()
            if not tombstone and publisher_id in reachable_honest_peers
        }
        if not seen_honest_publishers:
            eclipsed.append(str(agent_id))
    if eclipsed:
        return ValidatorReport(
            passed=False,
            detail=(
                f"{len(eclipsed)} honest agent(s) hold zero live cards from any other "
                "honest publisher (fully eclipsed)"
            ),
            evidence={
                "eclipsed_agents": eclipsed,
                "byzantine_ids": sorted(str(b) for b in byzantine_ids),
            },
        )
    return ValidatorReport(
        passed=True,
        detail=f"all {len(honest_ids)} honest agent(s) reached at least one honest publisher",
    )
