# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the three mandated adversarial registry validators (Task 5).

Each validator gets one hand-built ``reference``-style input (proving it
FAILs against what ``gossip``/``in_memory`` would actually produce) and one
hand-built ``byzantine_gossip``-style input (proving it PASSes against what
that plugin actually guarantees) -- the charter's bar for "adversarial".
Mirrors ``test_gossip_validators_and_scenario.py``'s unit-test style: build
snapshots/ledgers by hand, no full scenario needed here (that's Task 6).
"""

from __future__ import annotations

from typing import cast

from nest_core.types import AgentCard, AgentId
from nest_plugins_reference.identity.did_key import DidKeyIdentity
from nest_plugins_reference.registry.byzantine_gossip import canonical_write_bytes
from nest_plugins_reference.validators.registry_byzantine_validators import (
    EquivocationView,
    check_no_eclipse,
    check_no_equivocation_accepted,
    check_no_forged_card_in_view,
)


def _peered_identities(*agent_ids: str) -> dict[AgentId, DidKeyIdentity]:
    """Build one ``DidKeyIdentity`` per agent id, each knowing every peer's public key."""
    idents = {
        AgentId(aid): DidKeyIdentity(AgentId(aid), seed=f"seed-{aid}".encode()) for aid in agent_ids
    }
    for aid, ident in idents.items():
        for peer_id, peer_ident in idents.items():
            if peer_id != aid:
                ident.register_peer(peer_id, peer_ident.public_key)
    return idents


def _signed_card(
    identity: DidKeyIdentity, agent_id: AgentId, name: str, version: int, tombstone: bool = False
) -> AgentCard:
    card = AgentCard(agent_id=agent_id, name=name)
    sig = identity.sign(canonical_write_bytes(card, version, tombstone))
    return card.model_copy(
        update={
            "metadata": {
                "sig": {
                    "signer": str(sig.signer),
                    "value": sig.value.hex(),
                    "algorithm": sig.algorithm,
                }
            }
        }
    )


# ---------------------------------------------------------------------------
# check_no_forged_card_in_view
# ---------------------------------------------------------------------------


def test_forged_card_validator_fails_against_reference_style_unsigned_card() -> None:
    """``gossip``/``in_memory`` never sign anything -- any card lacks metadata["sig"]."""
    idents = _peered_identities("a")
    views = {AgentId("b"): {AgentId("a"): (1, AgentId("a"), False)}}
    cards = {AgentId("a"): AgentCard(agent_id=AgentId("a"), name="A")}  # no metadata["sig"] at all

    report = check_no_forged_card_in_view(views=views, identities=idents, cards=cards)

    assert not report.passed
    offenders = cast("list[tuple[str, str]]", report.evidence["offenders"])
    assert ("b", "a") in offenders


def test_forged_card_validator_fails_on_hand_forged_signature() -> None:
    """A relay claims agent A's identity with a bogus/mutated signature -- classic forgery."""
    idents = _peered_identities("a", "m")
    forged = AgentCard(
        agent_id=AgentId("a"),
        name="EVIL",
        metadata={"sig": {"signer": "a", "value": "00" * 32, "algorithm": "sim-rsa-sha256"}},
    )
    views = {AgentId("b"): {AgentId("a"): (1, AgentId("a"), False)}}
    cards = {AgentId("a"): forged}

    report = check_no_forged_card_in_view(views=views, identities=idents, cards=cards)

    assert not report.passed
    offenders = cast("list[tuple[str, str]]", report.evidence["offenders"])
    assert ("b", "a") in offenders


def test_forged_card_validator_passes_against_byzantine_style_signed_card() -> None:
    """``byzantine_gossip`` only ever merges cards that verified pre-``_apply``."""
    idents = _peered_identities("a")
    signed = _signed_card(idents[AgentId("a")], AgentId("a"), "A", version=1)
    views = {AgentId("b"): {AgentId("a"): (1, AgentId("a"), False)}}
    cards = {AgentId("a"): signed}

    report = check_no_forged_card_in_view(views=views, identities=idents, cards=cards)

    assert report.passed, report.detail


def test_forged_validator_fails_when_a_view_entry_is_unverifiable() -> None:
    """Absence of evidence must never read as a pass.

    A view entry whose publisher has no supplied identity (so its signature
    cannot be checked either way) must not let the report come back clean --
    a real forgery hiding behind an under-populated ``identities``/``cards``
    input would otherwise be masked as PASS. Unverifiable is a FAIL, not a
    silent no-op.
    """
    idents = _peered_identities("a")  # no identity registered for "a" as a *publisher* lookup key
    del idents[AgentId("a")]  # simulate an identity missing from the caller's input entirely
    views = {AgentId("b"): {AgentId("a"): (1, AgentId("a"), False)}}
    cards = {AgentId("a"): AgentCard(agent_id=AgentId("a"), name="A")}

    report = check_no_forged_card_in_view(views=views, identities=idents, cards=cards)

    assert not report.passed
    unverifiable = cast("list[tuple[str, str]]", report.evidence["unverifiable"])
    assert ("b", "a") in unverifiable


# ---------------------------------------------------------------------------
# check_no_equivocation_accepted
# ---------------------------------------------------------------------------


def test_equivocation_validator_fails_against_reference_style_silent_split() -> None:
    """Reference LWW: two nodes each accept a DIFFERENT conflicting write, no ledger exists.

    ``existing.tag >= tag`` means whichever conflicting write a node's gossip
    happens to deliver first silently and permanently wins there -- the
    reference plugin has no equivocation ledger at all, so this content
    split across honest nodes goes completely unrecorded.
    """
    ledgers: dict[AgentId, list[tuple[AgentId, int]]] = {AgentId("a"): [], AgentId("c"): []}
    views: EquivocationView = {
        AgentId("a"): {AgentId("e"): (1, AgentId("e"), False, "hash-of-card-1")},
        AgentId("c"): {AgentId("e"): (1, AgentId("e"), False, "hash-of-card-2")},
    }

    report = check_no_equivocation_accepted(equivocation_ledgers=ledgers, views=views)

    assert not report.passed
    undetected = cast("list[tuple[str, int]]", report.evidence["undetected_equivocations"])
    assert ("e", 1) in undetected


def test_equivocation_validator_passes_against_byzantine_style_quarantine() -> None:
    """``byzantine_gossip`` quarantines the publisher: the witness node's ledger records the key.

    Node ``b`` witnessed both conflicting writes and evicted the card (so it
    holds no entry for "e" anymore); nodes ``a``/``c`` each only ever
    received one of the two writes and hold differing hashes -- but the
    disagreement is recorded in ``b``'s ledger, so the network as a whole
    caught it.
    """
    ledgers: dict[AgentId, list[tuple[AgentId, int]]] = {
        AgentId("a"): [],
        AgentId("b"): [(AgentId("e"), 1)],
        AgentId("c"): [],
    }
    views: EquivocationView = {
        AgentId("a"): {AgentId("e"): (1, AgentId("e"), False, "hash-of-card-1")},
        AgentId("b"): {},  # evicted on quarantine
        AgentId("c"): {AgentId("e"): (1, AgentId("e"), False, "hash-of-card-2")},
    }

    report = check_no_equivocation_accepted(equivocation_ledgers=ledgers, views=views)

    assert report.passed, report.detail


def test_equivocation_validator_fails_on_masked_one_sided_split() -> None:
    """Incomplete evidence must never read as a pass.

    A real one-sided split: ``b`` witnessed a write for ``(e, 1)`` and then
    evicted/tombstoned it (``a`` never received a copy at all -- its
    conflicting side of the split is gone with no trace), so the only
    surviving entry anywhere is ``b``'s tombstone whose content hash could
    not be recovered (the known ``lookup()`` limitation this module's
    docstring already calls out -- ``content_hash=None`` signals "an entry
    existed here but its content is unverifiable", as distinct from no
    entry at all). No ledger recorded anything. The old logic only ever
    compared *known* hash strings against each other: with a single
    ``None`` in the set there is nothing to disagree with, so it declared
    "no disagreement" and returned PASS -- a fake green, since that lone
    unresolvable entry might be exactly the undetected half of a real
    equivocation. Incomplete evidence must FAIL, naming the key it could
    not resolve.
    """
    ledgers: dict[AgentId, list[tuple[AgentId, int]]] = {AgentId("a"): [], AgentId("b"): []}
    views: EquivocationView = {
        AgentId("a"): {},  # the conflicting side: evicted, no trace left anywhere
        # tombstoned, hash unrecoverable:
        AgentId("b"): {AgentId("e"): (1, AgentId("e"), True, None)},
    }

    report = check_no_equivocation_accepted(equivocation_ledgers=ledgers, views=views)

    assert not report.passed
    unverifiable = cast("list[tuple[str, int]]", report.evidence["unverifiable_equivocations"])
    assert ("e", 1) in unverifiable


def test_equivocation_validator_passes_when_no_disagreement_exists() -> None:
    """No-false-positive: honest multi-write history at distinct versions is not equivocation."""
    ledgers: dict[AgentId, list[tuple[AgentId, int]]] = {AgentId("a"): [], AgentId("b"): []}
    views: EquivocationView = {
        AgentId("a"): {AgentId("e"): (2, AgentId("e"), False, "hash-of-card-2")},
        AgentId("b"): {AgentId("e"): (2, AgentId("e"), False, "hash-of-card-2")},
    }

    report = check_no_equivocation_accepted(equivocation_ledgers=ledgers, views=views)

    assert report.passed, report.detail


# ---------------------------------------------------------------------------
# check_no_eclipse
# ---------------------------------------------------------------------------


def test_eclipse_validator_fails_against_reference_style_pure_uniform_draw() -> None:
    """Victim ``v``'s pure-uniform gossip draw (seed 5, see byzantine_gossip's Task 4 tests)
    excludes its only honest peer ``h`` -- v's view holds nothing from any honest publisher.
    """
    honest_ids = {AgentId("v"), AgentId("h")}
    byzantine_ids = {AgentId("m1"), AgentId("m2"), AgentId("m3")}
    views = {
        AgentId("v"): {},  # eclipsed: no entry for h, only byzantine junk was ever offered
        AgentId("h"): {AgentId("h"): (1, AgentId("h"), False)},
    }

    report = check_no_eclipse(views=views, honest_ids=honest_ids, byzantine_ids=byzantine_ids)

    assert not report.passed
    eclipsed_agents = cast("list[str]", report.evidence["eclipsed_agents"])
    assert "v" in eclipsed_agents


def test_eclipse_validator_passes_against_byzantine_style_anchor_sampling() -> None:
    """``byzantine_gossip``'s deterministic anchor half guarantees v still contacts h."""
    honest_ids = {AgentId("v"), AgentId("h")}
    byzantine_ids = {AgentId("m1"), AgentId("m2"), AgentId("m3")}
    views = {
        AgentId("v"): {AgentId("h"): (1, AgentId("h"), False)},
        AgentId("h"): {
            AgentId("h"): (1, AgentId("h"), False),
            AgentId("v"): (1, AgentId("v"), False),
        },
    }

    report = check_no_eclipse(views=views, honest_ids=honest_ids, byzantine_ids=byzantine_ids)

    assert report.passed, report.detail


def test_eclipse_validator_exempts_agent_with_no_honest_peers_to_reach() -> None:
    """A lone honest agent (no other honest peer exists) can't be eclipsed from anything."""
    honest_ids = {AgentId("v")}
    byzantine_ids = {AgentId("m1")}
    views: dict[AgentId, dict[AgentId, tuple[int, AgentId, bool]]] = {AgentId("v"): {}}

    report = check_no_eclipse(views=views, honest_ids=honest_ids, byzantine_ids=byzantine_ids)

    assert report.passed, report.detail
