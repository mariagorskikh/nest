# SPDX-License-Identifier: Apache-2.0
# pyright: reportPrivateUsage=false
"""Unit tests for the agent_receipts trust plugin.

Covers receipt verification, counterparty corroboration, Tarjan-SCC collusion
severance (shape-based: dense isolated rings and mutual-only pairs are severed
regardless of component size — issue #97), the no-receipt fallback, and the
Trust-protocol surface. The make-or-break invariant -- that an isolated
collusion-shaped component is severed at *every* size ratio while the sparse
honest cycle is spared -- is asserted directly against the severance primitive.
"""

from __future__ import annotations

import hashlib
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from nest_core.types import AgentId, Claim, Evidence
from nest_plugins_reference.trust.agent_receipts import (
    AgentReceiptsTrust,
    _collusion_shaped,
    _corroboration_graph,
    _normalize,
    _sccs,
    _severed_dids,
    _verify_receipt,
    cosign_receipt,
    did_for_pubkey,
    is_corroborated,
    sign_receipt,
)


def _seed(name: str) -> bytes:
    return hashlib.sha256(name.encode()).digest()[:32]


def _did(name: str) -> str:
    sk = Ed25519PrivateKey.from_private_bytes(_seed(name))
    return did_for_pubkey(sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))


def _receipt(issuer: str, cp: str, *, rid: str, category: str = "purchase") -> dict[str, object]:
    r: dict[str, object] = {
        "receipt_id": rid,
        "issuer_did": _did(issuer),
        "action": {"category": category, "counterparty_did": _did(cp)},
    }
    return sign_receipt(r, issuer_seed=_seed(issuer))


def _corroborated(
    issuer: str, cp: str, *, rid: str, category: str = "purchase"
) -> dict[str, object]:
    return cosign_receipt(
        _receipt(issuer, cp, rid=rid, category=category), counterparty_seed=_seed(cp)
    )


class TestReceiptVerification:
    def test_valid_issuer_signature_verifies(self) -> None:
        assert _verify_receipt(_receipt("a", "b", rid="r0")) is True

    def test_tampered_action_fails_verification(self) -> None:
        r = _receipt("a", "b", rid="r0")
        r["action"] = {"category": "payment_sent", "counterparty_did": _did("b")}  # post-sign edit
        assert _verify_receipt(r) is False

    def test_missing_signature_fails_without_crashing(self) -> None:
        r = {"receipt_id": "r0", "issuer_did": _did("a"), "action": {"category": "purchase"}}
        assert _verify_receipt(r) is False

    def test_garbage_signature_fails_without_crashing(self) -> None:
        r = _receipt("a", "b", rid="r0")
        r["signature"] = "not-hex"
        assert _verify_receipt(r) is False


class TestCorroboration:
    def test_counterparty_cosignature_is_corroborated(self) -> None:
        assert is_corroborated(_corroborated("a", "b", rid="r0")) is True

    def test_uncosigned_receipt_not_corroborated(self) -> None:
        assert is_corroborated(_receipt("a", "b", rid="r0")) is False

    def test_self_corroboration_rejected(self) -> None:
        # counterparty == issuer: not a distinct corroborator.
        assert is_corroborated(_corroborated("a", "a", rid="r0")) is False

    def test_wrong_witness_signature_not_corroborated(self) -> None:
        r = _receipt("a", "b", rid="r0")
        r.setdefault("evidence", {})["witness_signatures"] = [  # type: ignore[index]
            {"witness_did": _did("b"), "signature": "00" * 64}
        ]
        assert is_corroborated(r) is False


class TestSeverance:
    def _honest_and_ring(self) -> list[dict[str, object]]:
        honest = [f"h{i}" for i in range(5)]
        ring = [f"r{i}" for i in range(4)]
        receipts: list[dict[str, object]] = []
        # honest directed cycle + chord -> single SCC of size 5
        for i in range(5):
            for k in (1, 2):
                receipts.append(_corroborated(honest[i], honest[(i + k) % 5], rid=f"h{i}-{k}"))
        # isolated dense ring (all-pairs both directions)
        for i in range(4):
            for j in range(4):
                if i != j:
                    receipts.append(_corroborated(ring[i], ring[j], rid=f"r{i}-{j}"))
        return receipts

    def test_anchor_is_largest_honest_scc(self) -> None:
        """The honest population must be the anchor (largest SCC), strictly > ring."""
        graph = _corroboration_graph(self._honest_and_ring())
        comps = _sccs(graph)
        anchor = set(comps[0])
        assert anchor == {_did(f"h{i}") for i in range(5)}
        assert len(anchor) > 4  # strictly larger than the 4-agent ring

    def test_isolated_ring_is_severed(self) -> None:
        severed = _severed_dids(_corroboration_graph(self._honest_and_ring()))
        assert severed == {_did(f"r{i}") for i in range(4)}

    def test_ring_with_edge_to_anchor_not_severed(self) -> None:
        """A ring that actually transacts with an honest agent is not isolated."""
        receipts = self._honest_and_ring()
        # add a real corroborated edge ring->honest, bridging the ring to the anchor
        receipts.append(_corroborated("r0", "h0", rid="bridge"))
        severed = _severed_dids(_corroboration_graph(receipts))
        assert severed == set()

    def test_empty_graph_severs_nothing(self) -> None:
        assert _severed_dids({}) == set()

    def _clique(self, names: list[str], *, tag: str) -> list[dict[str, object]]:
        """All distinct ordered pairs, both directions — a dense isolated SCC."""
        receipts: list[dict[str, object]] = []
        for i, issuer in enumerate(names):
            for j, cp in enumerate(names):
                if i != j:
                    receipts.append(_corroborated(issuer, cp, rid=f"{tag}{i}-{j}"))
        return receipts

    def _cycle_chord(self, names: list[str], *, tag: str) -> list[dict[str, object]]:
        """Directed cycle + chord — one sparse SCC (density 2/(n-1), clean shape)."""
        receipts: list[dict[str, object]] = []
        n = len(names)
        for i in range(n):
            for step in (1, 2):
                receipts.append(
                    _corroborated(names[i], names[(i + step) % n], rid=f"{tag}{i}-{step}")
                )
        return receipts

    def test_majority_ring_still_severed(self) -> None:
        """Issue #97: a ring grown *larger* than the honest core is still severed.

        Previously the largest SCC was exempt as the "honest anchor", so an
        8-member wash ring facing a 5-member honest cycle became the anchor and
        kept its manufactured reputation (severed == empty set). Severance is
        now size-blind: the dense isolated ring is severed, the sparse honest
        cycle is spared.
        """
        honest = [f"mh{i}" for i in range(5)]
        ring = [f"mr{i}" for i in range(8)]
        receipts = self._cycle_chord(honest, tag="mh") + self._clique(ring, tag="mr")
        severed = _severed_dids(_corroboration_graph(receipts))
        assert severed == {_did(r) for r in ring}

    def test_issue_97_repro_ring_never_escapes(self) -> None:
        """The exact issue #97 graph: two isolated cliques, ring the larger one.

        The ring can no longer buy immunity with size. The evidence-free honest
        3-clique is *also* severed: an isolated dense clique with zero external
        corroboration is indistinguishable from a wash ring by graph shape, so
        the plugin refuses to certify either (fail-safe) instead of guessing by
        size (fail-open to the attacker).
        """
        honest = ["qh1", "qh2", "qh3"]
        ring = ["qs1", "qs2", "qs3", "qs4", "qs5"]
        receipts = self._clique(honest, tag="qh") + self._clique(ring, tag="qs")
        severed = _severed_dids(_corroboration_graph(receipts))
        assert {_did(r) for r in ring} <= severed
        assert severed == {_did(a) for a in honest + ring}

    def test_two_isolated_rings_both_severed(self) -> None:
        """A suspect neighbor does not exonerate.

        Two dense rings bridged only to each other (no contact with any clean
        component) are both severed — exoneration requires a corroborated edge
        to a *clean* component, not merely to another suspect.
        """
        honest = [f"th{i}" for i in range(8)]
        ring_a = [f"ta{i}" for i in range(3)]
        ring_b = [f"tb{i}" for i in range(3)]
        receipts = (
            self._cycle_chord(honest, tag="th")
            + self._clique(ring_a, tag="ta")
            + self._clique(ring_b, tag="tb")
        )
        receipts.append(_corroborated(ring_a[0], ring_b[0], rid="t-bridge"))
        severed = _severed_dids(_corroboration_graph(receipts))
        assert severed == {_did(a) for a in ring_a + ring_b}

    def test_isolated_mutual_pair_still_severed(self) -> None:
        """Edge-case pin: an isolated mutual-only pair is severed, as before."""
        honest = [f"ph{i}" for i in range(5)]
        receipts = self._cycle_chord(honest, tag="ph")
        receipts.append(_corroborated("pp1", "pp2", rid="pair-1"))
        receipts.append(_corroborated("pp2", "pp1", rid="pair-2"))
        severed = _severed_dids(_corroboration_graph(receipts))
        assert severed == {_did("pp1"), _did("pp2")}

    def test_collusion_shape_classification(self) -> None:
        """A sparse honest cycle is clean; a dense clique is collusion-shaped."""
        honest = [f"ch{i}" for i in range(5)]
        ring = [f"cr{i}" for i in range(4)]
        receipts = self._cycle_chord(honest, tag="ch") + self._clique(ring, tag="cr")
        graph = _corroboration_graph(receipts)
        assert _collusion_shaped(graph, sorted(_did(r) for r in ring)) is True
        assert _collusion_shaped(graph, sorted(_did(h) for h in honest)) is False


class TestScore:
    @pytest.mark.asyncio
    async def test_honest_scored_ring_severed(self) -> None:
        trust = AgentReceiptsTrust()
        honest = [f"honest-{i}" for i in range(5)]
        ring = [f"ring-{i}" for i in range(4)]
        for i in range(5):
            for k in (1, 2):
                r = _corroborated(honest[i], honest[(i + k) % 5], rid=f"h{i}-{k}")
                await trust.report(
                    AgentId(honest[i]),
                    Evidence(
                        reporter=AgentId(honest[i]),
                        subject=AgentId(honest[i]),
                        kind="positive",
                        detail=json.dumps(r),
                    ),
                )
        for i in range(4):
            for j in range(4):
                if i != j:
                    r = _corroborated(ring[i], ring[j], rid=f"r{i}-{j}")
                    await trust.report(
                        AgentId(ring[i]),
                        Evidence(
                            reporter=AgentId(ring[i]),
                            subject=AgentId(ring[i]),
                            kind="positive",
                            detail=json.dumps(r),
                        ),
                    )
        honest_score = await trust.score(AgentId("honest-0"))
        ring_score = await trust.score(AgentId("ring-0"))
        assert honest_score.score > 0.0
        assert honest_score.confidence == 1.0
        # severed: zero score AND zero confidence, but sample_count records the claim
        assert ring_score.score == 0.0
        assert ring_score.confidence == 0.0
        assert ring_score.sample_count > 0

    @pytest.mark.asyncio
    async def test_no_receipts_returns_neutral_prior(self) -> None:
        rep = await AgentReceiptsTrust().score(AgentId("nobody"))
        assert rep.score == 0.5
        assert rep.confidence == 0.0
        assert rep.sample_count == 0

    @pytest.mark.asyncio
    async def test_plain_string_detail_falls_back(self) -> None:
        """Stock-scenario plain-string detail uses the score-average heuristic."""
        trust = AgentReceiptsTrust()
        await trust.report(
            AgentId("a"),
            Evidence(reporter=AgentId("r"), subject=AgentId("a"), kind="positive", detail="ok"),
        )
        rep = await trust.score(AgentId("a"))
        assert rep.score == 1.0
        assert rep.sample_count == 1

    @pytest.mark.asyncio
    async def test_invalid_receipt_dict_falls_back_not_crashes(self) -> None:
        trust = AgentReceiptsTrust()
        bad = json.dumps({"issuer_did": _did("a"), "signature": "deadbeef", "action": {}})
        await trust.report(
            AgentId("a"),
            Evidence(reporter=AgentId("r"), subject=AgentId("a"), kind="negative", detail=bad),
        )
        rep = await trust.score(AgentId("a"))
        # fell back to heuristic (negative -> 0.0), did not enter the ledger
        assert rep.score == 0.0
        assert rep.sample_count == 1


class TestProtocolSurface:
    @pytest.mark.asyncio
    async def test_attest_produces_signed_attestation(self) -> None:
        trust = AgentReceiptsTrust()
        claim = Claim(subject=AgentId("a"), predicate="completed", value="task-1")
        att = await trust.attest(AgentId("a"), claim)
        assert att.claim == claim
        assert att.signature.algorithm == "ed25519"
        assert len(att.signature.value) == 64

    @pytest.mark.asyncio
    async def test_stake_is_noop_parity(self) -> None:
        trust = AgentReceiptsTrust()
        await trust.stake(AgentId("a"), 100)  # must not raise

    def test_normalize_bounds(self) -> None:
        assert _normalize(0.0) == 0.0
        assert 0.0 < _normalize(5.0) < 1.0
        assert _normalize(5.0) == pytest.approx(0.39346934, abs=1e-6)
