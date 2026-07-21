# SPDX-License-Identifier: Apache-2.0
# pyright: reportPrivateUsage=false
"""Hypothesis property-based tests for the agent_receipts trust plugin.

These complement the example-based ``test_agent_receipts.py`` by asserting
structural invariants over *generated* ledgers and receipt sets:

1. score in [0, 1] for any ledger (the ``1 - exp(-raw/K)`` normalization).
2. confidence (corroboration rate) in [0, 1].
3. Empty ledger -> raw 0, score 0, no severance, and ``score()`` never raises.
4. Permutation invariance: report order does not change score/confidence
   (severance + scoring are order-independent).
5. Corroboration gate: adding an *uncorroborated* receipt never raises an
   agent's score above its corroborated-only score.
6. Isolated-ring severance: any isolated dense clique (size >= 3) collapses to
   score ~0 for every ring member.
7. Anchor safety: bolting an isolated colluding ring onto the ledger never
   lowers an honest anchor agent's score.
8. Size-blind severance (issue #97): the isolated dense ring is severed and
   the sparse honest cycle spared at every size ratio, including ring larger
   than or equal to the honest population.

The plugin signs/verifies Ed25519 per receipt, so generated sizes are kept
small and every property carries ``deadline=None`` to stay non-flaky on CI.
Determinism is exact: weights are exact floats, bounded sums are exact, and
severance is ``sorted()``-deterministic, so permutation invariance is asserted
with ``==`` (not ``approx``).
"""

from __future__ import annotations

import hashlib
import json
import random
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from hypothesis import given, settings
from hypothesis import strategies as st
from nest_core.types import AgentId, Evidence
from nest_plugins_reference.trust.agent_receipts import (
    DEFAULT_CATEGORY_WEIGHTS,
    AgentReceiptsTrust,
    _corroboration_graph,
    _effective_receipts,
    _normalize,
    _raw_reputation,
    _severed_dids,
    cosign_receipt,
    did_for_pubkey,
    sign_receipt,
)

# ---------------------------------------------------------------------------
# Deterministic Ed25519 helpers (mirroring test_agent_receipts.py)
# ---------------------------------------------------------------------------

# Category names the plugin assigns weight to; "other"/breached weigh 0.
_WEIGHTED_CATEGORIES = sorted(DEFAULT_CATEGORY_WEIGHTS)


def _seed(name: str) -> bytes:
    return hashlib.sha256(name.encode()).digest()[:32]


def _did(name: str) -> str:
    sk = Ed25519PrivateKey.from_private_bytes(_seed(name))
    return did_for_pubkey(sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))


def _receipt(issuer: str, cp: str, *, rid: str, category: str = "purchase") -> dict[str, Any]:
    r: dict[str, Any] = {
        "receipt_id": rid,
        "issuer_did": _did(issuer),
        "action": {"category": category, "counterparty_did": _did(cp)},
    }
    return sign_receipt(r, issuer_seed=_seed(issuer))


def _corroborated(issuer: str, cp: str, *, rid: str, category: str = "purchase") -> dict[str, Any]:
    return cosign_receipt(
        _receipt(issuer, cp, rid=rid, category=category), counterparty_seed=_seed(cp)
    )


async def _report(trust: AgentReceiptsTrust, issuer: str, receipt: dict[str, Any]) -> None:
    """Feed a receipt to the plugin as a JSON-detail Evidence (as scenarios do)."""
    await trust.report(
        AgentId(issuer),
        Evidence(
            reporter=AgentId(issuer),
            subject=AgentId(issuer),
            kind="positive",
            detail=json.dumps(receipt),
        ),
    )


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# A small pool of distinct agent names. Issuer must differ from counterparty
# (self-corroboration is rejected), so we draw issuer/cp from this pool and
# discard self-pairs at build time.
_NAME_POOL = [f"agent-{i}" for i in range(6)]


@st.composite
def _ledger_strategy(draw: st.DrawFn) -> list[dict[str, Any]]:
    """Generate a bounded list of corroborated receipts between distinct agents."""
    n = draw(st.integers(min_value=0, max_value=12))
    receipts: list[dict[str, Any]] = []
    for k in range(n):
        issuer = draw(st.sampled_from(_NAME_POOL))
        cp = draw(st.sampled_from([x for x in _NAME_POOL if x != issuer]))
        category = draw(st.sampled_from(_WEIGHTED_CATEGORIES))
        # Mix corroborated and bare receipts so confidence varies across [0, 1].
        if draw(st.booleans()):
            receipts.append(_corroborated(issuer, cp, rid=f"r{k}", category=category))
        else:
            receipts.append(_receipt(issuer, cp, rid=f"r{k}", category=category))
    return receipts


def _honest_anchor(size: int) -> tuple[list[str], list[dict[str, Any]]]:
    """A cycle+chord SCC of ``size`` honest agents (mirrors _honest_and_ring)."""
    honest = [f"honest-{i}" for i in range(size)]
    receipts: list[dict[str, Any]] = []
    for i in range(size):
        for step in (1, 2):
            receipts.append(_corroborated(honest[i], honest[(i + step) % size], rid=f"h{i}-{step}"))
    return honest, receipts


def _isolated_ring(size: int) -> tuple[list[str], list[dict[str, Any]]]:
    """A dense isolated clique: all distinct ordered pairs, both directions."""
    ring = [f"ring-{i}" for i in range(size)]
    receipts: list[dict[str, Any]] = []
    for i in range(size):
        for j in range(size):
            if i != j:
                receipts.append(_corroborated(ring[i], ring[j], rid=f"ring{i}-{j}"))
    return ring, receipts


# ---------------------------------------------------------------------------
# 1 & 2. Score and confidence bounds over arbitrary ledgers
# ---------------------------------------------------------------------------


class TestScoreBounds:
    @settings(max_examples=40, deadline=None)
    @given(ledger=_ledger_strategy())
    @pytest.mark.asyncio
    async def test_score_and_confidence_in_unit_interval(
        self, ledger: list[dict[str, Any]]
    ) -> None:
        """score in [0, 1] and confidence in [0, 1] for every issuer in any ledger."""
        trust = AgentReceiptsTrust()
        for r in ledger:
            await _report(trust, str(r["issuer_did"]), r)
        for name in _NAME_POOL:
            rep = await trust.score(AgentId(name))
            assert 0.0 <= rep.score <= 1.0
            assert 0.0 <= rep.confidence <= 1.0

    @settings(max_examples=200, deadline=None)
    @given(raw=st.floats(min_value=0.0, max_value=1e6, allow_nan=False, allow_infinity=False))
    def test_normalize_always_in_unit_interval(self, raw: float) -> None:
        """The normalization 1 - exp(-raw/K) maps any raw >= 0 into [0, 1)."""
        s = _normalize(raw)
        assert 0.0 <= s <= 1.0


# ---------------------------------------------------------------------------
# 3. Empty ledger
# ---------------------------------------------------------------------------


class TestEmptyLedger:
    def test_empty_ledger_normalization_layer_is_zero(self) -> None:
        """No receipts -> raw 0, score 0, no severance (the normalization invariant)."""
        assert _raw_reputation([], DEFAULT_CATEGORY_WEIGHTS) == 0.0
        assert _normalize(0.0) == 0.0
        assert _effective_receipts([]) == []
        assert _severed_dids(_corroboration_graph([])) == set()

    @pytest.mark.asyncio
    async def test_score_on_empty_ledger_does_not_raise(self) -> None:
        """An agent with no receipts returns the neutral prior 0.5 without error."""
        rep = await AgentReceiptsTrust().score(AgentId("nobody"))
        assert rep.score == 0.5
        assert rep.confidence == 0.0
        assert rep.sample_count == 0


# ---------------------------------------------------------------------------
# 4. Permutation invariance
# ---------------------------------------------------------------------------


class TestPermutationInvariance:
    @settings(max_examples=30, deadline=None)
    @given(ledger=_ledger_strategy(), perm_seed=st.integers(min_value=0, max_value=2**31))
    @pytest.mark.asyncio
    async def test_report_order_does_not_change_scores(
        self, ledger: list[dict[str, Any]], perm_seed: int
    ) -> None:
        """Reporting the same multiset of receipts in two orders yields identical
        score and confidence for every agent (exact ==, not approx)."""
        shuffled = list(ledger)
        random.Random(perm_seed).shuffle(shuffled)

        trust_a = AgentReceiptsTrust()
        for r in ledger:
            await _report(trust_a, str(r["issuer_did"]), r)
        trust_b = AgentReceiptsTrust()
        for r in shuffled:
            await _report(trust_b, str(r["issuer_did"]), r)

        for name in _NAME_POOL:
            ra = await trust_a.score(AgentId(name))
            rb = await trust_b.score(AgentId(name))
            assert ra.score == rb.score
            assert ra.confidence == rb.confidence


# ---------------------------------------------------------------------------
# 5. Corroboration gate is monotone-down on score
# ---------------------------------------------------------------------------


class TestCorroborationGate:
    @settings(max_examples=30, deadline=None)
    @given(
        issuer=st.sampled_from(_NAME_POOL),
        cp_idx=st.integers(min_value=0, max_value=len(_NAME_POOL) - 1),
        category=st.sampled_from(_WEIGHTED_CATEGORIES),
    )
    @pytest.mark.asyncio
    async def test_uncorroborated_receipt_never_raises_score(
        self, issuer: str, cp_idx: int, category: str
    ) -> None:
        """Adding a valid but uncorroborated receipt cannot increase an agent's
        score above its corroborated-only score (only confidence may fall)."""
        cp = _NAME_POOL[cp_idx] if _NAME_POOL[cp_idx] != issuer else _NAME_POOL[(cp_idx + 1) % 6]
        trust = AgentReceiptsTrust()
        # One corroborated receipt establishes the baseline corroborated-only score.
        await _report(trust, issuer, _corroborated(issuer, cp, rid="base", category=category))
        base = await trust.score(AgentId(issuer))
        # Add an uncorroborated (signed, uncosigned) receipt; it enters the ledger
        # but is filtered by the corroboration gate.
        await _report(trust, issuer, _receipt(issuer, cp, rid="extra", category=category))
        after = await trust.score(AgentId(issuer))
        assert after.score <= base.score


# ---------------------------------------------------------------------------
# 6. Isolated-ring severance
# ---------------------------------------------------------------------------


class TestIsolatedRingSeverance:
    @settings(max_examples=20, deadline=None)
    @given(ring_size=st.integers(min_value=3, max_value=5))
    @pytest.mark.asyncio
    async def test_isolated_dense_ring_collapses_to_zero(self, ring_size: int) -> None:
        """Every member of an isolated dense clique (alongside a strictly larger
        honest anchor) scores ~0 with zero confidence."""
        # Anchor must be strictly larger than the ring so the ring is never the
        # anchor SCC; ring + 2 keeps it strictly larger and avoids size ties.
        honest, anchor_receipts = _honest_anchor(ring_size + 2)
        ring, ring_receipts = _isolated_ring(ring_size)

        trust = AgentReceiptsTrust()
        for r in anchor_receipts:
            await _report(trust, str(r["issuer_did"]), r)
        for r in ring_receipts:
            await _report(trust, str(r["issuer_did"]), r)

        for member in ring:
            rep = await trust.score(AgentId(member))
            assert rep.score == 0.0
            assert rep.confidence == 0.0
            assert rep.sample_count > 0  # the wash-traded claims are still counted
        # Sanity: at least one honest anchor agent kept a positive score.
        anchor_rep = await trust.score(AgentId(honest[0]))
        assert anchor_rep.score > 0.0


# ---------------------------------------------------------------------------
# 7. Anchor safety
# ---------------------------------------------------------------------------


class TestAnchorSafety:
    @settings(max_examples=20, deadline=None)
    @given(ring_size=st.integers(min_value=3, max_value=5))
    @pytest.mark.asyncio
    async def test_adding_isolated_ring_never_lowers_anchor_score(self, ring_size: int) -> None:
        """An honest anchor agent's score is unchanged by bolting on an isolated
        colluding ring (the ring is severed; the anchor is untouched)."""
        honest, anchor_receipts = _honest_anchor(ring_size + 2)

        trust_clean = AgentReceiptsTrust()
        for r in anchor_receipts:
            await _report(trust_clean, str(r["issuer_did"]), r)
        before = await trust_clean.score(AgentId(honest[0]))

        trust_poisoned = AgentReceiptsTrust()
        for r in anchor_receipts:
            await _report(trust_poisoned, str(r["issuer_did"]), r)
        _ring, ring_receipts = _isolated_ring(ring_size)
        for r in ring_receipts:
            await _report(trust_poisoned, str(r["issuer_did"]), r)
        after = await trust_poisoned.score(AgentId(honest[0]))

        assert after.score >= before.score


# ---------------------------------------------------------------------------
# 8. Size-blind severance (issue #97)
# ---------------------------------------------------------------------------


class TestSizeBlindSeverance:
    @settings(max_examples=20, deadline=None)
    @given(
        honest_size=st.integers(min_value=5, max_value=12),
        ring_size=st.integers(min_value=3, max_value=12),
    )
    def test_ring_severed_at_any_size_ratio(self, honest_size: int, ring_size: int) -> None:
        """Severance is size-blind (issue #97).

        For every size ratio — including ring > honest and ring == honest,
        where the old largest-SCC anchor exemption inverted the property — the
        isolated dense ring is severed exactly, and no member of the sparse
        honest cycle (density 2/(n-1) < RING_MIN_DENSITY for n >= 5) is ever
        severed.
        """
        _honest, anchor_receipts = _honest_anchor(honest_size)
        ring, ring_receipts = _isolated_ring(ring_size)
        severed = _severed_dids(_corroboration_graph(anchor_receipts + ring_receipts))
        assert severed == {_did(r) for r in ring}
