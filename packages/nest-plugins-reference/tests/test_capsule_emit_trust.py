# SPDX-License-Identifier: Apache-2.0
"""Tests for CapsuleEmitTrust: smoke tests and Gate-3 in-memory anchoring.

Ported from examples/capsule-emit/tests/test_smoke.py (non-payments tests only).
The plugin no longer reads filesystem ledgers or depends on ``capsule_emit``;
sealing is in-process via ``nest_core.canonical``.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from nest_core.types import AgentId, Evidence
from nest_plugins_reference.trust.agent_receipts import (
    cosign_receipt,
    did_for_pubkey,
    sign_receipt,
)
from nest_plugins_reference.trust.capsule_emit import CapsuleEmitTrust


def _make_corroborated_receipt(
    issuer_seed: bytes, counterparty_seed: bytes, action_id: str = "act-1"
) -> dict[str, Any]:
    """Return a signed and co-signed receipt using the two given seeds."""
    issuer_pub = (
        Ed25519PrivateKey.from_private_bytes(issuer_seed)
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    cp_pub = (
        Ed25519PrivateKey.from_private_bytes(counterparty_seed)
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    receipt: dict[str, Any] = {
        "issuer_did": did_for_pubkey(issuer_pub),
        "action": {
            "category": "purchase",
            "action_id": action_id,
            "counterparty_did": did_for_pubkey(cp_pub),
        },
    }
    signed = sign_receipt(receipt, issuer_seed=issuer_seed)
    return cosign_receipt(signed, counterparty_seed=counterparty_seed)


@pytest.mark.asyncio
async def test_trust_report_and_score_fallback() -> None:
    """Plain-string evidence triggers the fallback reputation path."""
    plugin = CapsuleEmitTrust()
    agent = AgentId("agent-a")
    reporter = AgentId("agent-b")

    ev = Evidence(reporter=reporter, subject=agent, kind="positive", detail="good work")
    await plugin.report(agent, ev)

    score = await plugin.score(agent)
    assert score.agent_id == agent
    assert 0.0 <= score.score <= 1.0


@pytest.mark.asyncio
async def test_gate3_tampered_receipt_excluded_from_score() -> None:
    """Gate 3 fires: mutated receipt digest no longer matches sealed digest.

    Attack: an adversary modifies a receipt's action category in-memory after the
    seal was computed. CapsuleEmitTrust stores the sealed digest at report time;
    at score time it recomputes the digest from the (now-mutated) receipt and sees
    a mismatch — the receipt is excluded and the score drops to zero.
    AgentReceiptsTrust cannot detect this attack because it has no sealed reference.
    """
    issuer_seed = hashlib.sha256(b"honest-agent").digest()[:32]
    cp_seed = hashlib.sha256(b"counterparty").digest()[:32]

    plugin = CapsuleEmitTrust()
    receipt = _make_corroborated_receipt(issuer_seed, cp_seed)
    agent = AgentId("honest-agent")

    ev = Evidence(
        reporter=AgentId("counterparty"),
        subject=agent,
        kind="positive",
        detail=json.dumps(receipt),
    )
    await plugin.report(agent, ev)

    # Before tampering: valid, sealed receipt contributes to score.
    score_before = await plugin.score(agent)
    assert score_before.score > 0.0, "valid corroborated receipt should build reputation"
    assert score_before.confidence > 0.0

    # Adversary mutates the in-memory receipt.
    plugin.receipts[-1]["action"]["category"] = "premium_purchase"

    # Gate 3: sealed digest no longer matches the mutated content -> excluded.
    score_after = await plugin.score(agent)
    assert score_after.score == 0.0, "Gate 3 must exclude tampered receipt from reputation"
    assert score_after.confidence == 0.0


@pytest.mark.asyncio
async def test_float_bearing_receipt_does_not_crash_score() -> None:
    """A receipt carrying a raw float must not crash score().

    jcs_digest raises ValueError on a raw float. The seal call catches it and
    marks the receipt as un-sealed; score() then excludes it via Gate 3.
    Either path must return cleanly rather than propagate the exception.
    """
    issuer_seed = hashlib.sha256(b"floaty-agent").digest()[:32]
    cp_seed = hashlib.sha256(b"floaty-cp").digest()[:32]
    issuer_pub = (
        Ed25519PrivateKey.from_private_bytes(issuer_seed)
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    cp_pub = (
        Ed25519PrivateKey.from_private_bytes(cp_seed)
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    receipt: dict[str, Any] = {
        "issuer_did": did_for_pubkey(issuer_pub),
        "action": {
            "category": "purchase",
            "amount": 19.99,  # raw float -> ValueError in jcs_digest
            "counterparty_did": did_for_pubkey(cp_pub),
        },
    }
    receipt = sign_receipt(receipt, issuer_seed=issuer_seed)
    receipt = cosign_receipt(receipt, counterparty_seed=cp_seed)

    plugin = CapsuleEmitTrust()
    agent = AgentId("floaty-agent")
    ev = Evidence(
        reporter=AgentId("floaty-cp"),
        subject=agent,
        kind="positive",
        detail=json.dumps(receipt),
    )
    await plugin.report(agent, ev)  # must not raise despite the float

    score = await plugin.score(agent)
    assert 0.0 <= score.score <= 1.0
    assert score.score == 0.0, "receipt that cannot be digest-verified must not build reputation"


@pytest.mark.asyncio
async def test_multiple_receipts_same_pair_same_category_all_anchored() -> None:
    """Several receipts between the same pair all build reputation (no key collision).

    Each receipt is keyed by its full content digest, so three distinct receipts
    with the same issuer/counterparty/category each get their own sealed entry.
    Gate-3 confidence must be 1.0 (all three anchored).
    """
    issuer_seed = hashlib.sha256(b"repeat-agent").digest()[:32]
    cp_seed = hashlib.sha256(b"repeat-cp").digest()[:32]
    agent = AgentId("repeat-agent")

    plugin = CapsuleEmitTrust()

    for n in range(3):
        receipt = _make_corroborated_receipt(issuer_seed, cp_seed, action_id=f"nonce-{n}")
        del receipt["action"]["action_id"]
        receipt["action"]["nonce"] = n
        base = {k: v for k, v in receipt.items() if k not in ("signature", "evidence")}
        signed = sign_receipt(base, issuer_seed=issuer_seed)
        receipt = cosign_receipt(signed, counterparty_seed=cp_seed)

        ev = Evidence(
            reporter=AgentId("repeat-cp"),
            subject=agent,
            kind="positive",
            detail=json.dumps(receipt),
        )
        await plugin.report(agent, ev)

    assert len(plugin.receipts) == 3
    score = await plugin.score(agent)
    assert score.sample_count == 3
    assert score.confidence == pytest.approx(1.0), (
        "all same-pair/same-category receipts must remain anchored (no key collision)"
    )
    assert score.score > 0.0


@pytest.mark.asyncio
async def test_seal_events_returned() -> None:
    """seal_events() returns one triple per receipt that was sealed."""
    issuer_seed = hashlib.sha256(b"seal-agent").digest()[:32]
    cp_seed = hashlib.sha256(b"seal-cp").digest()[:32]
    agent = AgentId("seal-agent")
    plugin = CapsuleEmitTrust()

    for i in range(2):
        receipt = _make_corroborated_receipt(issuer_seed, cp_seed, action_id=f"r{i}")
        ev = Evidence(
            reporter=AgentId("seal-cp"),
            subject=agent,
            kind="positive",
            detail=json.dumps(receipt),
        )
        await plugin.report(agent, ev)

    seals = plugin.seal_events()
    assert len(seals) == 2
    for i, (seq, subject_digest, chain_hash) in enumerate(seals):
        assert seq == i
        assert len(subject_digest) == 64  # hex SHA-256
        assert len(chain_hash) == 64


@pytest.mark.asyncio
async def test_ccf_receipt_events_from_injected_store() -> None:
    """The plugin emits (digest, receipt_hex) pairs only for digests in its store."""
    from nest_core.canonical import jcs_digest

    issuer_seed = hashlib.sha256(b"ccf-agent").digest()[:32]
    cp_seed = hashlib.sha256(b"ccf-cp").digest()[:32]
    agent = AgentId("ccf-agent")

    covered = _make_corroborated_receipt(issuer_seed, cp_seed, action_id="covered")
    uncovered = _make_corroborated_receipt(issuer_seed, cp_seed, action_id="uncovered")
    store = {jcs_digest(covered): b'{"fake": "write receipt bytes"}'}

    plugin = CapsuleEmitTrust(ccf_receipts=store)
    for receipt in (covered, uncovered):
        ev = Evidence(
            reporter=AgentId("ccf-cp"),
            subject=agent,
            kind="positive",
            detail=json.dumps(receipt),
        )
        await plugin.report(agent, ev)

    pairs = plugin.ccf_receipt_events()
    assert pairs == [(jcs_digest(covered), b'{"fake": "write receipt bytes"}'.hex())], (
        "exactly the covered digest, carrying the stored receipt bytes"
    )


@pytest.mark.asyncio
async def test_ccf_receipt_events_empty_without_fixtures() -> None:
    """Default construction (no committed fixtures yet) emits no evidence — fail-closed."""
    issuer_seed = hashlib.sha256(b"nofix-agent").digest()[:32]
    cp_seed = hashlib.sha256(b"nofix-cp").digest()[:32]
    agent = AgentId("nofix-agent")

    plugin = CapsuleEmitTrust()
    receipt = _make_corroborated_receipt(issuer_seed, cp_seed)
    ev = Evidence(
        reporter=AgentId("nofix-cp"),
        subject=agent,
        kind="positive",
        detail=json.dumps(receipt),
    )
    await plugin.report(agent, ev)

    assert plugin.seal_events(), "the receipt is sealed"
    assert plugin.ccf_receipt_events() == [], (
        "no committed write-receipt fixtures -> no anchoring evidence emitted"
    )
