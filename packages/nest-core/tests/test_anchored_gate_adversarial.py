# SPDX-License-Identifier: Apache-2.0
"""Adversarial acceptance tests for ``validate_receipt_reputation_anchored``.

The validator grades the anchoring property from deterministic trace events
plus one pinned constant — the service identity of an independent CCF / Azure
Confidential Ledger transparency service — with zero filesystem, environment,
or clock reads. The anchoring evidence is the per-receipt ledger-signed write
receipt (``ccfreceipt:`` lines); the unsigned ``seal:`` chain is only a tamper
trip-wire and can never produce a PASS by itself (see
``test_ccf_root_of_trust.py`` for the forgery proofs).

These tests mint evidence with the LOCAL TEST-ONLY confidential ledger from
``nest_mocks.ccf_ledger`` and inject its service identity explicitly; the
production pinned constant remains a fail-closed placeholder.

Case 1: Honest run (write receipts verify against the pinned identity) -> PASS
Case 2: Non-anchoring baseline (no write receipts) -> FAIL
Case 3: Stray ledger file on disk, no write receipts -> FAIL (file must not be read)
Case 4: Archived trace from different cwd, no ledger file -> PASS (evidence on trace)
Case 5: Stale ledger file in cwd, no write receipts -> FAIL
Case 6: Post-registration tamper (mutate receipt content) -> FAIL
Case 7: Seal-chain tamper (drop a seal event) -> FAIL (trip-wire)
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from nest_core.canonical import SEAL_CHAIN_GENESIS, jcs_digest, seal_chain
from nest_core.validators import validate_receipt_reputation_anchored
from nest_mocks.ccf_ledger import LocalTestConfidentialLedger, receipt_bytes
from nest_plugins_reference.trust.agent_receipts import (
    cosign_receipt,
    did_for_pubkey,
    sign_receipt,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _seed(label: str) -> bytes:
    return hashlib.sha256(label.encode()).digest()[:32]


def _did(label: str) -> str:
    pub = (
        Ed25519PrivateKey.from_private_bytes(_seed(label))
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    return did_for_pubkey(pub)


def _corroborated_receipt(issuer_label: str, cp_label: str, rid: str) -> dict[str, Any]:
    r: dict[str, Any] = {
        "receipt_id": rid,
        "issuer_did": _did(issuer_label),
        "action": {"category": "purchase", "counterparty_did": _did(cp_label)},
    }
    r = sign_receipt(r, issuer_seed=_seed(issuer_label))
    return cosign_receipt(r, counterparty_seed=_seed(cp_label))


def _receipt_event(receipt: dict[str, Any], agent: str = "honest-0") -> dict[str, Any]:
    return {"agent": agent, "kind": "send", "msg": "receipt:" + json.dumps(receipt), "ts": 0.0}


def _seal_events_from(receipts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build the seal:* trip-wire lines exactly as CapsuleEmitTrust would emit them."""
    chain = SEAL_CHAIN_GENESIS
    events: list[dict[str, Any]] = []
    for seq, r in enumerate(receipts):
        digest = jcs_digest(r)
        chain = seal_chain(chain, digest)
        events.append(
            {
                "agent": "auditor-0",
                "kind": "broadcast",
                "msg": f"seal:{seq}:{digest}:{chain}",
                "ts": 1.0,
            }
        )
    return events


def _ccf_events_from(
    receipts: list[dict[str, Any]], ledger: LocalTestConfidentialLedger
) -> list[dict[str, Any]]:
    """Mint one ledger write receipt per receipt digest — the anchoring evidence."""
    digests = [jcs_digest(r) for r in receipts]
    write_receipts = ledger.write_receipts([bytes.fromhex(d) for d in digests])
    return [
        {
            "agent": "auditor-0",
            "kind": "broadcast",
            "msg": f"ccfreceipt:{digest}:{receipt_bytes(wr).hex()}",
            "ts": 1.0,
        }
        for digest, wr in zip(digests, write_receipts, strict=True)
    ]


def _score_event() -> dict[str, Any]:
    return {
        "agent": "auditor-0",
        "kind": "broadcast",
        "msg": "score:honest-0:0.632121:1.000000:honest",
        "ts": 1.0,
    }


def _build_trace(
    receipts: list[dict[str, Any]],
    ledger: LocalTestConfidentialLedger | None = None,
    with_seals: bool = True,
) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = [_receipt_event(r) for r in receipts]
    events.append(_score_event())
    if with_seals:
        events.extend(_seal_events_from(receipts))
    if ledger is not None:
        events.extend(_ccf_events_from(receipts, ledger))
    return events


def _anchored(events: list[dict[str, Any]], identity_pem: str) -> Any:
    results = validate_receipt_reputation_anchored(events, service_identity_pem=identity_pem)
    matched = [r for r in results if r.name == "receipt_reputation_anchored"]
    assert matched, "receipt_reputation_anchored validator returned no result"
    return matched[0]


def _build_receipts() -> list[dict[str, Any]]:
    return [
        _corroborated_receipt("issuer-a", "cp-a", "r0"),
        _corroborated_receipt("issuer-b", "cp-b", "r1"),
        _corroborated_receipt("issuer-c", "cp-c", "r2"),
    ]


# ---------------------------------------------------------------------------
# A minimal "stale" capsule ledger fixture (old format, on-disk)
# ---------------------------------------------------------------------------


def _write_stale_ledger(path: Path, receipts: list[dict[str, Any]]) -> None:
    """Write a capsule_ledger.jsonl file in the old on-disk format."""
    with path.open("w") as f:
        for r in receipts:
            capsule = {
                "capsule_id": r.get("receipt_id", "?"),
                "model_attestation": {
                    "compute_attestation": {"agent_input_digest": jcs_digest(r)},
                },
            }
            f.write(json.dumps(capsule) + "\n")


# ---------------------------------------------------------------------------
# Case 1: Honest run -> PASS
# ---------------------------------------------------------------------------


def test_case1_honest_run_passes() -> None:
    """Ledger-signed write receipts covering every receipt on the trace -> PASS."""
    receipts = _build_receipts()
    ledger = LocalTestConfidentialLedger()
    events = _build_trace(receipts, ledger=ledger)
    result = _anchored(events, ledger.service_identity_pem)
    assert result.passed, f"Case 1 expected PASS: {result.detail}"
    assert "anchored" in result.detail


# ---------------------------------------------------------------------------
# Case 2: Non-anchoring baseline (no write receipts) -> FAIL
# ---------------------------------------------------------------------------


def test_case2_no_write_receipts_fails() -> None:
    """No ``ccfreceipt:`` events on the trace -> FAIL (non-anchoring baseline)."""
    receipts = _build_receipts()
    ledger = LocalTestConfidentialLedger()
    events = _build_trace(receipts, ledger=None, with_seals=False)
    result = _anchored(events, ledger.service_identity_pem)
    assert not result.passed, "Case 2 expected FAIL"
    assert "does not anchor" in result.detail


# ---------------------------------------------------------------------------
# Case 3: Stray ledger file on disk, no write receipts -> FAIL
# ---------------------------------------------------------------------------


def test_case3_stray_ledger_on_disk_no_evidence_fails(tmp_path: Path) -> None:
    """A capsule_ledger.jsonl file on disk must NOT be read; without evidence -> FAIL.

    The validator is event-only. Even if a stray ledger file is present in the
    cwd, the absence of write receipts on the trace causes FAIL, proving no
    filesystem read.
    """
    receipts = _build_receipts()
    ledger = LocalTestConfidentialLedger()
    stale = tmp_path / "capsule_ledger.jsonl"
    _write_stale_ledger(stale, receipts)

    old_cwd = os.getcwd()
    try:
        os.chdir(tmp_path)
        events = _build_trace(receipts, ledger=None)  # seals only, NO write receipts
        result = _anchored(events, ledger.service_identity_pem)
    finally:
        os.chdir(old_cwd)

    assert not result.passed, (
        "Case 3 expected FAIL: stray file on disk must not rescue a trace with no evidence"
    )
    assert "does not anchor" in result.detail


# ---------------------------------------------------------------------------
# Case 4: Archived trace from different cwd, no ledger file -> PASS
# ---------------------------------------------------------------------------


def test_case4_archived_trace_different_cwd_passes(tmp_path: Path) -> None:
    """Trace with valid write receipts from a cwd that has nothing else -> PASS.

    Proves the validator never falls back to reading any file from any cwd:
    the write receipts on the trace are the sole evidence, and they suffice.
    """
    receipts = _build_receipts()
    ledger = LocalTestConfidentialLedger()
    events = _build_trace(receipts, ledger=ledger)

    old_cwd = os.getcwd()
    try:
        os.chdir(tmp_path)
        result = _anchored(events, ledger.service_identity_pem)
    finally:
        os.chdir(old_cwd)

    assert result.passed, f"Case 4 expected PASS: {result.detail}"


# ---------------------------------------------------------------------------
# Case 5: Stale ledger file in cwd, no write receipts -> FAIL
# ---------------------------------------------------------------------------


def test_case5_stale_ledger_in_cwd_no_evidence_fails(tmp_path: Path) -> None:
    """Stale ledger file present in cwd, but no write receipts on the trace -> FAIL.

    This is the same scenario as Case 3 restated: the stale file must be
    ignored. No file (regardless of content or location) can cause a PASS
    without ledger-signed evidence on the trace.
    """
    receipts = _build_receipts()
    ledger = LocalTestConfidentialLedger()
    stale = tmp_path / "capsule_ledger.jsonl"
    _write_stale_ledger(stale, receipts)

    old_cwd = os.getcwd()
    try:
        os.chdir(tmp_path)
        events = _build_trace(receipts, ledger=None, with_seals=False)
        result = _anchored(events, ledger.service_identity_pem)
    finally:
        os.chdir(old_cwd)

    assert not result.passed, "Case 5 expected FAIL: stale file must not rescue missing evidence"


# ---------------------------------------------------------------------------
# Case 6: Post-registration tamper (mutate receipt content) -> FAIL
# ---------------------------------------------------------------------------


def test_case6_post_registration_tamper_fails() -> None:
    """A receipt mutated after ledger registration no longer verifies -> FAIL.

    The trace carries write receipts binding the *original* content, but the
    receipt line carries mutated content. The re-signed tampered receipt has a
    valid Ed25519 issuer signature, so it enters the receipt set — but its
    recomputed JCS digest was never signed by the ledger.
    """
    receipts = _build_receipts()
    ledger = LocalTestConfidentialLedger()
    evidence = _ccf_events_from(receipts, ledger)  # minted for the ORIGINALS

    tampered: dict[str, Any] = {
        "receipt_id": "r0",
        "issuer_did": _did("issuer-a"),
        "action": {"category": "premium_purchase", "counterparty_did": _did("cp-a")},
    }
    tampered = sign_receipt(tampered, issuer_seed=_seed("issuer-a"))
    tampered = cosign_receipt(tampered, counterparty_seed=_seed("cp-a"))

    tampered_receipts = [tampered, receipts[1], receipts[2]]
    events = [_receipt_event(r) for r in tampered_receipts]
    events.append(_score_event())
    events.extend(evidence)

    result = _anchored(events, ledger.service_identity_pem)
    assert not result.passed, "Case 6 expected FAIL: tampered receipt must not be anchored"
    assert "no confidential-ledger write receipt that verifies" in result.detail


# ---------------------------------------------------------------------------
# Case 7: Seal-chain tamper (drop a seal event) -> FAIL (trip-wire)
# ---------------------------------------------------------------------------


def test_case7_chain_tamper_fails() -> None:
    """Dropping a seal event breaks the trip-wire chain replay -> FAIL.

    Even with valid write receipts on the trace: an internally-inconsistent
    seal chain proves the trace was reordered or truncated after emission.
    """
    receipts = _build_receipts()
    ledger = LocalTestConfidentialLedger()
    seal_evs = _seal_events_from(receipts)

    events = [_receipt_event(r) for r in receipts]
    events.append(_score_event())
    events.extend(seal_evs[1:])  # drop seq=0
    events.extend(_ccf_events_from(receipts, ledger))

    result = _anchored(events, ledger.service_identity_pem)
    assert not result.passed, "Case 7 expected FAIL: chain tamper must be detected"
    assert "seal chain tampered" in result.detail
