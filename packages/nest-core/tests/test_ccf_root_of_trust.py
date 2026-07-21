# SPDX-License-Identifier: Apache-2.0
"""Root-of-trust acceptance tests for the anchoring validator.

THE acceptance gate for the root-of-trust rework, written FIRST (before the
fix). The hole: the on-trace seal ``seal:<seq>:<subject_digest>:<chain_hash>``
is unsigned and ``subject_digest`` is a pure function of plaintext receipt
content already on the trace — so a party that anchors NOTHING can recompute
the digests, rebuild the hash chain, and emit a seal set the validator grades
PASS. The evidence is authored by the party under test (self-authored evidence).

These tests assert the property the validator MUST have: anchoring evidence is
only acceptable when it is authored by an independent transparency service
whose private key the participant does not hold — a verifiable CCF / Azure
Confidential Ledger write receipt (Merkle inclusion proof + service-identity
signature over the tree head) that verifies against a pinned service identity.
Fabricated seals carry no such signature, so every forgery below must grade
FAIL.
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
from nest_core.ccf_receipt import PINNED_ACL_SERVICE_IDENTITY_PEM, compute_claims_digest
from nest_core.validators import validate_receipt_reputation_anchored
from nest_mocks.ccf_ledger import (
    WRONG_SERVICE_LABEL,
    LocalTestConfidentialLedger,
    receipt_bytes,
)
from nest_plugins_reference.trust.agent_receipts import (
    cosign_receipt,
    did_for_pubkey,
    sign_receipt,
)

# ---------------------------------------------------------------------------
# Plaintext-only helpers: everything below is computable by ANY trace reader.
# No ledger key material appears anywhere in the forgery section — that is the
# point: a forger has exactly these inputs and nothing else.
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


def _receipts() -> list[dict[str, Any]]:
    return [
        _corroborated_receipt("issuer-a", "cp-a", "r0"),
        _corroborated_receipt("issuer-b", "cp-b", "r1"),
        _corroborated_receipt("issuer-c", "cp-c", "r2"),
    ]


def _receipt_event(receipt: dict[str, Any], agent: str = "honest-0") -> dict[str, Any]:
    return {"agent": agent, "kind": "send", "msg": "receipt:" + json.dumps(receipt), "ts": 0.0}


def _score_event() -> dict[str, Any]:
    return {
        "agent": "auditor-0",
        "kind": "broadcast",
        "msg": "score:honest-0:0.632121:1.000000:honest",
        "ts": 1.0,
    }


def _forged_seal_events(
    receipts: list[dict[str, Any]], agent: str = "mallory-0"
) -> list[dict[str, Any]]:
    """THE forgery: rebuild a chain-valid seal set from plaintext trace content.

    This is exactly what a non-anchoring party (any registered plugin, or any
    agent via ``ctx.broadcast``) can do: read the ``receipt:`` lines, recompute
    each JCS digest, refold the public hash chain, and broadcast the seals. It
    anchors nothing and signs nothing.
    """
    chain = SEAL_CHAIN_GENESIS
    events: list[dict[str, Any]] = []
    for seq, r in enumerate(receipts):
        digest = jcs_digest(r)
        chain = seal_chain(chain, digest)
        events.append(
            {
                "agent": agent,
                "kind": "broadcast",
                "msg": f"seal:{seq}:{digest}:{chain}",
                "ts": 1.0,
            }
        )
    return events


def _anchored(events: list[dict[str, Any]]) -> Any:
    results = validate_receipt_reputation_anchored(events)
    matched = [r for r in results if r.name == "receipt_reputation_anchored"]
    assert matched, "receipt_reputation_anchored validator returned no result"
    return matched[0]


# ---------------------------------------------------------------------------
# The acceptance gate: forged seals from plaintext MUST grade FAIL
# ---------------------------------------------------------------------------


def test_forged_seal_events_from_plaintext_fail() -> None:
    """A non-anchoring party's fabricated seal set must grade FAIL.

    The trace carries valid receipts plus seals forged purely from their
    plaintext — no transparency service signed anything. If this grades PASS,
    the gate accepts self-authored evidence and the anchoring property is void.
    """
    receipts = _receipts()
    events = [_receipt_event(r) for r in receipts]
    events.append(_score_event())
    events.extend(_forged_seal_events(receipts))

    result = _anchored(events)
    assert not result.passed, (
        "FORGERY ACCEPTED: a party that anchors nothing fabricated a chain-valid "
        "seal set from plaintext trace content and the validator graded it PASS. "
        f"detail={result.detail!r}"
    )


def test_forged_seals_attributed_to_auditor_fail() -> None:
    """Same forgery with the seal events attributed to ``auditor-0`` must FAIL.

    Emitter attribution is not a root of trust either — nothing stops a
    participant-supplied plugin from emitting under the auditor's flow. Only
    an independent ledger's signature over the evidence counts.
    """
    receipts = _receipts()
    events = [_receipt_event(r) for r in receipts]
    events.append(_score_event())
    events.extend(_forged_seal_events(receipts, agent="auditor-0"))

    result = _anchored(events)
    assert not result.passed, (
        "FORGERY ACCEPTED: fabricated seals attributed to the auditor graded PASS. "
        f"detail={result.detail!r}"
    )


# ---------------------------------------------------------------------------
# Discrimination table against a LOCAL TEST-ONLY confidential ledger.
#
# The tests below mint real CCF-shaped write receipts with
# ``nest_mocks.ccf_ledger`` — a deterministic TEST SERVICE IDENTITY (not
# production) — and inject its identity into the validator explicitly. The
# pinned production constant stays None and is proven fail-closed below;
# nothing outside an explicit ``service_identity_pem=`` argument ever trusts
# the test identity.
# ---------------------------------------------------------------------------


def _ccf_event(digest: str, receipt: dict[str, Any], agent: str = "auditor-0") -> dict[str, Any]:
    return {
        "agent": agent,
        "kind": "broadcast",
        "msg": f"ccfreceipt:{digest}:{receipt_bytes(receipt).hex()}",
        "ts": 1.0,
    }


def _honest_trace(
    receipts: list[dict[str, Any]], ledger: LocalTestConfidentialLedger
) -> list[dict[str, Any]]:
    """Receipts + seals + ledger-minted write receipts — the honest anchoring run."""
    digests = [jcs_digest(r) for r in receipts]
    write_receipts = ledger.write_receipts([bytes.fromhex(d) for d in digests])
    events = [_receipt_event(r) for r in receipts]
    events.append(_score_event())
    events.extend(_forged_seal_events(receipts, agent="auditor-0"))  # honest chain, same bytes
    events.extend(_ccf_event(d, wr) for d, wr in zip(digests, write_receipts, strict=True))
    return events


def _anchored_with(events: list[dict[str, Any]], identity_pem: str) -> Any:
    results = validate_receipt_reputation_anchored(events, service_identity_pem=identity_pem)
    matched = [r for r in results if r.name == "receipt_reputation_anchored"]
    assert matched, "receipt_reputation_anchored validator returned no result"
    return matched[0]


def test_honest_anchoring_run_passes() -> None:
    """Receipts each bound by a ledger-signed write receipt -> PASS."""
    receipts = _receipts()
    ledger = LocalTestConfidentialLedger()
    result = _anchored_with(_honest_trace(receipts, ledger), ledger.service_identity_pem)
    assert result.passed, f"honest anchoring run must PASS: {result.detail}"
    assert "verified" in result.detail and "offline" in result.detail


def test_non_anchoring_baseline_fails() -> None:
    """No confidential-ledger write receipts on the trace -> FAIL (does not anchor)."""
    receipts = _receipts()
    ledger = LocalTestConfidentialLedger()
    events = [_receipt_event(r) for r in receipts]
    events.append(_score_event())
    result = _anchored_with(events, ledger.service_identity_pem)
    assert not result.passed
    assert "does not anchor" in result.detail


def test_forged_receipt_json_fails() -> None:
    """ccfreceipt lines fabricated from plaintext (no ledger signature) -> FAIL.

    A forger can compute every digest and every *unsigned* field — a binding
    application claim, self-consistent leaf components, a proof — but cannot
    produce the service identity's signature over the head, nor a node cert
    the pinned identity endorses.
    """
    receipts = _receipts()
    ledger = LocalTestConfidentialLedger()
    events = [_receipt_event(r) for r in receipts]
    events.append(_score_event())
    for r in receipts:
        digest = jcs_digest(r)
        claims: list[dict[str, Any]] = [
            {
                "kind": "LedgerEntry",
                "ledgerEntry": {
                    "collectionId": "subledger:0",
                    "contents": digest,
                    "protocol": "LedgerEntryV1",
                    "secretKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                },
            }
        ]
        forged: dict[str, Any] = {
            "receipt": {
                "cert": "-----BEGIN CERTIFICATE-----\nZm9yZ2Vk\n-----END CERTIFICATE-----\n",
                "leafComponents": {
                    "claimsDigest": compute_claims_digest(claims, bytes.fromhex(digest)).hex(),
                    "commitEvidence": "ce:2.0:forged",
                    "writeSetDigest": "00" * 32,
                },
                "nodeId": "00" * 32,
                "proof": [],
                "signature": "AAAA",
            },
            "applicationClaims": claims,
        }
        events.append(_ccf_event(digest, forged))
    result = _anchored_with(events, ledger.service_identity_pem)
    assert not result.passed
    assert "no confidential-ledger write receipt that verifies" in result.detail


def test_wrong_identity_minted_receipts_fail() -> None:
    """Write receipts minted under a DIFFERENT service identity -> FAIL."""
    receipts = _receipts()
    ledger = LocalTestConfidentialLedger()
    imposter = LocalTestConfidentialLedger(WRONG_SERVICE_LABEL)
    result = _anchored_with(_honest_trace(receipts, imposter), ledger.service_identity_pem)
    assert not result.passed, "evidence signed by a non-pinned identity must not verify"


def test_post_registration_tamper_fails() -> None:
    """A receipt mutated after ledger registration -> FAIL (digest never signed)."""
    receipts = _receipts()
    ledger = LocalTestConfidentialLedger()
    events = _honest_trace(receipts, ledger)

    # Mutate receipt r0 on the trace (freshly re-signed, so the issuer
    # signature is valid) while the write receipts still bind the originals.
    tampered: dict[str, Any] = {
        "receipt_id": "r0",
        "issuer_did": _did("issuer-a"),
        "action": {"category": "premium_purchase", "counterparty_did": _did("cp-a")},
    }
    tampered = sign_receipt(tampered, issuer_seed=_seed("issuer-a"))
    tampered = cosign_receipt(tampered, counterparty_seed=_seed("cp-a"))
    events = [
        _receipt_event(tampered)
        if str(ev.get("msg", "")).startswith("receipt:") and '"r0"' in str(ev.get("msg", ""))
        else ev
        for ev in events
    ]

    result = _anchored_with(events, ledger.service_identity_pem)
    assert not result.passed
    assert "no confidential-ledger write receipt that verifies" in result.detail


def test_partial_coverage_fails() -> None:
    """Anchoring is complete or it is nothing: one unbound receipt -> FAIL."""
    receipts = _receipts()
    ledger = LocalTestConfidentialLedger()
    events = _honest_trace(receipts, ledger)
    covered_digest = jcs_digest(receipts[0])
    events = [
        ev
        for ev in events
        if not str(ev.get("msg", "")).startswith(f"ccfreceipt:{covered_digest}:")
    ]
    result = _anchored_with(events, ledger.service_identity_pem)
    assert not result.passed
    assert "1/3" in result.detail


def test_test_ledger_evidence_fails_the_production_pin() -> None:
    """The registry path (pinned PRODUCTION identity) rejects test-ledger evidence.

    ``PINNED_ACL_SERVICE_IDENTITY_PEM`` is now the real Azure Confidential
    Ledger service identity. The LOCAL TEST-ONLY ledger's keys are publicly
    derivable, so its output must never satisfy the production gate — only
    receipts signed by the real ledger can.
    """
    assert PINNED_ACL_SERVICE_IDENTITY_PEM is not None, "production service identity must be pinned"
    receipts = _receipts()
    ledger = LocalTestConfidentialLedger()
    result = _anchored(_honest_trace(receipts, ledger))  # registry path: production pin
    assert not result.passed
    assert "no confidential-ledger write receipt that verifies" in result.detail


def test_verdict_is_deterministic_and_cwd_independent(tmp_path: Path) -> None:
    """Same events -> same verdict, from any cwd (archived-trace property)."""
    receipts = _receipts()
    ledger = LocalTestConfidentialLedger()
    events = _honest_trace(receipts, ledger)

    first = _anchored_with(events, ledger.service_identity_pem)
    old_cwd = os.getcwd()
    try:
        os.chdir(tmp_path)  # no ledger file, no fixtures, nothing here
        second = _anchored_with(events, ledger.service_identity_pem)
    finally:
        os.chdir(old_cwd)
    assert (first.passed, first.detail) == (second.passed, second.detail)
    assert first.passed
