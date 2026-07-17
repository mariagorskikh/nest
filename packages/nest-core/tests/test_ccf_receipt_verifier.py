# SPDX-License-Identifier: Apache-2.0
"""Fail-closed unit tests for the vendored ACL write-receipt verifier.

``verify_ccf_write_receipt`` must return ``False`` — never raise, never
default open — for every malformed, truncated, mutated, or mis-keyed input,
and ``True`` only for evidence whose application claim binds the statement
and whose claims digest, inclusion proof, endorsement, ``nodeId``, and
service-identity signature all check out.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from typing import Any, cast

from nest_core.ccf_receipt import (
    PINNED_ACL_SERVICE_IDENTITY_PEM,
    verify_ccf_write_receipt,
)
from nest_mocks.ccf_ledger import (
    WRONG_SERVICE_LABEL,
    LocalTestConfidentialLedger,
    receipt_bytes,
)

_LEDGER = LocalTestConfidentialLedger()
_CLAIMS = [f"claim-{i}".encode() for i in range(5)]
_RECEIPTS = _LEDGER.write_receipts(_CLAIMS)
_PEM = _LEDGER.service_identity_pem


def _clone(evidence: dict[str, Any]) -> dict[str, Any]:
    return json.loads(receipt_bytes(evidence).decode("utf-8"))


def test_honest_receipts_verify_and_bind_their_claim() -> None:
    for wr, claim in zip(_RECEIPTS, _CLAIMS, strict=True):
        assert verify_ccf_write_receipt(wr, claim, _PEM)
    # Receipt for claim 0 must not verify claim 1 (binding).
    assert not verify_ccf_write_receipt(_RECEIPTS[0], _CLAIMS[1], _PEM)


def test_tree_shapes_from_one_to_nine_leaves() -> None:
    """Odd/even/promoted-leaf tree shapes all produce verifying proofs."""
    for n in range(1, 10):
        claims = [f"n{n}-c{i}".encode() for i in range(n)]
        receipts = _LEDGER.write_receipts(claims)
        for wr, claim in zip(receipts, claims, strict=True):
            assert verify_ccf_write_receipt(wr, claim, _PEM), f"n={n} claim={claim!r}"


def test_wrong_identity_rejected_both_directions() -> None:
    imposter = LocalTestConfidentialLedger(WRONG_SERVICE_LABEL)
    assert not verify_ccf_write_receipt(_RECEIPTS[0], _CLAIMS[0], imposter.service_identity_pem)
    forged = imposter.write_receipts(_CLAIMS)
    assert not verify_ccf_write_receipt(forged[0], _CLAIMS[0], _PEM)


def test_test_ledger_evidence_rejected_by_production_pin() -> None:
    """The LOCAL TEST-ONLY ledger's output is not evidence under the real pin.

    The production constant is the real ACL service identity; the test
    ledger's deterministic, publicly-derivable identity must never satisfy it.
    """
    assert PINNED_ACL_SERVICE_IDENTITY_PEM is not None
    for wr, claim in zip(_RECEIPTS, _CLAIMS, strict=True):
        assert not verify_ccf_write_receipt(wr, claim, PINNED_ACL_SERVICE_IDENTITY_PEM)


def test_unendorsed_self_made_cert_rejected() -> None:
    """A receipt whose node cert the pinned identity never issued must fail."""
    rogue = LocalTestConfidentialLedger(WRONG_SERVICE_LABEL)
    forged = rogue.write_receipts(_CLAIMS)[0]
    # Correct claim + leaf components for the statement, but the cert chain
    # dies at the pinned identity: rogue's node cert is not issued by it.
    honest = _clone(_RECEIPTS[0])
    forged["applicationClaims"] = honest["applicationClaims"]
    forged["receipt"]["leafComponents"] = honest["receipt"]["leafComponents"]
    assert not verify_ccf_write_receipt(forged, _CLAIMS[0], _PEM)


def _set_receipt(evidence: dict[str, Any], key: str, value: Any) -> None:
    cast("dict[str, Any]", evidence["receipt"])[key] = value


def _drop_receipt(evidence: dict[str, Any], key: str) -> None:
    cast("dict[str, Any]", evidence["receipt"]).pop(key)


def _set_leaf(evidence: dict[str, Any], key: str, value: Any) -> None:
    cast("dict[str, Any]", cast("dict[str, Any]", evidence["receipt"])["leafComponents"])[key] = (
        value
    )


def _set_entry(evidence: dict[str, Any], key: str, value: Any) -> None:
    claims = cast("list[dict[str, Any]]", evidence["applicationClaims"])
    cast("dict[str, Any]", claims[0]["ledgerEntry"])[key] = value


def test_every_field_mutation_is_rejected() -> None:
    """Any single-field tamper on valid evidence must fail verification."""
    wr, claim = _RECEIPTS[2], _CLAIMS[2]
    truncated_proof = cast("list[Any]", _clone(wr)["receipt"]["proof"])[:-1]

    mutations: list[tuple[str, Callable[[dict[str, Any]], None]]] = [
        ("garbage signature", lambda e: _set_receipt(e, "signature", "AAAA")),
        ("non-base64 signature", lambda e: _set_receipt(e, "signature", "not base64!")),
        ("null signature", lambda e: _set_receipt(e, "signature", None)),
        ("missing signature", lambda e: _drop_receipt(e, "signature")),
        ("garbage cert", lambda e: _set_receipt(e, "cert", "not a pem")),
        ("missing cert", lambda e: _drop_receipt(e, "cert")),
        ("wrong nodeId", lambda e: _set_receipt(e, "nodeId", "00" * 32)),
        ("endorsement chain smuggled", lambda e: _set_receipt(e, "serviceEndorsements", ["x"])),
        ("empty proof", lambda e: _set_receipt(e, "proof", [])),
        ("truncated proof", lambda e: _set_receipt(e, "proof", truncated_proof)),
        ("non-hex proof step", lambda e: _set_receipt(e, "proof", [{"left": "zz"}])),
        ("unknown proof side", lambda e: _set_receipt(e, "proof", [{"up": "00" * 32}])),
        (
            "two-sided proof step",
            lambda e: _set_receipt(e, "proof", [{"left": "00" * 32, "right": "00" * 32}]),
        ),
        ("missing proof", lambda e: _drop_receipt(e, "proof")),
        ("claims digest swap", lambda e: _set_leaf(e, "claimsDigest", "00" * 32)),
        ("write-set digest swap", lambda e: _set_leaf(e, "writeSetDigest", "00" * 32)),
        ("commit evidence swap", lambda e: _set_leaf(e, "commitEvidence", "ce:tampered")),
        ("empty commit evidence", lambda e: _set_leaf(e, "commitEvidence", "")),
        ("missing leaf components", lambda e: _drop_receipt(e, "leafComponents")),
        ("claim contents swap", lambda e: _set_entry(e, "contents", "ff" * 32)),
        (
            "claim secret swap",
            lambda e: _set_entry(e, "secretKey", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
        ),
        ("claim collection swap", lambda e: _set_entry(e, "collectionId", "subledger:1")),
        ("claim protocol swap", lambda e: _set_entry(e, "protocol", "LedgerEntryV2")),
        ("claims dropped", lambda e: e.__setitem__("applicationClaims", [])),
        (
            "claims doubled",
            lambda e: e.__setitem__(
                "applicationClaims",
                cast("list[Any]", e["applicationClaims"]) * 2,
            ),
        ),
    ]
    for label, mutate in mutations:
        mutated = _clone(wr)
        mutate(mutated)
        assert not verify_ccf_write_receipt(mutated, claim, _PEM), f"survived: {label}"


def test_proof_step_swap_rejected() -> None:
    """Swapping a proof step's side (left<->right) must break the fold."""
    wr, claim = _RECEIPTS[0], _CLAIMS[0]
    mutated = _clone(wr)
    proof = cast("list[dict[str, str]]", mutated["receipt"]["proof"])
    assert proof, "expected a non-trivial proof for a 5-leaf tree"
    ((side, value),) = proof[0].items()
    proof[0] = {("right" if side == "left" else "left"): value}
    assert not verify_ccf_write_receipt(mutated, claim, _PEM)


def test_garbage_shapes_never_raise() -> None:
    garbage_shapes: list[dict[str, Any]] = [
        {},
        {"receipt": None, "applicationClaims": None},
        {"receipt": 5, "applicationClaims": "x"},
        {"receipt": {}, "applicationClaims": []},
        {
            "receipt": {"cert": _PEM, "leafComponents": [], "proof": "x", "signature": 9},
            "applicationClaims": [{"kind": "ClaimDigest"}],
        },
        {
            "receipt": {"leafComponents": {"claimsDigest": hashlib.sha256(b"x").hexdigest()}},
            "applicationClaims": [{"kind": "LedgerEntry", "ledgerEntry": {}}],
        },
    ]
    for garbage in garbage_shapes:
        assert not verify_ccf_write_receipt(garbage, _CLAIMS[0], _PEM)


def test_empty_batch_rejected_by_ledger() -> None:
    try:
        _LEDGER.write_receipts([])
    except ValueError:
        return
    raise AssertionError("empty batch must raise")


def test_committed_production_fixtures_verify_against_pinned_identity() -> None:
    """Every committed fixture verifies offline against the pinned production pin.

    This is the fixture-integrity gate: it reads the committed fixtures (a
    TEST-side filesystem read — the validator itself still only sees trace
    events) and proves each one is real ledger-signed evidence for exactly
    the digest its filename claims.
    """
    from nest_plugins_reference.trust.capsule_emit import load_committed_ccf_receipts

    assert PINNED_ACL_SERVICE_IDENTITY_PEM is not None
    store = load_committed_ccf_receipts()
    assert len(store) > 0, "production fixtures must be committed"
    for digest, blob in store.items():
        evidence = json.loads(blob.decode("utf-8"))
        assert verify_ccf_write_receipt(
            evidence, bytes.fromhex(digest), PINNED_ACL_SERVICE_IDENTITY_PEM
        ), f"committed fixture {digest[:16]}… does not verify"
        # And it must NOT verify for any other digest (binding is per-statement).
        assert not verify_ccf_write_receipt(
            evidence, bytes.fromhex("00" * 32), PINNED_ACL_SERVICE_IDENTITY_PEM
        )
