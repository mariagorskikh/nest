# SPDX-License-Identifier: Apache-2.0
# pyright: reportPrivateUsage=false
"""Unit + hostile-path + property tests for the ``parc`` trust plugin.

The hostile paths mirror the sm-parc threat taxonomy: tampered credential,
untrusted issuer, replayed (stolen) credential, stale credential, stale
(rotated-out) signing key, oversized ledger, foreign receipts, tampered
ledger (root mismatch), issuer-inflated-and-re-signed score, below-threshold,
missing published ledger, and wash-ring severance over the published ledger.
Each asserts the *typed reason*, not just the denial — the reasons are the
plugin's contract with the trace validators.

Property tests (Hypothesis) assert the structural invariants:

1. Merkle root is permutation-invariant and tamper-sensitive.
2. Any single-nibble proof tamper is rejected as ``proof_invalid``.
3. Export -> admit round-trips for arbitrary honest ledgers.
4. Admission thresholding is exact: admitted iff recomputed score clears
   ``min_reputation_score``.
5. base58btc round-trips against an independent decoder.
6. Every leaf of every ledger yields an inclusion proof that verifies
   against ``merkle_root``; disclosure verification is tamper-sensitive
   (wrong receipt / sibling / root / leaf count / credential proof) and
   byte-deterministic.
"""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from hypothesis import given, settings
from hypothesis import strategies as st
from nest_core.types import AgentId, Evidence
from nest_plugins_reference.identity.ed25519_rotating import Ed25519RotatingIdentity
from nest_plugins_reference.trust.agent_receipts import (
    cosign_receipt,
    did_for_pubkey,
    sign_receipt,
)
from nest_plugins_reference.trust.parc import (
    _B58_ALPHABET,
    AdmissionPolicy,
    ParcTrust,
    _b58btc_encode,
    attach_proof,
    credential_payload,
    did_key_for_pubkey,
    inclusion_proof,
    merkle_root,
    verify_inclusion,
)

_ISSUER = AgentId("issuer-a")
_GATE = AgentId("gate-b")
_ROTATE_AT = 5.0
_ISSUE_AT = 6.0


def _seed(name: str) -> bytes:
    """The deterministic receipt seed for an agent name (plugin-matching)."""
    return hashlib.sha256(name.encode()).digest()[:32]


def _did(name: str) -> str:
    """The trust-layer receipt identity (hex pubkey) for an agent name."""
    sk = Ed25519PrivateKey.from_private_bytes(_seed(name))
    return did_for_pubkey(sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))


def _receipt(issuer: str, cp: str, *, rid: str, category: str = "purchase") -> dict[str, Any]:
    """A corroborated receipt from ``issuer`` about counterparty ``cp``."""
    r: dict[str, Any] = {
        "receipt_id": rid,
        "issuer_did": _did(issuer),
        "action": {"category": category, "counterparty_did": _did(cp)},
    }
    return cosign_receipt(sign_receipt(r, issuer_seed=_seed(issuer)), counterparty_seed=_seed(cp))


async def _trust_with(receipts: list[dict[str, Any]]) -> ParcTrust:
    """A ParcTrust whose ledger holds ``receipts`` (reported the normal way)."""
    trust = ParcTrust()
    for r in receipts:
        await trust.report(
            AgentId("reporter"),
            Evidence(
                reporter=AgentId("reporter"),
                subject=AgentId("reporter"),
                kind="positive",
                detail=json.dumps(r),
            ),
        )
    return trust


def _identities() -> tuple[Ed25519RotatingIdentity, Ed25519RotatingIdentity, str]:
    """(issuer identity, gate identity, issuer's pre-rotation key id).

    The gate learns the issuer's key #0, the issuer rotates at ``_ROTATE_AT``,
    and the gate applies the rotation record — the same wiring the scenario
    factory performs.
    """
    issuer = Ed25519RotatingIdentity(_ISSUER, seed=b"test:issuer-a")
    gate = Ed25519RotatingIdentity(_GATE, seed=b"test:gate-b")
    old_key_id = str(issuer.current_key_id)
    gate.register_peer(_ISSUER, issuer.public_key)
    issuer.set_clock(_ROTATE_AT)
    rotation = issuer.rotate_key(b"test:issuer-a:rotated")
    gate.set_clock(_ROTATE_AT)
    assert gate.apply_rotation(rotation)
    issuer.set_clock(_ISSUE_AT)
    return issuer, gate, old_key_id


def _policy(**overrides: Any) -> AdmissionPolicy:
    """The default test policy: trusts the test issuer, threshold 0.2."""
    defaults: dict[str, Any] = {
        "trusted_issuers": {f"did:nest:{_ISSUER}"},
        "min_reputation_score": 0.2,
    }
    defaults.update(overrides)
    return AdmissionPolicy(**defaults)


async def _admit(
    gate_trust: ParcTrust,
    vc: dict[str, Any],
    *,
    presenter: str = "alice",
    policy: AdmissionPolicy | None = None,
    current_tick: float = _ISSUE_AT,
) -> Any:
    """Admit ``vc`` at a fresh gate against the standard test wiring."""
    _, gate_ident, _ = _identities()
    return await gate_trust.admit(
        vc,
        policy=policy or _policy(),
        presenter_did=_did(presenter),
        identity=gate_ident,
        current_tick=current_tick,
    )


def _alice_receipts() -> list[dict[str, Any]]:
    """Two corroborated purchase receipts for alice (inline score ~0.63)."""
    return [
        _receipt("alice", "bob", rid="r1"),
        _receipt("alice", "carol", rid="r2"),
    ]


async def _alice_credential() -> tuple[dict[str, Any], ParcTrust]:
    """A genuine credential for alice plus the exporting trust instance."""
    trust = await _trust_with(_alice_receipts())
    issuer_ident, _, _ = _identities()
    vc = await trust.build_credential(AgentId("alice"), identity=issuer_ident, valid_from=_ISSUE_AT)
    return vc, trust


# ---------------------------------------------------------------------------
# did:key / base58btc
# ---------------------------------------------------------------------------


class TestDidKey:
    def test_ed25519_did_key_prefix(self) -> None:
        # Every multicodec-prefixed Ed25519 key encodes to did:key:z6Mk...
        issuer, _, _ = _identities()
        assert did_key_for_pubkey(issuer.public_key).startswith("did:key:z6Mk")

    def test_distinct_keys_distinct_dids(self) -> None:
        issuer, gate, _ = _identities()
        assert did_key_for_pubkey(issuer.public_key) != did_key_for_pubkey(gate.public_key)

    @given(st.binary(min_size=0, max_size=48))
    @settings(deadline=None)
    def test_b58btc_roundtrip(self, data: bytes) -> None:
        encoded = _b58btc_encode(data)
        # Independent decode: leading '1's are zero bytes, the rest is base-58.
        pad = len(encoded) - len(encoded.lstrip("1"))
        num = 0
        for char in encoded[pad:]:
            num = num * 58 + _B58_ALPHABET.index(char)
        body = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
        assert b"\x00" * pad + body == data


# ---------------------------------------------------------------------------
# Merkle root
# ---------------------------------------------------------------------------


class TestMerkleRoot:
    @given(st.permutations(list(range(5))))
    @settings(deadline=None)
    def test_permutation_invariant(self, order: list[int]) -> None:
        receipts = [_receipt("alice", "bob", rid=f"r{i}") for i in range(5)]
        shuffled = [receipts[i] for i in order]
        assert merkle_root(shuffled) == merkle_root(receipts)

    def test_tamper_changes_root(self) -> None:
        receipts = _alice_receipts()
        root = merkle_root(receipts)
        tampered = copy.deepcopy(receipts)
        tampered[0]["action"]["category"] = "payment_sent"
        assert merkle_root(tampered) != root

    def test_subset_changes_root(self) -> None:
        receipts = _alice_receipts()
        assert merkle_root(receipts[:1]) != merkle_root(receipts)

    def test_empty_ledger_root_is_defined(self) -> None:
        assert merkle_root([]) == hashlib.sha256(b"").hexdigest()


# ---------------------------------------------------------------------------
# Export -> admit round-trip
# ---------------------------------------------------------------------------


class TestRoundTrip:
    @pytest.mark.asyncio
    async def test_genuine_credential_admitted(self) -> None:
        vc, trust = await _alice_credential()
        result = await _admit(trust, vc)
        assert result.admitted is True
        assert result.reason == "admitted"
        assert result.recomputed_score == pytest.approx(
            float(vc["credentialSubject"]["reputation_score"]), abs=1e-6
        )

    @pytest.mark.asyncio
    async def test_credential_shape(self) -> None:
        vc, _ = await _alice_credential()
        assert vc["type"] == ["VerifiableCredential", "ParcReputationCredential"]
        assert vc["issuer"] == f"did:nest:{_ISSUER}"
        subject = vc["credentialSubject"]
        assert subject["id"] == _did("alice")
        assert subject["scoring_method"] == "nanda-rep/0.2"
        assert subject["receipt_count"] == 2
        assert subject["behavioral_merkle_root"] == merkle_root(subject["receipts"])
        assert vc["proof"]["type"] == "Ed25519Signature2020"
        assert vc["proof"]["verificationMethod"].startswith("did:key:z6Mk")

    @pytest.mark.asyncio
    async def test_credential_bytes_deterministic(self) -> None:
        vc1, _ = await _alice_credential()
        vc2, _ = await _alice_credential()
        assert credential_payload(vc1) == credential_payload(vc2)
        assert vc1["proof"] == vc2["proof"]

    @pytest.mark.asyncio
    async def test_empty_ledger_credential_scores_zero(self) -> None:
        trust = await _trust_with([])
        issuer_ident, _, _ = _identities()
        vc = await trust.build_credential(
            AgentId("nobody"), identity=issuer_ident, valid_from=_ISSUE_AT
        )
        assert vc["credentialSubject"]["reputation_score"] == "0.000000"
        result = await _admit(trust, vc, presenter="nobody")
        assert result.admitted is False
        assert result.reason == "below_threshold"


# ---------------------------------------------------------------------------
# Hostile paths — one typed reason each
# ---------------------------------------------------------------------------


class TestHostilePaths:
    @pytest.mark.asyncio
    async def test_schema_invalid(self) -> None:
        trust = ParcTrust()
        result = await _admit(trust, {"type": ["VerifiableCredential"]})
        assert (result.admitted, result.reason) == (False, "schema_invalid")

    @pytest.mark.asyncio
    async def test_wrong_scoring_method(self) -> None:
        vc, trust = await _alice_credential()
        vc = copy.deepcopy(vc)
        # An un-corroborated nanda-rep/0.1 facet must be rejected before any
        # recomputation, even though its proof is now broken anyway.
        vc["credentialSubject"]["scoring_method"] = "nanda-rep/0.1"
        result = await _admit(trust, vc)
        assert (result.admitted, result.reason) == (False, "wrong_scoring_method")

    @pytest.mark.asyncio
    async def test_untrusted_issuer(self) -> None:
        vc, trust = await _alice_credential()
        result = await _admit(trust, vc, policy=_policy(trusted_issuers={"did:nest:someone"}))
        assert (result.admitted, result.reason) == (False, "untrusted_issuer")

    @pytest.mark.asyncio
    async def test_replayed_credential_rejected(self) -> None:
        vc, trust = await _alice_credential()
        result = await _admit(trust, vc, presenter="mallory")
        assert (result.admitted, result.reason) == (False, "replay_presenter_mismatch")

    @pytest.mark.asyncio
    async def test_stale_credential_rejected(self) -> None:
        vc, trust = await _alice_credential()
        result = await _admit(
            trust, vc, policy=_policy(max_age_ticks=10.0), current_tick=_ISSUE_AT + 11.0
        )
        assert (result.admitted, result.reason) == (False, "stale_credential")

    @pytest.mark.asyncio
    async def test_tampered_proof_rejected(self) -> None:
        vc, trust = await _alice_credential()
        vc = copy.deepcopy(vc)
        value = vc["proof"]["proofValue"]
        vc["proof"]["proofValue"] = ("0" if value[0] != "0" else "f") + value[1:]
        result = await _admit(trust, vc)
        assert (result.admitted, result.reason) == (False, "proof_invalid")

    @pytest.mark.asyncio
    async def test_tampered_subject_breaks_proof(self) -> None:
        vc, trust = await _alice_credential()
        vc = copy.deepcopy(vc)
        # Tamper a signed field WITHOUT re-signing: the untouched (genuine)
        # proof no longer covers the canonical bytes.
        vc["credentialSubject"]["receipt_count"] = 99
        result = await _admit(trust, vc)
        assert (result.admitted, result.reason) == (False, "proof_invalid")

    @pytest.mark.asyncio
    async def test_unknown_key_id_rejected(self) -> None:
        vc, trust = await _alice_credential()
        vc = copy.deepcopy(vc)
        did_part, _, _ = vc["proof"]["verificationMethod"].partition("#")
        vc["proof"]["verificationMethod"] = f"{did_part}#{'0' * 64}"
        result = await _admit(trust, vc)
        assert (result.admitted, result.reason) == (False, "proof_invalid")

    @pytest.mark.asyncio
    async def test_stale_key_rejected(self) -> None:
        # Signed with the issuer's PRE-rotation key, validFrom after rotation:
        # cryptographically valid, but the key's window is [0, _ROTATE_AT).
        trust = await _trust_with(_alice_receipts())
        issuer_ident, _, old_key_id = _identities()
        vc = await trust.build_credential(
            AgentId("alice"), identity=issuer_ident, valid_from=_ISSUE_AT, key_id=old_key_id
        )
        result = await _admit(trust, vc)
        assert (result.admitted, result.reason) == (False, "stale_key")

    @pytest.mark.asyncio
    async def test_old_key_valid_within_its_window(self) -> None:
        # The same pre-rotation key IS acceptable for a credential anchored
        # inside its window — rotation must not retroactively void history.
        trust = await _trust_with(_alice_receipts())
        issuer_ident, _, old_key_id = _identities()
        vc = await trust.build_credential(
            AgentId("alice"), identity=issuer_ident, valid_from=1.0, key_id=old_key_id
        )
        result = await _admit(trust, vc)
        assert result.admitted is True

    @pytest.mark.asyncio
    async def test_ledger_too_large_rejected(self) -> None:
        vc, trust = await _alice_credential()
        result = await _admit(trust, vc, policy=_policy(max_ledger_receipts=1))
        assert (result.admitted, result.reason) == (False, "ledger_too_large")

    @pytest.mark.asyncio
    async def test_foreign_receipts_rejected(self) -> None:
        # Mallory pads her thin ledger with bob's genuine receipts and
        # recommits the root + scores, re-signed by a corrupt trusted issuer:
        # the subject-binding gate still rejects it.
        trust = await _trust_with([_receipt("mallory", "bob", rid="m1")])
        issuer_ident, _, _ = _identities()
        vc = await trust.build_credential(
            AgentId("mallory"), identity=issuer_ident, valid_from=_ISSUE_AT
        )
        vc.pop("proof")
        padded = [*vc["credentialSubject"]["receipts"], _receipt("bob", "carol", rid="b1")]
        vc["credentialSubject"]["receipts"] = padded
        vc["credentialSubject"]["behavioral_merkle_root"] = merkle_root(padded)
        vc = attach_proof(vc, identity=issuer_ident)
        result = await _admit(trust, vc, presenter="mallory")
        assert (result.admitted, result.reason) == (False, "foreign_receipts")

    @pytest.mark.asyncio
    async def test_root_mismatch_rejected(self) -> None:
        # A receipt vanishes from the carried ledger but the committed root
        # is left stale — re-signed so the proof itself verifies.
        vc, trust = await _alice_credential()
        issuer_ident, _, _ = _identities()
        vc = copy.deepcopy(vc)
        vc.pop("proof")
        vc["credentialSubject"]["receipts"] = vc["credentialSubject"]["receipts"][:1]
        vc = attach_proof(vc, identity=issuer_ident)
        result = await _admit(trust, vc)
        assert (result.admitted, result.reason) == (False, "root_mismatch")

    @pytest.mark.asyncio
    async def test_inflated_score_rejected_despite_valid_signature(self) -> None:
        # The headline property: a trusted issuer inflates the score and
        # genuinely re-signs. Proof verifies; recomputation catches the lie.
        vc, trust = await _alice_credential()
        issuer_ident, _, _ = _identities()
        vc = copy.deepcopy(vc)
        vc.pop("proof")
        vc["credentialSubject"]["reputation_score"] = "0.990000"
        vc = attach_proof(vc, identity=issuer_ident)
        result = await _admit(trust, vc)
        assert (result.admitted, result.reason) == (False, "score_mismatch")
        assert result.recomputed_score == pytest.approx(0.6321, abs=1e-3)

    @pytest.mark.asyncio
    async def test_naive_gate_admits_inflated_score(self) -> None:
        # The differential: with recomputation off, the same inflated
        # credential is admitted — which is exactly what the adversarial
        # validators punish.
        vc, trust = await _alice_credential()
        issuer_ident, _, _ = _identities()
        vc = copy.deepcopy(vc)
        vc.pop("proof")
        vc["credentialSubject"]["reputation_score"] = "0.990000"
        vc = attach_proof(vc, identity=issuer_ident)
        result = await _admit(trust, vc, policy=_policy(require_recomputation=False))
        assert result.admitted is True

    @pytest.mark.asyncio
    async def test_below_threshold_rejected(self) -> None:
        vc, trust = await _alice_credential()
        result = await _admit(trust, vc, policy=_policy(min_reputation_score=0.9))
        assert (result.admitted, result.reason) == (False, "below_threshold")

    @pytest.mark.asyncio
    async def test_published_ledger_missing_rejected(self) -> None:
        vc, _ = await _alice_credential()
        gate = ParcTrust()  # never ingested a published ledger
        _, gate_ident, _ = _identities()
        result = await gate.admit(
            vc,
            policy=_policy(require_published_ledger=True),
            presenter_did=_did("alice"),
            identity=gate_ident,
            current_tick=_ISSUE_AT,
        )
        assert (result.admitted, result.reason) == (False, "published_ledger_missing")

    @pytest.mark.asyncio
    async def test_ring_severed_over_published_ledger(self) -> None:
        # Each ring member's inline credential is individually corroborated
        # and survives recomputation; the published-ledger severance is what
        # denies it. Honest agents over the same published ledger stay
        # admitted.
        ring = ["r0", "r1", "r2"]
        honest = ["h0", "h1", "h2", "h3"]
        ledger: list[dict[str, Any]] = []
        for i, a in enumerate(honest):
            for k in (1, 2):
                ledger.append(_receipt(a, honest[(i + k) % len(honest)], rid=f"{a}-{k}"))
        for a in ring:
            for b in ring:
                if a != b:
                    ledger.append(_receipt(a, b, rid=f"{a}->{b}"))
        trust = await _trust_with(ledger)
        issuer_ident, _, _ = _identities()
        gate = ParcTrust()
        assert gate.ingest_published_ledger(ledger) == len(ledger)
        policy = _policy(require_published_ledger=True)
        _, gate_ident, _ = _identities()

        ring_vc = await trust.build_credential(
            AgentId("r0"), identity=issuer_ident, valid_from=_ISSUE_AT
        )
        result = await gate.admit(
            ring_vc,
            policy=policy,
            presenter_did=_did("r0"),
            identity=gate_ident,
            current_tick=_ISSUE_AT,
        )
        assert (result.admitted, result.reason) == (False, "severed_below_threshold")

        honest_vc = await trust.build_credential(
            AgentId("h0"), identity=issuer_ident, valid_from=_ISSUE_AT
        )
        result = await gate.admit(
            honest_vc,
            policy=policy,
            presenter_did=_did("h0"),
            identity=gate_ident,
            current_tick=_ISSUE_AT,
        )
        assert result.admitted is True

    def test_hostile_published_ledger_edges_dropped(self) -> None:
        gate = ParcTrust()
        forged = {"receipt_id": "x", "issuer_did": _did("a"), "signature": "00" * 64}
        assert gate.ingest_published_ledger([forged]) == 0


# ---------------------------------------------------------------------------
# Properties
# ---------------------------------------------------------------------------


class TestProperties:
    @given(st.integers(min_value=0, max_value=127))
    @settings(deadline=None, max_examples=30)
    def test_any_proof_nibble_tamper_rejected(self, position: int) -> None:
        import asyncio

        async def run() -> None:
            vc, trust = await _alice_credential()
            vc2 = copy.deepcopy(vc)
            value = vc2["proof"]["proofValue"]
            index = position % len(value)
            original = value[index]
            replacement = "0" if original != "0" else "f"
            vc2["proof"]["proofValue"] = value[:index] + replacement + value[index + 1 :]
            result = await _admit(trust, vc2)
            assert result.admitted is False
            assert result.reason == "proof_invalid"

        asyncio.run(run())

    @given(st.integers(min_value=1, max_value=5), st.integers(min_value=0, max_value=100))
    @settings(deadline=None, max_examples=25)
    def test_export_admit_roundtrip_and_exact_threshold(
        self, receipt_count: int, threshold_pct: int
    ) -> None:
        import asyncio

        async def run() -> None:
            receipts = [_receipt("alice", f"cp{i}", rid=f"r{i}") for i in range(receipt_count)]
            trust = await _trust_with(receipts)
            issuer_ident, _, _ = _identities()
            vc = await trust.build_credential(
                AgentId("alice"), identity=issuer_ident, valid_from=_ISSUE_AT
            )
            threshold = threshold_pct / 100.0
            result = await _admit(trust, vc, policy=_policy(min_reputation_score=threshold))
            score = float(vc["credentialSubject"]["reputation_score"])
            if result.admitted:
                assert score >= threshold - 1e-9
                assert result.reason == "admitted"
            else:
                assert result.reason == "below_threshold"
                assert score < threshold

        asyncio.run(run())


# ---------------------------------------------------------------------------
# Selective disclosure — inclusion proofs
# ---------------------------------------------------------------------------


def _ledger(count: int, *, issuer: str = "alice") -> list[dict[str, Any]]:
    """``count`` deterministic corroborated receipts issued by ``issuer``."""
    return [_receipt(issuer, f"cp{i}", rid=f"r{i:02d}") for i in range(count)]


class TestInclusionProofs:
    def test_round_trip_all_sizes(self) -> None:
        # Every leaf of 1-, 2-, 3- (odd duplication), 8- and 50-leaf trees
        # proves and verifies against the plugin's own merkle_root.
        for count in (1, 2, 3, 8, 50):
            receipts = _ledger(count)
            root = merkle_root(receipts)
            for r in receipts:
                proof = inclusion_proof(receipts, receipt=r)
                assert proof["leaf_count"] == count
                assert verify_inclusion(r, proof, root)

    @given(st.integers(min_value=1, max_value=10))
    @settings(deadline=None, max_examples=15)
    def test_every_leaf_proves_membership(self, count: int) -> None:
        receipts = _ledger(count)
        root = merkle_root(receipts)
        for r in receipts:
            assert verify_inclusion(r, inclusion_proof(receipts, receipt=r), root)

    def test_single_receipt_path_is_empty(self) -> None:
        # A one-leaf tree IS its root: the authentication path has no steps.
        receipts = _ledger(1)
        proof = inclusion_proof(receipts, receipt=receipts[0])
        assert proof == {"leaf_index": 0, "leaf_count": 1, "path": []}
        assert (
            merkle_root(receipts)
            == hashlib.sha256(
                json.dumps(receipts[0], sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
        )

    def test_absent_receipt_raises(self) -> None:
        receipts = _ledger(3)
        stranger = _receipt("alice", "zed", rid="zz")
        with pytest.raises(ValueError, match="not present"):
            inclusion_proof(receipts, receipt=stranger)

    def test_tampered_receipt_rejected(self) -> None:
        receipts = _ledger(4)
        root = merkle_root(receipts)
        proof = inclusion_proof(receipts, receipt=receipts[0])
        tampered = copy.deepcopy(receipts[0])
        tampered["action"]["category"] = "payment_sent"
        assert not verify_inclusion(tampered, proof, root)

    def test_tampered_sibling_rejected(self) -> None:
        receipts = _ledger(4)
        root = merkle_root(receipts)
        proof = copy.deepcopy(inclusion_proof(receipts, receipt=receipts[0]))
        sibling = proof["path"][0]["sibling"]
        proof["path"][0]["sibling"] = ("0" if sibling[0] != "0" else "f") + sibling[1:]
        assert not verify_inclusion(receipts[0], proof, root)

    def test_wrong_root_rejected(self) -> None:
        receipts = _ledger(4)
        proof = inclusion_proof(receipts, receipt=receipts[0])
        assert not verify_inclusion(receipts[0], proof, merkle_root(receipts[:3]))

    def test_malformed_proof_rejected(self) -> None:
        receipts = _ledger(2)
        root = merkle_root(receipts)
        assert not verify_inclusion(receipts[0], {}, root)
        assert not verify_inclusion(receipts[0], {"path": [{"sibling": 7}]}, root)
        assert not verify_inclusion(
            receipts[0], {"path": [{"sibling": "ab", "position": "up"}]}, root
        )

    def test_proof_deterministic(self) -> None:
        # Two independent builds of the same ledger produce byte-identical
        # proofs — the disclosure surface inherits the plugin's determinism.
        one = inclusion_proof(_ledger(7), receipt=_ledger(7)[3])
        two = inclusion_proof(_ledger(7), receipt=_ledger(7)[3])
        assert json.dumps(one, sort_keys=True) == json.dumps(two, sort_keys=True)


# ---------------------------------------------------------------------------
# Selective disclosure — presentations
# ---------------------------------------------------------------------------


async def _presentation(
    count: int = 20, disclose: tuple[str, ...] = ("r03", "r07", "r11")
) -> tuple[dict[str, Any], ParcTrust, list[dict[str, Any]]]:
    """A genuine presentation over a ``count``-receipt ledger + its trust."""
    receipts = _ledger(count)
    trust = await _trust_with(receipts)
    issuer_ident, _, _ = _identities()
    vc = await trust.build_credential(AgentId("alice"), identity=issuer_ident, valid_from=_ISSUE_AT)
    return trust.build_presentation(vc, receipts, disclose=disclose), trust, receipts


async def _verify_pres(trust: ParcTrust, presentation: dict[str, Any], **kwargs: Any) -> Any:
    """Verify ``presentation`` against the standard gate identity wiring."""
    _, gate_ident, _ = _identities()
    return await trust.verify_presentation(presentation, identity=gate_ident, **kwargs)


class TestPresentation:
    @pytest.mark.asyncio
    async def test_round_trip_ok(self) -> None:
        pres, trust, _ = await _presentation()
        assert [e["receipt"]["receipt_id"] for e in pres["disclosed"]] == ["r03", "r07", "r11"]
        assert all(e["proof"]["leaf_count"] == 20 for e in pres["disclosed"])
        result = await _verify_pres(trust, pres)
        assert (result.ok, result.reasons) == (True, ())

    @pytest.mark.asyncio
    async def test_expected_issuer_enforced(self) -> None:
        pres, trust, _ = await _presentation()
        ok = await _verify_pres(trust, pres, expected_issuer=f"did:nest:{_ISSUER}")
        assert ok.ok is True
        bad = await _verify_pres(trust, pres, expected_issuer="did:nest:someone")
        assert (bad.ok, bad.reasons) == (False, ("issuer_mismatch",))

    @pytest.mark.asyncio
    async def test_tampered_disclosed_receipt_not_included(self) -> None:
        pres, trust, _ = await _presentation()
        pres = copy.deepcopy(pres)
        pres["disclosed"][0]["receipt"]["action"]["category"] = "payment_sent"
        result = await _verify_pres(trust, pres)
        assert (result.ok, result.reasons) == (False, ("not_included",))

    @pytest.mark.asyncio
    async def test_receipt_from_different_ledger_not_included(self) -> None:
        # Mallory splices a receipt (plus a genuine proof) from her OWN
        # 20-receipt ledger into alice's presentation: leaf_count matches the
        # signed receipt_count, but the leaf folds to mallory's root.
        pres, trust, _ = await _presentation()
        other = _ledger(20, issuer="mallory")
        pres = copy.deepcopy(pres)
        pres["disclosed"][0] = {
            "receipt": other[0],
            "proof": inclusion_proof(other, receipt=other[0]),
        }
        result = await _verify_pres(trust, pres)
        assert (result.ok, result.reasons) == (False, ("not_included",))

    @pytest.mark.asyncio
    async def test_leaf_count_lie_count_mismatch(self) -> None:
        # The path still folds to the root; only the claimed scope bound lies.
        pres, trust, _ = await _presentation()
        pres = copy.deepcopy(pres)
        pres["disclosed"][1]["proof"]["leaf_count"] = 3
        result = await _verify_pres(trust, pres)
        assert (result.ok, result.reasons) == (False, ("count_mismatch",))

    @pytest.mark.asyncio
    async def test_forged_credential_proof_rejected(self) -> None:
        pres, trust, _ = await _presentation()
        pres = copy.deepcopy(pres)
        value = pres["credential"]["proof"]["proofValue"]
        pres["credential"]["proof"]["proofValue"] = ("0" if value[0] != "0" else "f") + value[1:]
        result = await _verify_pres(trust, pres)
        assert (result.ok, result.reasons) == (False, ("bad_credential_proof",))
        assert result.detail == "proof_invalid"

    @pytest.mark.asyncio
    async def test_inflated_resigned_stale_key_fails_like_admit(self) -> None:
        # An issuer inflates the score and genuinely re-signs — with a
        # rotated-out key. admit() rejects it as stale_key; the disclosure
        # path rejects the SAME credential as bad_credential_proof, carrying
        # the same underlying reason. No score is recomputed on either path.
        receipts = _ledger(20)
        trust = await _trust_with(receipts)
        issuer_ident, _, old_key_id = _identities()
        vc = await trust.build_credential(
            AgentId("alice"), identity=issuer_ident, valid_from=_ISSUE_AT
        )
        vc.pop("proof")
        vc["credentialSubject"]["reputation_score"] = "0.990000"
        vc = attach_proof(vc, identity=issuer_ident, key_id=old_key_id)

        admit_result = await _admit(trust, vc)
        assert (admit_result.admitted, admit_result.reason) == (False, "stale_key")

        pres = trust.build_presentation(vc, receipts, disclose=("r00",))
        result = await _verify_pres(trust, pres)
        assert (result.ok, result.reasons) == (False, ("bad_credential_proof",))
        assert result.detail == "stale_key"

    @pytest.mark.asyncio
    async def test_malformed_disclosed_proof(self) -> None:
        pres, trust, _ = await _presentation()
        pres = copy.deepcopy(pres)
        del pres["disclosed"][0]["proof"]["leaf_count"]
        result = await _verify_pres(trust, pres)
        assert (result.ok, result.reasons) == (False, ("malformed_proof",))

    @pytest.mark.asyncio
    async def test_malformed_presentation(self) -> None:
        trust = ParcTrust()
        result = await _verify_pres(trust, {})
        assert (result.ok, result.reasons) == (False, ("malformed_presentation",))
        result = await _verify_pres(trust, {"credential": {"type": []}, "disclosed": []})
        assert (result.ok, result.reasons) == (False, ("malformed_presentation",))

    @pytest.mark.asyncio
    async def test_unknown_disclose_id_raises(self) -> None:
        pres, trust, receipts = await _presentation()
        with pytest.raises(ValueError, match="not present"):
            trust.build_presentation(pres["credential"], receipts, disclose=("nope",))

    @pytest.mark.asyncio
    async def test_presentation_deterministic(self) -> None:
        pres1, _, _ = await _presentation()
        pres2, _, _ = await _presentation()
        assert json.dumps(pres1, sort_keys=True) == json.dumps(pres2, sort_keys=True)
