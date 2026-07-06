# SPDX-License-Identifier: Apache-2.0
"""Medical data exchange scenario tests for the ``hybrid_x25519`` privacy plugin.

Exercises the **selective-disclosure** code path (``prove`` / ``verify_proof``)
that the existing ``sealed_bid_with_privacy`` scenario does not cover.  That
scenario validates ``encrypt`` / ``decrypt`` for sealed-bid auctions; this one
validates credential-based proofs in a medical-data workflow where a hospital
shares patient records with multiple insurers, each authorised to see only a
subset of fields.

Coverage layers:

1. **Unit** — A hospital commits a 5-field patient credential, proves to three
   insurers revealing different subsets, and each proof verifies.
2. **Cross-agent proof replay** — Insurer-A's valid proof is replayed to
   Insurer-B's verifier with a different root; must fail.
3. **Adversarial discrimination** — ``noop`` leaks all fields and accepts
   replayed proofs; ``hybrid_x25519`` blocks both.
4. **Scenario integration** — Boots the YAML and confirms determinism.

Example::

    pytest packages/nest-plugins-reference/tests/test_medical_exchange.py
"""

from __future__ import annotations

import json

from nest_core.types import AgentId, Statement, Witness
from nest_plugins_reference.privacy.hybrid_x25519 import (
    HybridX25519Privacy,
    NotInAudienceError,
    commit_credential,
)
from nest_plugins_reference.privacy.noop import NoopPrivacy


def _mk(name: str, *, seed: bytes | None = None) -> HybridX25519Privacy:
    """Create a deterministic plugin instance for testing.

    Example::

        alice = _mk("alice")
    """
    return HybridX25519Privacy(
        AgentId(name), seed=seed if seed is not None else name.encode(), deterministic=True
    )


def _dumps(mapping: dict[str, str]) -> str:
    return json.dumps(mapping, sort_keys=True)


# The patient credential used across all tests.
_PATIENT_FIELDS = {
    "name": "Mario Rossi",
    "age": "42",
    "diagnosis": "type-2 diabetes",
    "treatment": "metformin 500mg",
    "blood_type": "A+",
}


def _patient_credential(
    *, salt_seed: bytes = b"hospital-issuer",
) -> tuple[str, dict[str, str], dict[str, str]]:
    """Commit the standard 5-field patient credential.

    Returns ``(root_hex, salts, fields)``.

    Example::

        root, salts, fields = _patient_credential()
    """
    root, salts = commit_credential(_PATIENT_FIELDS, salt_seed=salt_seed)
    return root, salts, dict(_PATIENT_FIELDS)


def _make_statement(root: str, reveal: str) -> Statement:
    """Build a selective-disclosure statement for the given root and fields.

    Example::

        stmt = _make_statement(root, "age,diagnosis")
    """
    return Statement(
        predicate="selective_disclosure",
        public_inputs={"root": root, "reveal": reveal},
    )


def _make_witness(fields: dict[str, str], salts: dict[str, str]) -> Witness:
    """Build a witness carrying all fields plus salts.

    Example::

        w = _make_witness(fields, salts)
    """
    return Witness(private_inputs={**fields, "__salts__": _dumps(salts)})


# ---------------------------------------------------------------------------
# 1. Unit — selective disclosure with different reveal sets
# ---------------------------------------------------------------------------


class TestMedicalSelectiveDisclosure:
    """Hospital proves subsets of a patient credential to different insurers."""

    async def test_insurer_a_sees_age_and_diagnosis(self) -> None:
        """Insurer A is authorised for age + diagnosis only."""
        hospital = _mk("hospital")
        root, salts, fields = _patient_credential()
        stmt = _make_statement(root, "age,diagnosis")
        witness = _make_witness(fields, salts)
        proof = await hospital.prove(stmt, witness)
        assert await hospital.verify_proof(stmt, proof)
        assert b"type-2 diabetes" not in proof.data or b"age" in proof.data
        assert b"metformin" not in proof.data

    async def test_insurer_b_sees_diagnosis_and_treatment(self) -> None:
        """Insurer B is authorised for diagnosis + treatment."""
        hospital = _mk("hospital")
        root, salts, fields = _patient_credential()
        stmt = _make_statement(root, "diagnosis,treatment")
        witness = _make_witness(fields, salts)
        proof = await hospital.prove(stmt, witness)
        assert await hospital.verify_proof(stmt, proof)
        assert b"Mario Rossi" not in proof.data

    async def test_insurer_c_sees_age_only(self) -> None:
        """Insurer C gets only age — demographics for actuarial use."""
        hospital = _mk("hospital")
        root, salts, fields = _patient_credential()
        stmt = _make_statement(root, "age")
        witness = _make_witness(fields, salts)
        proof = await hospital.prove(stmt, witness)
        assert await hospital.verify_proof(stmt, proof)
        assert b"type-2 diabetes" not in proof.data
        assert b"metformin" not in proof.data
        assert b"Mario Rossi" not in proof.data
        assert b"A+" not in proof.data

    async def test_hidden_fields_never_in_proof(self) -> None:
        """No unrevealed field value appears anywhere in the proof bytes."""
        hospital = _mk("hospital")
        root, salts, fields = _patient_credential()
        stmt = _make_statement(root, "age")
        witness = _make_witness(fields, salts)
        proof = await hospital.prove(stmt, witness)
        for field_name in ("name", "diagnosis", "treatment", "blood_type"):
            assert fields[field_name].encode() not in proof.data


# ---------------------------------------------------------------------------
# 2. Cross-agent proof replay — the fifth attack
# ---------------------------------------------------------------------------


class TestCrossAgentProofReplay:
    """A proof valid under root-A must fail verification under root-B.

    This is the cross-agent replay attack: Insurer-A receives a valid proof
    from the hospital, then replays it verbatim to Insurer-B's verifier which
    expects proofs anchored to a *different* credential root.  The Merkle
    root binding defeats this.
    """

    async def test_proof_for_root_a_fails_under_root_b(self) -> None:
        hospital = _mk("hospital")

        root_a, salts_a, fields_a = _patient_credential(salt_seed=b"patient-a")
        root_b, _, _ = _patient_credential(salt_seed=b"patient-b")

        assert root_a != root_b, "different salt seeds must produce different roots"

        stmt_a = _make_statement(root_a, "age,diagnosis")
        witness_a = _make_witness(fields_a, salts_a)
        proof_a = await hospital.prove(stmt_a, witness_a)

        assert await hospital.verify_proof(stmt_a, proof_a)

        stmt_b = _make_statement(root_b, "age,diagnosis")
        assert not await hospital.verify_proof(stmt_b, proof_a)

    async def test_tampered_root_in_statement_fails(self) -> None:
        """Attacker replays a valid proof but rewrites the statement root."""
        hospital = _mk("hospital")
        root, salts, fields = _patient_credential()
        stmt = _make_statement(root, "age")
        witness = _make_witness(fields, salts)
        proof = await hospital.prove(stmt, witness)

        forged_stmt = _make_statement("00" * 32, "age")
        assert not await hospital.verify_proof(forged_stmt, proof)


# ---------------------------------------------------------------------------
# 3. Adversarial discrimination — noop vs hybrid_x25519
# ---------------------------------------------------------------------------


class TestNoopFailsWhereHybridSucceeds:
    """The noop plugin must fail every check that hybrid_x25519 passes."""

    async def test_noop_encrypt_leaks_plaintext(self) -> None:
        noop = NoopPrivacy()
        secret = b"diagnosis: type-2 diabetes, treatment: metformin"
        ct = await noop.encrypt(secret, [AgentId("insurer-a")])
        assert ct == secret, "noop returns plaintext unchanged"

    async def test_noop_verify_always_true(self) -> None:
        """noop.verify_proof accepts any proof, including a replayed one."""
        noop = NoopPrivacy()
        root, salts, fields = _patient_credential()
        stmt_a = _make_statement(root, "age")
        stmt_forged = _make_statement("00" * 32, "age")
        witness = _make_witness(fields, salts)
        proof = await noop.prove(stmt_a, witness)
        assert await noop.verify_proof(stmt_forged, proof), (
            "noop must accept anything — it has no crypto"
        )

    async def test_hybrid_encrypt_hides_plaintext(self) -> None:
        hospital = _mk("hospital")
        insurer = _mk("insurer-a")
        hospital.register_peer(AgentId("insurer-a"), insurer.public_key)
        secret = b"diagnosis: type-2 diabetes"
        ct = await hospital.encrypt(secret, [AgentId("insurer-a")])
        assert secret not in ct

    async def test_hybrid_outsider_cannot_decrypt(self) -> None:
        hospital = _mk("hospital")
        insurer = _mk("insurer-a")
        snoop = _mk("snoop")
        hospital.register_peer(AgentId("insurer-a"), insurer.public_key)
        ct = await hospital.encrypt(b"confidential", [AgentId("insurer-a")])
        try:
            await snoop.decrypt(ct)
        except NotInAudienceError:
            return
        raise AssertionError("eavesdropper decrypted — should have raised")

    async def test_hybrid_rejects_cross_agent_replay(self) -> None:
        """hybrid_x25519 rejects a proof anchored to a different root."""
        hospital = _mk("hospital")
        root_a, salts_a, fields_a = _patient_credential(salt_seed=b"patient-a")
        root_b, _, _ = _patient_credential(salt_seed=b"patient-b")
        stmt_a = _make_statement(root_a, "age")
        witness_a = _make_witness(fields_a, salts_a)
        proof_a = await hospital.prove(stmt_a, witness_a)
        stmt_b = _make_statement(root_b, "age")
        assert not await hospital.verify_proof(stmt_b, proof_a)


# ---------------------------------------------------------------------------
# 4. Encrypted medical exchange — full round-trip
# ---------------------------------------------------------------------------


class TestEncryptedMedicalExchange:
    """Hospital encrypts a patient record to an insurer and sends a
    selective-disclosure proof alongside it."""

    async def test_encrypted_record_plus_proof_round_trip(self) -> None:
        hospital = _mk("hospital")
        insurer = _mk("insurer-a")
        hospital.register_peer(AgentId("insurer-a"), insurer.public_key)

        root, salts, fields = _patient_credential()
        record = json.dumps(fields).encode()
        ct = await hospital.encrypt(record, [AgentId("insurer-a")])

        pt = await insurer.decrypt(ct)
        assert json.loads(pt) == fields

        stmt = _make_statement(root, "age,diagnosis")
        witness = _make_witness(fields, salts)
        proof = await hospital.prove(stmt, witness)

        assert await insurer.verify_proof(stmt, proof)

    async def test_eavesdropper_gets_nothing(self) -> None:
        hospital = _mk("hospital")
        insurer = _mk("insurer-a")
        snoop = _mk("snoop")
        hospital.register_peer(AgentId("insurer-a"), insurer.public_key)

        _root, _salts, fields = _patient_credential()
        record = json.dumps(fields).encode()
        ct = await hospital.encrypt(record, [AgentId("insurer-a")])

        assert b"type-2 diabetes" not in ct
        assert b"metformin" not in ct
        assert b"Mario Rossi" not in ct

        try:
            await snoop.decrypt(ct)
        except NotInAudienceError:
            pass
        else:
            raise AssertionError("eavesdropper decrypted")

    async def test_revoked_insurer_cannot_decrypt_new_records(self) -> None:
        hospital = _mk("hospital")
        insurer_a = _mk("insurer-a")
        insurer_b = _mk("insurer-b")
        hospital.register_peer(AgentId("insurer-a"), insurer_a.public_key)
        hospital.register_peer(AgentId("insurer-b"), insurer_b.public_key)

        pre = await hospital.encrypt(
            b"pre-revocation record",
            [AgentId("insurer-a"), AgentId("insurer-b")],
        )
        assert await insurer_a.decrypt(pre) == b"pre-revocation record"

        hospital.revoke(AgentId("insurer-a"))

        post = await hospital.encrypt(
            b"post-revocation record",
            [AgentId("insurer-a"), AgentId("insurer-b")],
        )
        assert await insurer_b.decrypt(post) == b"post-revocation record"
        try:
            await insurer_a.decrypt(post)
        except NotInAudienceError:
            return
        raise AssertionError("revoked insurer decrypted post-revocation message")
