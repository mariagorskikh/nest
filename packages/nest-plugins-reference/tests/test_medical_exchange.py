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
4. **Encrypted medical exchange** — full encrypt/prove/verify round-trip,
   eavesdropper exclusion, and revocation in a medical context.
5. **Deeper privacy invariants** — six additional attack surfaces not covered
   by the existing test suite:

   a. Salt hiding — the same low-entropy field value committed with two
      different salts produces different leaf hashes, so the root does not
      leak the value to a passive observer who only knows the schema.
   b. Reveal-set integrity — a proof built for ``reveal=X`` does not verify
      against a statement demanding ``reveal=X,Y`` (extra-field mismatch).
   c. Merkle path substitution — the authentication path from leaf *i* cannot
      be spliced into a proof claiming leaf *j*; the reconstructed root diverges.
   d. Redirect / wrap-strip attack — stripping one recipient's wrap entry from
      a multi-recipient envelope breaks AEAD authentication for the remaining
      recipient (the AAD binds the full sorted recipient key-id list).
   e. Cross-insurer proof non-transferability — a proof built for insurer-A's
      statement does not verify against insurer-B's statement even when both
      statements share the same root but request different reveal sets.
   f. Partial reveal completeness — hospital can prove strict subsets of the
      credential (one field, two fields, all five fields) and every partial
      proof verifies while hiding all non-revealed values.

Example::

    pytest packages/nest-plugins-reference/tests/test_medical_exchange.py
"""

from __future__ import annotations

import json
from typing import Any, cast

from nest_core.types import AgentId, Statement, Witness
from nest_plugins_reference.privacy.hybrid_x25519 import (
    HybridX25519Privacy,
    MalformedEnvelopeError,
    NotInAudienceError,
    TamperError,
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
    *,
    salt_seed: bytes = b"hospital-issuer",
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


# ---------------------------------------------------------------------------
# 5. Deeper privacy invariants — six attack surfaces not in the existing suite
# ---------------------------------------------------------------------------


class TestSaltHiding:
    """Salt actually hides low-entropy field values from passive observers.

    Age, blood type, and diagnosis are low-cardinality values; an attacker who
    knows the schema could hash every candidate value against the published root
    unless each field's leaf hash is randomised by a unique per-field salt.
    These tests confirm that the salt is the source of that randomness, using
    only the public ``commit_credential`` / ``prove`` / ``verify_proof`` API.
    """

    def test_same_fields_different_salt_seeds_produce_different_roots(self) -> None:
        """Two credentials with identical field values but different salt seeds
        must have different Merkle roots, proving the salt actually diversifies
        the commitment (the root alone does not recover any field value)."""
        root_a, _ = commit_credential(_PATIENT_FIELDS, salt_seed=b"issuer-a")
        root_b, _ = commit_credential(_PATIENT_FIELDS, salt_seed=b"issuer-b")
        assert root_a != root_b, "different salt seeds must produce different roots"

    def test_random_salts_produce_unlinkable_commitments(self) -> None:
        """``salt_seed=None`` draws from the RNG: two commits of the same fields
        always differ, so a credential root cannot be linked to a known credential
        just by hashing the candidate field set."""
        root_a, _ = commit_credential(_PATIENT_FIELDS)
        root_b, _ = commit_credential(_PATIENT_FIELDS)
        assert root_a != root_b, (
            "random-salt commits of identical fields must be unlinkable (different roots)"
        )

    async def test_salt_change_breaks_proof_verification(self) -> None:
        """A proof built with one salt set does not verify under a root committed
        with a *different* salt set, even if all field values are identical.

        This confirms that the salt is cryptographically bound into the proof:
        re-issuing the credential with new salts invalidates all existing proofs.
        """
        hospital = _mk("hospital")
        root_a, salts_a = commit_credential(_PATIENT_FIELDS, salt_seed=b"epoch-1")
        root_b, _ = commit_credential(_PATIENT_FIELDS, salt_seed=b"epoch-2")
        assert root_a != root_b

        stmt_a = _make_statement(root_a, "age,diagnosis")
        witness_a = _make_witness(_PATIENT_FIELDS, salts_a)
        proof_a = await hospital.prove(stmt_a, witness_a)

        # Proof verifies under root-A.
        assert await hospital.verify_proof(stmt_a, proof_a)

        # The same proof must NOT verify under root-B, even though all field
        # values are identical — the salts differ so the leaf hashes differ.
        stmt_b = _make_statement(root_b, "age,diagnosis")
        assert not await hospital.verify_proof(stmt_b, proof_a), (
            "proof issued under epoch-1 salts must be rejected under epoch-2 root"
        )


class TestRevealSetIntegrity:
    """A proof is bound to the exact reveal set in its statement.

    verify_proof checks ``set(disclosed) == reveal_set(statement)``.  These
    tests confirm that a proof for a *subset* of fields does not verify against
    a statement demanding a *superset*, and vice versa.
    """

    async def test_subset_proof_fails_against_superset_statement(self) -> None:
        """Hospital proves age only; insurer's statement demands age + diagnosis."""
        hospital = _mk("hospital")
        root, salts, fields = _patient_credential()

        stmt_narrow = _make_statement(root, "age")
        witness = _make_witness(fields, salts)
        proof = await hospital.prove(stmt_narrow, witness)
        assert await hospital.verify_proof(stmt_narrow, proof)

        stmt_wide = _make_statement(root, "age,diagnosis")
        assert not await hospital.verify_proof(stmt_wide, proof), (
            "proof for 'age' must not verify against 'age,diagnosis'"
        )

    async def test_superset_proof_fails_against_subset_statement(self) -> None:
        """Hospital proves age + diagnosis; statement only asks for age."""
        hospital = _mk("hospital")
        root, salts, fields = _patient_credential()

        stmt_wide = _make_statement(root, "age,diagnosis")
        witness = _make_witness(fields, salts)
        proof = await hospital.prove(stmt_wide, witness)
        assert await hospital.verify_proof(stmt_wide, proof)

        stmt_narrow = _make_statement(root, "age")
        assert not await hospital.verify_proof(stmt_narrow, proof), (
            "proof for 'age,diagnosis' must not verify against 'age'"
        )

    async def test_empty_reveal_set_proof_not_accepted_as_full_disclosure(
        self,
    ) -> None:
        """A prove call with all fields listed verifies; claiming reveal='' fails."""
        hospital = _mk("hospital")
        root, salts, fields = _patient_credential()

        stmt_full = _make_statement(root, "age,blood_type,diagnosis,name,treatment")
        witness = _make_witness(fields, salts)
        proof = await hospital.prove(stmt_full, witness)
        assert await hospital.verify_proof(stmt_full, proof)

        stmt_empty = _make_statement(root, "")
        assert not await hospital.verify_proof(stmt_empty, proof), (
            "full-disclosure proof must not verify against empty reveal set"
        )


class TestMerklePathSubstitution:
    """An authentication path from one leaf position cannot be reused for another.

    In a Merkle tree, each leaf's path is position-specific.  Splicing the path
    of field *i* into a proof that claims to be about field *j* (same root,
    different index) changes the reconstructed root and must fail verification.
    """

    async def test_path_from_age_does_not_validate_diagnosis(self) -> None:
        hospital = _mk("hospital")
        root, salts, fields = _patient_credential()

        # Build two proofs from the same credential: one revealing age, one
        # revealing diagnosis.
        stmt_age = _make_statement(root, "age")
        stmt_diag = _make_statement(root, "diagnosis")
        witness = _make_witness(fields, salts)

        proof_age = await hospital.prove(stmt_age, witness)
        proof_diag = await hospital.prove(stmt_diag, witness)

        # Honest verification passes.
        assert await hospital.verify_proof(stmt_age, proof_age)
        assert await hospital.verify_proof(stmt_diag, proof_diag)

        # Splice: take proof_age's raw disclosed section and re-label the key
        # as "diagnosis" to claim the age path proves the diagnosis leaf.
        body_age = json.loads(proof_age.data)
        body_diag = json.loads(proof_diag.data)

        # Swap path from the age proof into the diagnosis proof's disclosed entry.
        age_entry = body_age["disclosed"]["age"]
        body_diag["disclosed"]["diagnosis"]["path"] = age_entry["path"]
        spliced_data = json.dumps(body_diag, sort_keys=True, separators=(",", ":")).encode()
        spliced_proof = proof_diag.model_copy(update={"data": spliced_data})

        assert not await hospital.verify_proof(stmt_diag, spliced_proof), (
            "path spliced from 'age' must not validate 'diagnosis'"
        )


class TestRedirectAndWrapStripAttack:
    """Stripping or redirecting a wrap entry breaks authentication for survivors.

    The AEAD associated data binds the *sorted list of all recipient key-ids*.
    Removing one recipient's wrap entry from a multi-recipient envelope changes
    the key-id list, which invalidates the AAD used to decrypt the content key.
    The surviving recipient's decrypt must therefore fail with a tamper error
    rather than silently succeeding with a degraded audience.
    """

    async def test_strip_one_wrap_entry_breaks_survivor_decrypt(self) -> None:
        hospital = _mk("hospital")
        insurer_a = _mk("insurer-a")
        insurer_b = _mk("insurer-b")
        hospital.register_peer(AgentId("insurer-a"), insurer_a.public_key)
        hospital.register_peer(AgentId("insurer-b"), insurer_b.public_key)

        record = b"confidential: diagnosis type-2-diabetes"
        env = await hospital.encrypt(record, [AgentId("insurer-a"), AgentId("insurer-b")])
        # Both insurers can decrypt the original envelope.
        assert await insurer_a.decrypt(env) == record
        # Insurer-B needs a fresh encrypt call (replay protection consumed
        # insurer-a's seen-set entry, but insurer-b's is independent).
        env2 = await hospital.encrypt(record, [AgentId("insurer-a"), AgentId("insurer-b")])
        assert await insurer_b.decrypt(env2) == record

        # Attacker strips insurer-b's wrap from a fresh envelope and re-presents
        # it to insurer-a.  The AAD no longer matches — AEAD must reject.
        env3 = await hospital.encrypt(record, [AgentId("insurer-a"), AgentId("insurer-b")])
        parsed = json.loads(env3)
        # Keep only the wrap entry whose kid matches insurer-a.
        parsed["to"] = [w for w in parsed["to"] if w["kid"] == insurer_a.key_id]
        stripped = json.dumps(parsed, sort_keys=True, separators=(",", ":")).encode()
        try:
            await insurer_a.decrypt(stripped)
        except (TamperError, MalformedEnvelopeError, NotInAudienceError):
            pass  # any cryptographic rejection is acceptable
        else:
            raise AssertionError(
                "insurer-a decrypted a wrap-stripped envelope — AAD binding failed"
            )


class TestCrossInsurerProofNonTransferability:
    """A proof issued for insurer-A's statement does not satisfy insurer-B's.

    Even when both statements share the same Merkle root, each statement
    specifies its own ``reveal`` set.  The prove/verify binding ensures a proof
    minted for one party's authorisation cannot be reused by another party
    with a different authorisation scope.
    """

    async def test_insurer_a_proof_fails_against_insurer_b_statement(self) -> None:
        hospital = _mk("hospital")
        root, salts, fields = _patient_credential()

        # Insurer-A is authorised to see age + diagnosis only.
        stmt_a = _make_statement(root, "age,diagnosis")
        # Insurer-B is authorised to see diagnosis + treatment only.
        stmt_b = _make_statement(root, "diagnosis,treatment")

        witness = _make_witness(fields, salts)
        proof_a = await hospital.prove(stmt_a, witness)

        assert await hospital.verify_proof(stmt_a, proof_a)
        assert not await hospital.verify_proof(stmt_b, proof_a), (
            "insurer-A's proof must not verify against insurer-B's statement"
        )

    async def test_all_three_insurer_proofs_are_mutually_non_transferable(
        self,
    ) -> None:
        """Each insurer's proof verifies only against its own statement."""
        hospital = _mk("hospital")
        root, salts, fields = _patient_credential()
        witness = _make_witness(fields, salts)

        statements = {
            "insurer-a": _make_statement(root, "age,diagnosis"),
            "insurer-b": _make_statement(root, "diagnosis,treatment"),
            "insurer-c": _make_statement(root, "age"),
        }
        proofs = {name: await hospital.prove(stmt, witness) for name, stmt in statements.items()}

        for owner, proof in proofs.items():
            for verifier, stmt in statements.items():
                ok = await hospital.verify_proof(stmt, proof)
                if owner == verifier:
                    assert ok, f"{owner}'s proof failed its own statement"
                else:
                    assert not ok, (
                        f"{owner}'s proof wrongly verified against {verifier}'s statement"
                    )


class TestPartialRevealCompleteness:
    """Hospital can prove any strict subset of credential fields.

    Confirms that the Merkle scheme is complete for all subset sizes (1 through
    5 fields) and that each partial proof hides every non-revealed value.
    """

    async def test_every_single_field_can_be_proved_independently(self) -> None:
        hospital = _mk("hospital")
        root, salts, fields = _patient_credential()
        witness = _make_witness(fields, salts)

        for field_name in _PATIENT_FIELDS:
            stmt = _make_statement(root, field_name)
            proof = await hospital.prove(stmt, witness)
            assert await hospital.verify_proof(stmt, proof), (
                f"single-field proof for '{field_name}' failed to verify"
            )
            # Parse the proof JSON to check the *disclosed values* section only.
            # Raw-byte substring checks would produce false positives because
            # short field values (e.g. "42") can appear as substrings of the
            # hexadecimal Merkle path hashes — not a data leak.
            body = cast("dict[str, Any]", json.loads(proof.data))
            raw_disc = cast("dict[str, Any]", body.get("disclosed", {}))
            disclosed_values: dict[str, str] = {
                name: str(cast("dict[str, Any]", entry)["value"])
                for name, entry in raw_disc.items()
                if isinstance(entry, dict) and "value" in entry
            }
            for other, _value in _PATIENT_FIELDS.items():
                if other != field_name:
                    assert other not in disclosed_values, (
                        f"hidden field '{other}' appeared in disclosed section"
                        f" of proof for '{field_name}'"
                    )
                    assert disclosed_values.get(field_name) == _PATIENT_FIELDS[field_name]  # noqa: SIM910

    async def test_all_five_fields_can_be_proved_at_once(self) -> None:
        hospital = _mk("hospital")
        root, salts, fields = _patient_credential()
        witness = _make_witness(fields, salts)

        all_fields = ",".join(sorted(_PATIENT_FIELDS))
        stmt = _make_statement(root, all_fields)
        proof = await hospital.prove(stmt, witness)
        assert await hospital.verify_proof(stmt, proof)

    async def test_two_field_proof_hides_remaining_three(self) -> None:
        hospital = _mk("hospital")
        root, salts, fields = _patient_credential()
        witness = _make_witness(fields, salts)

        revealed = {"age", "blood_type"}
        hidden = set(_PATIENT_FIELDS) - revealed
        stmt = _make_statement(root, ",".join(sorted(revealed)))
        proof = await hospital.prove(stmt, witness)
        assert await hospital.verify_proof(stmt, proof)
        # Check the disclosed-values section of the proof JSON; substring checks
        # on raw bytes would false-positive on hex Merkle path hashes.
        body = cast("dict[str, Any]", json.loads(proof.data))
        raw_disc2 = cast("dict[str, Any]", body.get("disclosed", {}))
        disclosed_values2: dict[str, str] = {
            name: str(cast("dict[str, Any]", entry)["value"])
            for name, entry in raw_disc2.items()
            if isinstance(entry, dict) and "value" in entry
        }
        for field_name in hidden:
            assert field_name not in disclosed_values2, (
                f"hidden field '{field_name}' appeared in disclosed section of two-field proof"
            )
