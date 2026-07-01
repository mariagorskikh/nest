# SPDX-License-Identifier: Apache-2.0
"""Tests for signed, identity-bound policy manifests."""

from __future__ import annotations

from nest_core.types import AgentId
from nest_plugins_reference.identity.ed25519_rotating import Ed25519RotatingIdentity
from nest_plugins_reference.policy.manifest import (
    Approval,
    Budget,
    PolicyManifest,
    sign_manifest,
    verify_manifest,
)


def _ident(aid: str = "a1", seed: bytes = b"seed") -> Ed25519RotatingIdentity:
    return Ed25519RotatingIdentity(AgentId(aid), seed=seed)


def test_sign_verify_roundtrip() -> None:
    ident = _ident()
    manifest = PolicyManifest(agent_id=AgentId("a1"), tools=["buy"], budget=Budget(cap=500))
    signed = sign_manifest(ident, manifest)
    assert signed.signature is not None
    assert verify_manifest(ident, signed)


def test_unsigned_manifest_rejected() -> None:
    ident = _ident()
    manifest = PolicyManifest(agent_id=AgentId("a1"), tools=["buy"])
    assert not verify_manifest(ident, manifest)


def test_tamper_tools_after_signing_rejected() -> None:
    ident = _ident()
    manifest = PolicyManifest(agent_id=AgentId("a1"), tools=["buy"], budget=Budget(cap=500))
    signed = sign_manifest(ident, manifest)
    tampered = signed.model_copy(update={"tools": ["buy", "admin"]})
    assert not verify_manifest(ident, tampered)


def test_tamper_budget_after_signing_rejected() -> None:
    ident = _ident()
    manifest = PolicyManifest(agent_id=AgentId("a1"), budget=Budget(cap=100))
    signed = sign_manifest(ident, manifest)
    tampered = signed.model_copy(update={"budget": Budget(cap=10_000)})
    assert not verify_manifest(ident, tampered)


def test_forged_by_other_identity_rejected() -> None:
    # Attacker signs a manifest claiming to be a1, using their own key material.
    attacker = _ident("a1", seed=b"attacker-key")
    honest = _ident("a1", seed=b"seed")  # the *real* a1 key the verifier trusts
    manifest = PolicyManifest(agent_id=AgentId("a1"), tools=["admin"])
    forged = sign_manifest(attacker, manifest)
    # The honest verifier binds a1 to the real key; the forged signature's
    # key_id is not among the trusted records, so verification fails.
    assert not verify_manifest(honest, forged)


def test_signing_bytes_deterministic_and_order_independent() -> None:
    a = PolicyManifest(agent_id=AgentId("a1"), tools=["a", "b"], budget=Budget(cap=5))
    b = PolicyManifest(agent_id=AgentId("a1"), budget=Budget(cap=5), tools=["a", "b"])
    assert a.signing_bytes() == a.signing_bytes()
    assert a.signing_bytes() == b.signing_bytes()


def test_tamper_agent_id_after_signing_rejected() -> None:
    ident = _ident()
    signed = sign_manifest(ident, PolicyManifest(agent_id=AgentId("a1"), tools=["buy"]))
    tampered = signed.model_copy(update={"agent_id": AgentId("a2")})
    assert not verify_manifest(ident, tampered)


def test_tamper_issued_at_after_signing_rejected() -> None:
    ident = _ident()
    signed = sign_manifest(ident, PolicyManifest(agent_id=AgentId("a1"), issued_at=1.0))
    tampered = signed.model_copy(update={"issued_at": 999.0})
    assert not verify_manifest(ident, tampered)


def test_tamper_approvals_after_signing_rejected() -> None:
    ident = _ident()
    signed = sign_manifest(
        ident,
        PolicyManifest(
            agent_id=AgentId("a1"),
            budget=Budget(cap=1000),
            approvals=[Approval(op="pay", threshold=100)],
        ),
    )
    tampered = signed.model_copy(update={"approvals": [Approval(op="pay", threshold=10_000)]})
    assert not verify_manifest(ident, tampered)


def test_signature_transplant_rejected() -> None:
    ident = _ident()
    signed_a = sign_manifest(ident, PolicyManifest(agent_id=AgentId("a1"), tools=["buy"]))
    other = PolicyManifest(agent_id=AgentId("a1"), tools=["admin"])
    transplanted = other.model_copy(update={"signature": signed_a.signature})
    assert not verify_manifest(ident, transplanted)


def test_signed_manifest_json_roundtrip_still_verifies() -> None:
    # The signed manifest must serialise to JSON (raw signature bytes -> hex)
    # and round-trip back to a manifest that still verifies. This is the
    # trace-announcement / validator-decode contract (JSON round-trip).
    ident = _ident()
    signed = sign_manifest(
        ident,
        PolicyManifest(
            agent_id=AgentId("a1"),
            tools=["buy"],
            data={"pii": ["seller-1"]},
            budget=Budget(cap=500),
            approvals=[Approval(op="pay", threshold=100)],
        ),
    )
    payload = signed.model_dump_json()
    restored = PolicyManifest.model_validate_json(payload)
    assert restored.signature is not None
    assert restored.signature.value == signed.signature.value if signed.signature else False
    assert verify_manifest(ident, restored)


def test_unsigned_manifest_json_roundtrips() -> None:
    m = PolicyManifest(agent_id=AgentId("a1"), tools=["buy"])
    restored = PolicyManifest.model_validate_json(m.model_dump_json())
    assert restored.signature is None
    assert restored.signing_bytes() == m.signing_bytes()
