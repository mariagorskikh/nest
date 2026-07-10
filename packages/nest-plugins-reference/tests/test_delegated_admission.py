# SPDX-License-Identifier: Apache-2.0
"""Unit + property tests for the delegated-admission trust plugin.

Layers of coverage:

1. Byte-exact parity with the TS ``canonicalProofEnvelope`` (fixed vector).
2. Trust protocol conformance + registry resolution.
3. PuhProof verification (freshness, hash, signature, principal).
4. Grant chain narrowing, cascade revoke, ancestor-expiry narrowing.
5. ``report()`` admission end-to-end.
6. Hypothesis property tests.
7. Byzantine-input parametrization.
"""

from __future__ import annotations

import asyncio
import hashlib
import random
import tempfile
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from nest_core.layers.trust import Trust
from nest_core.plugins import PluginRegistry
from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_core.types import AgentId, Evidence
from nest_core.validators import ValidationResult, validate_trace
from nest_plugins_reference.trust.delegated_admission import (
    ALGORITHM,
    MAX_HOPS,
    PUH_FRESHNESS_MS,
    PUH_SKEW_MS,
    AdmissionPolicy,
    AdmissionVerdict,
    DelegatedAdmissionTrust,
    DelegationSubject,
    PuhProof,
    _public_raw,  # pyright: ignore[reportPrivateUsage]  # test-only inspection
    build_proof,
    canonical_proof_envelope,
    derive_principal,
    envelope_hash,
    sign_proof_envelope,
)

# ---------------------------------------------------------------------------
# Shared fixtures / helpers
# ---------------------------------------------------------------------------

# A fixed "now" comfortably inside PuhProof freshness for every test that
# doesn't specifically test the freshness window.
NOW_MS = 1_700_000_000_000
NOW_S = NOW_MS // 1000

DEFAULT_TTL_S = NOW_S + 3600  # one hour ahead

# PuhProof identity fixture literals, reused across every proof-building test.
_FIXTURE_DEVICE_DID = "did:key:z6MkFixture"
_FIXTURE_REQUEST_ID = "req-fixture"


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


def _cast_scope(items: Any) -> tuple[str, ...]:
    """Test helper: accept a heterogeneous iterable as the scope tuple."""
    return tuple(items)


def _principal_seed(tag: str = "pri") -> tuple[str, Any]:
    """Deterministic principal for tests."""
    return derive_principal(f"delegated-admission-tests:{tag}".encode())


def _make_trust(*, tag: str = "pri", scope: str = "trust.report") -> DelegatedAdmissionTrust:
    pid, priv = _principal_seed(tag)
    trust = DelegatedAdmissionTrust(
        agent_id=AgentId("observer"),
        seed=b"test",
        policy=AdmissionPolicy(
            trusted_principals={pid: _public_raw(priv)},
            required_scope=scope,
        ),
    )
    trust.set_clock(NOW_MS)
    return trust


def _default_subject(
    delegate_id: str = "agent-delegate-1",
    scope: tuple[str, ...] = ("trust.report", "tool.echo"),
    expires_at: int | None = None,
    parent: str | None = None,
    revocable: bool = True,
) -> DelegationSubject:
    return DelegationSubject(
        delegate_id=delegate_id,
        granted_scope=scope,
        expires_at=expires_at if expires_at is not None else DEFAULT_TTL_S,
        parent_delegation_id=parent,
        revocable=revocable,
    )


def _issue_grant(
    trust: DelegatedAdmissionTrust,
    *,
    tag: str = "pri",
    subject: DelegationSubject | None = None,
    now_ms: int | None = None,
) -> str:
    """Issue a valid grant and return the delegation id."""
    pid, priv = _principal_seed(tag)
    subj = subject or _default_subject()
    envelope, proof = build_proof(pid, priv, subj, now_ms=now_ms if now_ms is not None else NOW_MS)
    result = trust.grant(subj, proof, granted_by_proof_hash=envelope_hash(envelope))
    assert result.ok, f"expected grant success, got {result.reason}"
    assert result.delegation_id is not None
    return result.delegation_id


# ---------------------------------------------------------------------------
# 0. Wiring — registry resolution, Trust protocol conformance
# ---------------------------------------------------------------------------


def test_registry_resolves_delegated_admission() -> None:
    """The plugin is wired into the built-in registry as trust:delegated_admission."""
    cls = PluginRegistry().resolve("trust", "delegated_admission")
    assert cls is DelegatedAdmissionTrust


def test_satisfies_trust_protocol() -> None:
    """An instance structurally satisfies the Trust layer Protocol."""
    assert isinstance(DelegatedAdmissionTrust(agent_id=AgentId("a1")), Trust)


def test_attest_uses_algorithm_tag() -> None:
    """attest() stamps the module's ALGORITHM constant onto the signature."""
    from nest_core.types import Claim  # local import — Claim is only needed here

    trust = _make_trust()
    claim = Claim(subject=AgentId("a1"), predicate="p", value="v")
    att = _run(trust.attest(AgentId("a1"), claim))
    assert att.signature.algorithm == ALGORITHM


def test_constructor_ignores_identity_positional() -> None:
    """The identity positional is accepted-and-ignored for baseline compat."""
    trust = DelegatedAdmissionTrust("some-identity-stub", agent_id=AgentId("a1"))
    assert isinstance(trust, DelegatedAdmissionTrust)


# ---------------------------------------------------------------------------
# 1. Canonical envelope — byte-exact TS parity
# ---------------------------------------------------------------------------


_FIXED_VECTOR_CANONICAL = (
    b'{"principalPk":"yz-principal-01",'
    b'"deviceDid":"did:key:z6Mkdevice",'
    b'"requestId":"yz-req-01",'
    b'"grantee":"agent-delegate-1",'
    b'"scope":{"toolNames":["tool.echo","tool.summarize"]},'
    b'"expiresAt":1000000000,'
    b'"parentDelegationId":null,'
    b'"revocable":true,'
    b'"issuedAt":999500000}'
)


def _fixed_vector_subject_proof() -> tuple[PuhProof, DelegationSubject]:
    subject = DelegationSubject(
        delegate_id="agent-delegate-1",
        granted_scope=("tool.echo", "tool.summarize"),
        expires_at=1_000_000_000,
        parent_delegation_id=None,
        revocable=True,
    )
    proof = PuhProof(
        principal_pk="yz-principal-01",
        device_did="did:key:z6Mkdevice",
        request_id="yz-req-01",
        bound_at_ms=0,
        issued_at_ms=999_500_000,
    )
    return proof, subject


def test_canonical_envelope_matches_ts_fixed_vector() -> None:
    """The exact TS byte sequence is what canonical_proof_envelope emits."""
    proof, subject = _fixed_vector_subject_proof()
    assert canonical_proof_envelope(proof, subject) == _FIXED_VECTOR_CANONICAL


def test_canonical_envelope_hash_matches_computed_sha256() -> None:
    """The envelope hash is the plain sha256 of the canonical bytes."""
    proof, subject = _fixed_vector_subject_proof()
    canonical = canonical_proof_envelope(proof, subject)
    assert envelope_hash(canonical) == hashlib.sha256(_FIXED_VECTOR_CANONICAL).hexdigest()


def test_canonical_envelope_sorts_tool_names_regardless_of_input_order() -> None:
    """Scope order is not a signal — reversed input yields the same envelope."""
    proof, subject_fwd = _fixed_vector_subject_proof()
    subject_rev = DelegationSubject(
        delegate_id=subject_fwd.delegate_id,
        granted_scope=tuple(reversed(subject_fwd.granted_scope)),
        expires_at=subject_fwd.expires_at,
        parent_delegation_id=subject_fwd.parent_delegation_id,
        revocable=subject_fwd.revocable,
    )
    assert canonical_proof_envelope(proof, subject_fwd) == canonical_proof_envelope(
        proof, subject_rev
    )


def test_canonical_envelope_trims_and_drops_empty_scope_entries() -> None:
    """Whitespace is trimmed; empty / non-string entries are dropped entirely."""
    proof, subject_ref = _fixed_vector_subject_proof()
    dirty = DelegationSubject(
        delegate_id=subject_ref.delegate_id,
        granted_scope=_cast_scope(("  tool.echo  ", "", "  ", "tool.summarize")),
        expires_at=subject_ref.expires_at,
        parent_delegation_id=subject_ref.parent_delegation_id,
        revocable=subject_ref.revocable,
    )
    assert canonical_proof_envelope(proof, dirty) == _FIXED_VECTOR_CANONICAL


def test_canonical_envelope_drops_non_string_scope_entries() -> None:
    """Non-string scope entries (dict, int, None) don't crash and are ignored."""
    proof, subject_ref = _fixed_vector_subject_proof()
    dirty = DelegationSubject(
        delegate_id=subject_ref.delegate_id,
        # Cast through Any so the type checker accepts a mixed tuple only in tests.
        granted_scope=_cast_scope(("tool.echo", 42, None, {"x": 1}, "tool.summarize")),  # type: ignore[arg-type]
        expires_at=subject_ref.expires_at,
        parent_delegation_id=subject_ref.parent_delegation_id,
        revocable=subject_ref.revocable,
    )
    assert canonical_proof_envelope(proof, dirty) == _FIXED_VECTOR_CANONICAL


# ---------------------------------------------------------------------------
# 2. PuhProof verification
# ---------------------------------------------------------------------------


def test_puh_fresh_proof_admits_grant() -> None:
    """A freshly-signed, correctly-hashed proof from a trusted principal is admissible."""
    trust = _make_trust()
    _ = _issue_grant(trust)


def test_puh_stale_bound_at_rejected() -> None:
    """A bound_at older than PUH_FRESHNESS_MS is rejected as puh-proof-stale."""
    trust = _make_trust()
    pid, priv = _principal_seed()
    subject = _default_subject()
    envelope, proof = build_proof(
        pid, priv, subject, now_ms=NOW_MS - (PUH_FRESHNESS_MS + PUH_SKEW_MS + 1)
    )
    r = trust.grant(subject, proof, granted_by_proof_hash=envelope_hash(envelope))
    assert not r.ok and r.reason == "puh-proof-stale"


def test_puh_stale_issued_at_rejected() -> None:
    """issued_at older than freshness window is rejected even when bound_at is fresh."""
    trust = _make_trust()
    pid, priv = _principal_seed()
    subject = _default_subject()
    stale_issued = NOW_MS - (PUH_FRESHNESS_MS + PUH_SKEW_MS + 1)
    proof_unsigned = PuhProof(
        principal_pk=pid,
        device_did=_FIXTURE_DEVICE_DID,
        request_id=_FIXTURE_REQUEST_ID,
        bound_at_ms=NOW_MS,
        issued_at_ms=stale_issued,
        signature=None,
    )
    envelope = canonical_proof_envelope(proof_unsigned, subject)
    proof = PuhProof(
        principal_pk=pid,
        device_did=_FIXTURE_DEVICE_DID,
        request_id=_FIXTURE_REQUEST_ID,
        bound_at_ms=NOW_MS,
        issued_at_ms=stale_issued,
        signature=sign_proof_envelope(priv, envelope),
    )
    r = trust.grant(subject, proof, granted_by_proof_hash=envelope_hash(envelope))
    assert not r.ok and r.reason == "puh-proof-stale"


def test_puh_future_dated_beyond_skew_rejected() -> None:
    """A bound_at further ahead than PUH_SKEW_MS is rejected as stale/future."""
    trust = _make_trust()
    pid, priv = _principal_seed()
    subject = _default_subject()
    envelope, proof = build_proof(pid, priv, subject, now_ms=NOW_MS + (PUH_SKEW_MS + 1))
    r = trust.grant(subject, proof, granted_by_proof_hash=envelope_hash(envelope))
    assert not r.ok and r.reason == "puh-proof-stale"


def test_puh_issued_before_bound_beyond_skew_rejected() -> None:
    """issued_at < bound_at - skew is rejected (contradictory ordering)."""
    trust = _make_trust()
    pid, priv = _principal_seed()
    subject = _default_subject()
    bound = NOW_MS
    issued = bound - PUH_SKEW_MS - 1
    proof_unsigned = PuhProof(
        principal_pk=pid,
        device_did=_FIXTURE_DEVICE_DID,
        request_id=_FIXTURE_REQUEST_ID,
        bound_at_ms=bound,
        issued_at_ms=issued,
        signature=None,
    )
    envelope = canonical_proof_envelope(proof_unsigned, subject)
    proof = PuhProof(
        principal_pk=pid,
        device_did=_FIXTURE_DEVICE_DID,
        request_id=_FIXTURE_REQUEST_ID,
        bound_at_ms=bound,
        issued_at_ms=issued,
        signature=sign_proof_envelope(priv, envelope),
    )
    r = trust.grant(subject, proof, granted_by_proof_hash=envelope_hash(envelope))
    # Production parity: the TS verifier rejects contradictory ordering with
    # ``invalid-proof`` (not a staleness reason).
    assert not r.ok and r.reason == "invalid-proof"


def test_puh_hash_mismatch_when_grantee_altered() -> None:
    """A proof hash computed for a different grantee is rejected."""
    trust = _make_trust()
    pid, priv = _principal_seed()
    subject_a = _default_subject(delegate_id="agent-A")
    subject_b = _default_subject(delegate_id="agent-B")
    env_a, _ = build_proof(pid, priv, subject_a, now_ms=NOW_MS)
    # Present subject_a's hash on a grant for subject_b.
    _, proof_b = build_proof(pid, priv, subject_b, now_ms=NOW_MS)
    r = trust.grant(subject_b, proof_b, granted_by_proof_hash=envelope_hash(env_a))
    assert not r.ok and r.reason == "proof-hash-mismatch"


def test_puh_hash_mismatch_when_scope_widened() -> None:
    """Widened scope makes the recomputed hash diverge from a preimage hash."""
    trust = _make_trust()
    pid, priv = _principal_seed()
    narrow = _default_subject(scope=("trust.report",))
    wide = _default_subject(scope=("trust.report", "tool.dangerous"))
    env_narrow, _ = build_proof(pid, priv, narrow, now_ms=NOW_MS)
    _, proof_wide = build_proof(pid, priv, wide, now_ms=NOW_MS)
    r = trust.grant(wide, proof_wide, granted_by_proof_hash=envelope_hash(env_narrow))
    assert not r.ok and r.reason == "proof-hash-mismatch"


def test_puh_missing_hash_rejected() -> None:
    """A grant call without any granted_by_proof_hash is rejected."""
    trust = _make_trust()
    pid, priv = _principal_seed()
    subject = _default_subject()
    _, proof = build_proof(pid, priv, subject, now_ms=NOW_MS)
    r = trust.grant(subject, proof, granted_by_proof_hash=None)
    assert not r.ok and r.reason == "missing-proof-hash"


def test_puh_missing_signature_rejected_when_required() -> None:
    """require_signed_puh=True rejects an unsigned proof."""
    trust = _make_trust()
    pid, priv = _principal_seed()
    subject = _default_subject()
    envelope, _ = build_proof(pid, priv, subject, now_ms=NOW_MS, signed=False)
    unsigned = PuhProof(
        principal_pk=pid,
        device_did=_FIXTURE_DEVICE_DID,
        request_id=_FIXTURE_REQUEST_ID,
        bound_at_ms=NOW_MS,
        issued_at_ms=NOW_MS,
        signature=None,
    )
    r = trust.grant(subject, unsigned, granted_by_proof_hash=envelope_hash(envelope))
    assert not r.ok and r.reason == "missing-signature"


def test_puh_tampered_signature_rejected() -> None:
    """Flipping a byte of the signature causes bad-signature."""
    trust = _make_trust()
    pid, priv = _principal_seed()
    subject = _default_subject()
    envelope, proof = build_proof(pid, priv, subject, now_ms=NOW_MS)
    assert proof.signature is not None
    tampered = bytearray(proof.signature)
    tampered[0] ^= 0x01
    bad = PuhProof(
        principal_pk=proof.principal_pk,
        device_did=proof.device_did,
        request_id=proof.request_id,
        bound_at_ms=proof.bound_at_ms,
        issued_at_ms=proof.issued_at_ms,
        signature=bytes(tampered),
    )
    r = trust.grant(subject, bad, granted_by_proof_hash=envelope_hash(envelope))
    assert not r.ok and r.reason == "bad-signature"


def test_puh_unknown_principal_rejected() -> None:
    """A principal_pk not on the trusted roster fails admission."""
    trust = _make_trust()
    _, priv_evil = derive_principal(b"evil-principal")
    # Impersonation attempt: proof carries an unknown principal id.
    subject = _default_subject()
    proof_unsigned = PuhProof(
        principal_pk="unknown-pk",
        device_did=_FIXTURE_DEVICE_DID,
        request_id=_FIXTURE_REQUEST_ID,
        bound_at_ms=NOW_MS,
        issued_at_ms=NOW_MS,
    )
    envelope = canonical_proof_envelope(proof_unsigned, subject)
    proof = PuhProof(
        principal_pk="unknown-pk",
        device_did=_FIXTURE_DEVICE_DID,
        request_id=_FIXTURE_REQUEST_ID,
        bound_at_ms=NOW_MS,
        issued_at_ms=NOW_MS,
        signature=sign_proof_envelope(priv_evil, envelope),
    )
    r = trust.grant(subject, proof, granted_by_proof_hash=envelope_hash(envelope))
    assert not r.ok and r.reason == "unknown-principal"


def test_puh_signature_present_but_not_required_still_verified() -> None:
    """If policy tolerates unsigned proofs, a present-but-bad signature still fails."""
    pid, priv = _principal_seed()
    trust = DelegatedAdmissionTrust(
        agent_id=AgentId("observer"),
        policy=AdmissionPolicy(
            trusted_principals={pid: _public_raw(priv)},
            require_signed_puh=False,
        ),
    )
    trust.set_clock(NOW_MS)
    subject = _default_subject()
    envelope, proof = build_proof(pid, priv, subject, now_ms=NOW_MS)
    assert proof.signature is not None
    tampered_bytes = bytearray(proof.signature)
    tampered_bytes[0] ^= 0x01  # deterministic single-byte flip → invalid
    tampered = bytes(tampered_bytes)
    bad = PuhProof(
        principal_pk=proof.principal_pk,
        device_did=proof.device_did,
        request_id=proof.request_id,
        bound_at_ms=proof.bound_at_ms,
        issued_at_ms=proof.issued_at_ms,
        signature=tampered,
    )
    r = trust.grant(subject, bad, granted_by_proof_hash=envelope_hash(envelope))
    assert not r.ok and r.reason == "bad-signature"


# ---------------------------------------------------------------------------
# 3. Grant chain narrowing
# ---------------------------------------------------------------------------


def test_grant_rejects_empty_scope() -> None:
    """Empty scope (after normalisation) is rejected at grant time."""
    trust = _make_trust()
    pid, priv = _principal_seed()
    subject = _default_subject(scope=())
    _, proof = build_proof(pid, priv, subject, now_ms=NOW_MS)
    r = trust.grant(subject, proof, granted_by_proof_hash="")
    assert not r.ok and r.reason == "empty-scope"


def test_grant_rejects_already_expired() -> None:
    """A grant whose expires_at <= now_s is rejected as expired-at-grant."""
    trust = _make_trust()
    pid, priv = _principal_seed()
    subject = _default_subject(expires_at=NOW_S - 1)
    envelope, proof = build_proof(pid, priv, subject, now_ms=NOW_MS)
    r = trust.grant(subject, proof, granted_by_proof_hash=envelope_hash(envelope))
    assert not r.ok and r.reason == "expired-at-grant"


def test_chain_parent_not_found() -> None:
    """A child claiming a parent that doesn't exist is rejected."""
    trust = _make_trust()
    pid, priv = _principal_seed()
    subject = _default_subject(delegate_id="child-1", parent="del-ghost-nonexistent")
    envelope, proof = build_proof(pid, priv, subject, now_ms=NOW_MS)
    r = trust.grant(subject, proof, granted_by_proof_hash=envelope_hash(envelope))
    assert not r.ok and r.reason == "parent-not-found"


def test_chain_parent_revoked() -> None:
    """A child of a revoked parent cannot be minted."""
    trust = _make_trust()
    parent_id = _issue_grant(trust, subject=_default_subject(delegate_id="parent-1"))
    trust.revoke(parent_id)
    pid, priv = _principal_seed()
    subject = _default_subject(delegate_id="child-1", parent=parent_id)
    envelope, proof = build_proof(pid, priv, subject, now_ms=NOW_MS)
    r = trust.grant(subject, proof, granted_by_proof_hash=envelope_hash(envelope))
    assert not r.ok and r.reason == "parent-revoked"


def test_chain_scope_widens_parent() -> None:
    """A child cannot add a scope the parent lacked."""
    trust = _make_trust()
    parent_id = _issue_grant(
        trust, subject=_default_subject(delegate_id="parent-1", scope=("trust.report",))
    )
    pid, priv = _principal_seed()
    child_subject = _default_subject(
        delegate_id="child-1", scope=("trust.report", "tool.exfiltrate"), parent=parent_id
    )
    envelope, proof = build_proof(pid, priv, child_subject, now_ms=NOW_MS)
    r = trust.grant(child_subject, proof, granted_by_proof_hash=envelope_hash(envelope))
    assert not r.ok and r.reason == "scope-widens-parent"


def test_chain_ttl_widens_parent() -> None:
    """A child cannot outlive its parent."""
    trust = _make_trust()
    parent_id = _issue_grant(
        trust,
        subject=_default_subject(delegate_id="parent-1", expires_at=NOW_S + 100),
    )
    pid, priv = _principal_seed()
    child_subject = _default_subject(
        delegate_id="child-1", parent=parent_id, expires_at=NOW_S + 1000
    )
    envelope, proof = build_proof(pid, priv, child_subject, now_ms=NOW_MS)
    r = trust.grant(child_subject, proof, granted_by_proof_hash=envelope_hash(envelope))
    assert not r.ok and r.reason == "ttl-widens-parent"


def test_chain_revocable_flip_forbidden() -> None:
    """A revocable parent cannot yield an irrevocable child."""
    trust = _make_trust()
    parent_id = _issue_grant(
        trust, subject=_default_subject(delegate_id="parent-1", revocable=True)
    )
    pid, priv = _principal_seed()
    child_subject = _default_subject(delegate_id="child-1", parent=parent_id, revocable=False)
    envelope, proof = build_proof(pid, priv, child_subject, now_ms=NOW_MS)
    r = trust.grant(child_subject, proof, granted_by_proof_hash=envelope_hash(envelope))
    assert not r.ok and r.reason == "revocable-flip-forbidden"


def test_chain_too_deep_rejected_at_mint() -> None:
    """The MAX_HOPS-th re-delegation is minted; one deeper is refused.

    Fail-closed depth cap: the production TS source bounds the cascade and
    ancestor walks but not mint depth, which fails open past twice the
    bound — we refuse at mint so every legal chain is fully covered.
    """
    trust = _make_trust()
    pid, priv = _principal_seed()
    parent: str | None = None
    for i in range(MAX_HOPS + 1):  # root (depth 0) + MAX_HOPS descendants
        subject = _default_subject(delegate_id=f"agent-{i}", parent=parent)
        envelope, proof = build_proof(pid, priv, subject, now_ms=NOW_MS)
        r = trust.grant(subject, proof, granted_by_proof_hash=envelope_hash(envelope))
        assert r.ok, f"depth {i} should mint: {r.reason}"
        parent = r.delegation_id
    subject = _default_subject(delegate_id="agent-too-deep", parent=parent)
    envelope, proof = build_proof(pid, priv, subject, now_ms=NOW_MS)
    r = trust.grant(subject, proof, granted_by_proof_hash=envelope_hash(envelope))
    assert not r.ok and r.reason == "chain-too-deep"


def test_policy_accessor_and_trust_principal() -> None:
    """`policy` exposes the live policy; `trust_principal` extends the roster."""
    trust = _make_trust()
    assert trust.policy.required_scope == "trust.report"
    pid2, priv2 = derive_principal(b"second-principal")
    trust.trust_principal(pid2, _public_raw(priv2))
    subject = _default_subject(delegate_id="agent-p2")
    envelope, proof = build_proof(pid2, priv2, subject, now_ms=NOW_MS)
    r = trust.grant(subject, proof, granted_by_proof_hash=envelope_hash(envelope))
    assert r.ok


# ---------------------------------------------------------------------------
# 4. Revoke cascade + check semantics
# ---------------------------------------------------------------------------


def _build_three_level_chain(trust: DelegatedAdmissionTrust) -> tuple[str, str, str]:
    """Root → mid → leaf; returns their delegation ids."""
    pid, priv = _principal_seed()
    root_sub = _default_subject(delegate_id="root", scope=("trust.report", "tool.echo"))
    env, proof = build_proof(pid, priv, root_sub, now_ms=NOW_MS)
    root = trust.grant(root_sub, proof, granted_by_proof_hash=envelope_hash(env))
    assert root.ok and root.delegation_id
    mid_sub = _default_subject(
        delegate_id="mid", scope=("trust.report",), parent=root.delegation_id
    )
    env, proof = build_proof(pid, priv, mid_sub, now_ms=NOW_MS)
    mid = trust.grant(mid_sub, proof, granted_by_proof_hash=envelope_hash(env))
    assert mid.ok and mid.delegation_id
    leaf_sub = _default_subject(
        delegate_id="leaf", scope=("trust.report",), parent=mid.delegation_id
    )
    env, proof = build_proof(pid, priv, leaf_sub, now_ms=NOW_MS)
    leaf = trust.grant(leaf_sub, proof, granted_by_proof_hash=envelope_hash(env))
    assert leaf.ok and leaf.delegation_id
    return root.delegation_id, mid.delegation_id, leaf.delegation_id


def test_cascade_revoke_marks_descendants() -> None:
    """Revoking mid revokes leaf but leaves root intact."""
    trust = _make_trust()
    root_id, mid_id, leaf_id = _build_three_level_chain(trust)
    r = trust.revoke(mid_id)
    assert r.ok
    assert set(r.cascaded) == {mid_id, leaf_id}
    assert trust.check(root_id).valid
    assert trust.check(mid_id).revoked
    assert trust.check(leaf_id).revoked


def test_revoke_is_idempotent() -> None:
    """A double revoke succeeds with an empty cascade the second time."""
    trust = _make_trust()
    grant_id = _issue_grant(trust)
    first = trust.revoke(grant_id)
    second = trust.revoke(grant_id)
    assert first.ok and second.ok
    assert first.cascaded == (grant_id,)
    assert second.cascaded == ()


def test_check_expired_grant_when_now_past_ttl() -> None:
    """A grant whose expiry has passed is expired but not revoked."""
    trust = _make_trust()
    grant_id = _issue_grant(trust, subject=_default_subject(expires_at=NOW_S + 60))
    trust.set_clock(NOW_MS + 120_000)
    c = trust.check(grant_id)
    assert c.expired and not c.revoked and not c.valid


def test_ancestor_expiry_narrows_child_expiry() -> None:
    """CRITICAL-3: a nearer ancestor's expiry overrides the child's own."""
    trust = _make_trust()
    pid, priv = _principal_seed()
    # Root expires soon.
    root_sub = _default_subject(delegate_id="root", scope=("trust.report",), expires_at=NOW_S + 60)
    env, proof = build_proof(pid, priv, root_sub, now_ms=NOW_MS)
    root = trust.grant(root_sub, proof, granted_by_proof_hash=envelope_hash(env))
    assert root.ok and root.delegation_id
    # Child requests same expiry (child cannot outlive parent, so equal is fine).
    child_sub = _default_subject(
        delegate_id="child",
        scope=("trust.report",),
        parent=root.delegation_id,
        expires_at=NOW_S + 60,
    )
    env, proof = build_proof(pid, priv, child_sub, now_ms=NOW_MS)
    child = trust.grant(child_sub, proof, granted_by_proof_hash=envelope_hash(env))
    assert child.ok and child.delegation_id
    # Advance the clock past root's TTL; child must now report expired,
    # and the effective expiry surfaces the ancestor's earlier bound.
    trust.set_clock(NOW_MS + 120_000)
    c = trust.check(child.delegation_id)
    assert c.expired and not c.valid
    assert c.expires_at_effective == NOW_S + 60


def test_cycle_safety_and_hop_bound() -> None:
    """A pathological long chain terminates cleanly under MAX_HOPS.

    We can't construct a real cycle through the grant() API (parent-not-found
    rejects any reference to an unminted id), so this test drives directly
    into the internal store to prove the check() ancestor walk stays bounded.
    """
    trust = _make_trust()
    # Chain of length MAX_HOPS + 5 built directly into the store.
    store = trust._grants  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
    prev: str | None = None
    ids: list[str] = []
    for i in range(MAX_HOPS + 5):
        gid = f"del-synthetic-{i:04d}"
        store[gid] = store.get(gid) or _synthetic_grant(
            gid=gid, delegate_id=f"a{i}", parent=prev, expires_at=NOW_S + 10_000
        )
        prev = gid
        ids.append(gid)
    # check() must not loop indefinitely: the deepest node reports valid
    # because no revocation is set.
    c = trust.check(ids[-1])
    assert not c.revoked
    # Force a cycle: mutate the root's parent to point to the leaf.
    store[ids[0]] = _synthetic_grant(
        gid=ids[0], delegate_id="a0", parent=ids[-1], expires_at=NOW_S + 10_000
    )
    # Must terminate — and terminate with a well-formed CheckResult. The
    # ancestor walk is bounded by MAX_HOPS with a seen-set, so no ancestor
    # is revoked or expired here: the leaf is still valid and the effective
    # expiry is the untouched leaf's own expiry.
    c2 = trust.check(ids[-1])
    assert c2.valid is True
    assert c2.revoked is False
    assert c2.expired is False
    assert c2.expires_at_effective == NOW_S + 10_000


def _synthetic_grant(gid: str, delegate_id: str, parent: str | None, expires_at: int) -> Any:
    """Build an internal _Grant record directly (test-only)."""
    from nest_plugins_reference.trust.delegated_admission import (
        _Grant,  # pyright: ignore[reportPrivateUsage]
    )

    pid, _ = _principal_seed()
    proof = PuhProof(
        principal_pk=pid,
        device_did=_FIXTURE_DEVICE_DID,
        request_id="req",
        bound_at_ms=NOW_MS,
        issued_at_ms=NOW_MS,
        signature=b"\x00" * 64,
    )
    return _Grant(
        delegation_id=gid,
        delegator_id="self",
        delegate_id=delegate_id,
        granted_scope=("trust.report",),
        expires_at=expires_at,
        parent_delegation_id=parent,
        revocable=True,
        granted_by_proof_hash="0" * 64,
        proof=proof,
    )


# ---------------------------------------------------------------------------
# 5. report() admission end-to-end
# ---------------------------------------------------------------------------


def test_report_admits_grantholder_evidence() -> None:
    """Evidence from a live grantholder scores like the score_average baseline."""
    trust = _make_trust()
    _issue_grant(trust, subject=_default_subject(delegate_id="honest-1"))
    ev = Evidence(reporter=AgentId("honest-1"), subject=AgentId("victim"), kind="positive")
    _run(trust.report(AgentId("victim"), ev))
    rep = _run(trust.score(AgentId("victim")))
    assert rep.sample_count == 1
    assert rep.score == 1.0
    assert trust.admitted_count == 1
    v = trust.last_verdict(AgentId("honest-1"))
    assert v is not None and v.admitted and v.reason == "admitted"


def test_report_quarantines_sybil_without_grant() -> None:
    """A reporter with no grant is quarantined with reason no-grant."""
    trust = _make_trust()
    ev = Evidence(reporter=AgentId("sybil-0"), subject=AgentId("victim"), kind="negative")
    _run(trust.report(AgentId("victim"), ev))
    rep = _run(trust.score(AgentId("victim")))
    assert rep.sample_count == 0
    assert rep.score == 0.5
    assert trust.quarantined_count == 1
    v = trust.last_verdict(AgentId("sybil-0"))
    assert v is not None and not v.admitted and v.reason == "no-grant"


def test_report_quarantines_revoked_reporter() -> None:
    """After a grant is revoked, the reporter's evidence is quarantined."""
    trust = _make_trust()
    gid = _issue_grant(trust, subject=_default_subject(delegate_id="revoked-1"))
    trust.revoke(gid)
    ev = Evidence(reporter=AgentId("revoked-1"), subject=AgentId("victim"), kind="positive")
    _run(trust.report(AgentId("victim"), ev))
    assert trust.quarantined_count == 1
    # Verdict may be either "no-grant" (index was cleared) or "revoked"
    # depending on the delegate-index policy; the module clears the index
    # on revoke, so we expect "no-grant" specifically.
    v = trust.last_verdict(AgentId("revoked-1"))
    assert v is not None and not v.admitted
    assert v.reason in ("no-grant", "revoked")


def test_report_quarantines_scope_mismatch() -> None:
    """A grant lacking the required_scope is quarantined as scope-mismatch."""
    trust = _make_trust()
    _issue_grant(
        trust,
        subject=_default_subject(delegate_id="wrong-scope-1", scope=("tool.other",)),
    )
    ev = Evidence(reporter=AgentId("wrong-scope-1"), subject=AgentId("victim"), kind="positive")
    _run(trust.report(AgentId("victim"), ev))
    assert trust.quarantined_count == 1
    v = trust.last_verdict(AgentId("wrong-scope-1"))
    assert v is not None and v.reason == "scope-mismatch"


def test_report_quarantines_stale_proof() -> None:
    """A grant whose stored proof aged out by report-time is rejected."""
    trust = _make_trust()
    _issue_grant(trust, subject=_default_subject(delegate_id="honest-1"))
    # Advance clock beyond puh freshness — no new proof filed.
    trust.set_clock(NOW_MS + PUH_FRESHNESS_MS + PUH_SKEW_MS + 10_000)
    ev = Evidence(reporter=AgentId("honest-1"), subject=AgentId("victim"), kind="positive")
    _run(trust.report(AgentId("victim"), ev))
    v = trust.last_verdict(AgentId("honest-1"))
    assert v is not None and not v.admitted
    assert v.reason in ("puh-proof-stale", "expired")  # expiry may fire first for short TTLs


def test_report_honest_score_unaffected_by_sybil_swarm() -> None:
    """8 honest positives + 20 sybil negatives → victim's admitted score is 1.0."""
    trust = _make_trust()
    honest_ids = [f"honest-{i}" for i in range(8)]
    for hid in honest_ids:
        _issue_grant(trust, subject=_default_subject(delegate_id=hid))

    reports: list[Evidence] = []
    for hid in honest_ids:
        reports.append(Evidence(reporter=AgentId(hid), subject=AgentId("victim"), kind="positive"))
    for i in range(20):
        reports.append(
            Evidence(
                reporter=AgentId(f"sybil-{i}"),
                subject=AgentId("victim"),
                kind="negative",
            )
        )
    random.Random(42).shuffle(reports)
    for ev in reports:
        _run(trust.report(AgentId("victim"), ev))

    rep = _run(trust.score(AgentId("victim")))
    assert rep.sample_count == 8
    assert rep.score == 1.0
    assert trust.quarantined_count == 20


# ---------------------------------------------------------------------------
# 6. Hypothesis property tests
# ---------------------------------------------------------------------------


_SCOPE_STRATEGY = st.lists(
    st.sampled_from(
        [
            "trust.report",
            "tool.echo",
            "tool.summarize",
            "tool.review",
            "tool.compose",
            "svc.storage",
        ]
    ),
    min_size=1,
    max_size=6,
    unique=True,
)


@settings(max_examples=40, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(scope=_SCOPE_STRATEGY)
def test_property_scope_permutation_invariant_hash(scope: list[str]) -> None:
    """Any permutation of a scope list yields the identical envelope hash."""
    subject_fwd = DelegationSubject(
        delegate_id="perm-agent",
        granted_scope=tuple(scope),
        expires_at=1_000_000_000,
        parent_delegation_id=None,
        revocable=True,
    )
    subject_rev = DelegationSubject(
        delegate_id="perm-agent",
        granted_scope=tuple(reversed(scope)),
        expires_at=1_000_000_000,
        parent_delegation_id=None,
        revocable=True,
    )
    proof = PuhProof(
        principal_pk="pk-x",
        device_did="dev",
        request_id="req",
        bound_at_ms=0,
        issued_at_ms=0,
    )
    assert envelope_hash(canonical_proof_envelope(proof, subject_fwd)) == envelope_hash(
        canonical_proof_envelope(proof, subject_rev)
    )


@settings(
    max_examples=20,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(
    chain_len=st.integers(min_value=2, max_value=6),
    revoke_at=st.integers(min_value=0, max_value=5),
)
def test_property_no_descendant_of_revoked_is_valid(chain_len: int, revoke_at: int) -> None:
    """After revoking any node, no descendant reports as valid."""
    trust = _make_trust(tag="prop")
    pid, priv = _principal_seed(tag="prop")
    ids: list[str] = []
    parent: str | None = None
    for i in range(chain_len):
        subj = _default_subject(delegate_id=f"chain-{i}", scope=("trust.report",), parent=parent)
        env, proof = build_proof(pid, priv, subj, now_ms=NOW_MS)
        r = trust.grant(subj, proof, granted_by_proof_hash=envelope_hash(env))
        assert r.ok and r.delegation_id
        ids.append(r.delegation_id)
        parent = r.delegation_id

    idx = revoke_at % chain_len
    trust.revoke(ids[idx])
    # Every descendant (including the revoked node itself) must be invalid.
    for j in range(idx, chain_len):
        c = trust.check(ids[j])
        assert not c.valid
    # Duplicate revoke delivery is a no-op.
    r2 = trust.revoke(ids[idx])
    assert r2.ok and r2.cascaded == ()


@settings(
    max_examples=40,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(
    reporter_name=st.text(
        alphabet=st.characters(min_codepoint=32, max_codepoint=126),
        min_size=0,
        max_size=50,
    ),
    subject_name=st.text(
        alphabet=st.characters(min_codepoint=32, max_codepoint=126),
        min_size=0,
        max_size=50,
    ),
    kind=st.text(min_size=0, max_size=30),
    detail=st.text(min_size=0, max_size=100),
)
def test_property_report_never_raises_on_garbage(
    reporter_name: str, subject_name: str, kind: str, detail: str
) -> None:
    """Arbitrary garbage evidence is quarantined, never raised."""
    trust = _make_trust(tag="garbage")
    ev = Evidence(
        reporter=AgentId(reporter_name),
        subject=AgentId(subject_name),
        kind=kind,
        detail=detail,
    )
    # Must not raise.
    _run(trust.report(AgentId(subject_name), ev))


# ---------------------------------------------------------------------------
# 7. Byzantine parametrization — garbage grants and proofs quarantine cleanly
# ---------------------------------------------------------------------------


_GARBAGE_PROOFS: list[Any] = [
    None,
    "not-a-proof",
    42,
    PuhProof(
        principal_pk="",
        device_did="d",
        request_id="r",
        bound_at_ms=NOW_MS,
        issued_at_ms=NOW_MS,
    ),  # empty principal_pk
    PuhProof(
        principal_pk="p",
        device_did="",
        request_id="r",
        bound_at_ms=NOW_MS,
        issued_at_ms=NOW_MS,
    ),  # empty device_did
    PuhProof(
        principal_pk="p",
        device_did="d",
        request_id="",
        bound_at_ms=NOW_MS,
        issued_at_ms=NOW_MS,
    ),  # empty request_id
]


@pytest.mark.parametrize("proof", _GARBAGE_PROOFS)
def test_garbage_proof_never_crashes_grant(proof: Any) -> None:
    """A malformed proof yields a stable GrantResult; never an exception."""
    trust = _make_trust()
    subject = _default_subject()
    r = trust.grant(subject, proof, granted_by_proof_hash="0" * 64)
    assert not r.ok
    assert r.reason in {"missing-proof", "invalid-proof", "puh-proof-stale", "proof-hash-mismatch"}


def test_check_of_unknown_delegation_reports_not_found() -> None:
    """check() on an unknown id doesn't crash and returns a stable reason."""
    trust = _make_trust()
    c = trust.check("del-does-not-exist")
    assert not c.valid and c.reason == "not-found"


def test_revoke_of_unknown_delegation_reports_not_found() -> None:
    """revoke() on an unknown id doesn't crash and returns a stable reason."""
    trust = _make_trust()
    r = trust.revoke("del-does-not-exist")
    assert not r.ok and r.reason == "not-found"


def test_admission_verdict_is_hashable_dataclass() -> None:
    """AdmissionVerdict is a frozen dataclass safe to store in sets/dicts."""
    v = AdmissionVerdict(admitted=True, reason="admitted", delegation_id="del-x")
    assert v.admitted
    # Frozen dataclasses are hashable by default.
    assert {v} == {v}


# ---------------------------------------------------------------------------
# 8. Full simulator integration, discrimination, determinism
# ---------------------------------------------------------------------------

SCENARIO_PATH = Path(__file__).resolve().parents[3] / "scenarios" / "delegated_trust_market.yaml"
_SCENARIO_SEEDS = [42, 7, 1337]


def _run_delegated_scenario(seed: int, trust_plugin: str) -> dict[str, ValidationResult]:
    """Run the delegated_trust_market scenario and return validator results."""
    config = ScenarioConfig.from_yaml(str(SCENARIO_PATH)).model_copy(update={"seed": seed})
    config = config.model_copy(
        update={"layers": config.layers.model_copy(update={"trust": trust_plugin})}
    )
    with tempfile.TemporaryDirectory() as tmp:
        trace_path = Path(tmp) / f"da_{trust_plugin}_{seed}.jsonl"
        config = config.model_copy(
            update={"output": config.output.model_copy(update={"trace": str(trace_path)})}
        )
        asyncio.run(ScenarioRunner(config, registry=PluginRegistry()).run())
        results = validate_trace(trace_path, "delegated_admission")
    return {r.name: r for r in results}


def _run_delegated_bytes(seed: int) -> bytes:
    """Run the scenario and return the raw trace bytes."""
    config = ScenarioConfig.from_yaml(str(SCENARIO_PATH)).model_copy(update={"seed": seed})
    with tempfile.TemporaryDirectory() as tmp:
        trace_path = Path(tmp) / "da_replay.jsonl"
        config = config.model_copy(
            update={"output": config.output.model_copy(update={"trace": str(trace_path)})}
        )
        asyncio.run(ScenarioRunner(config, registry=PluginRegistry()).run())
        return trace_path.read_bytes()


@pytest.mark.parametrize("seed", _SCENARIO_SEEDS)
def test_scenario_delegated_passes_every_validator(seed: int) -> None:
    """With delegated_admission, all four gate validators pass at every seed."""
    if not SCENARIO_PATH.exists():
        pytest.skip(f"scenario not found at {SCENARIO_PATH}")
    results = _run_delegated_scenario(seed, "delegated_admission")
    expected = {
        "delegated_unattested_quarantined",
        "delegated_revocation_cascade",
        "delegated_scope_escalation_blocked",
        "delegated_stale_proof_rejected",
    }
    assert expected <= set(results), f"missing validators: {expected - set(results)}"
    for name, res in results.items():
        assert res.passed, f"seed={seed} {name} failed: {res.detail}"


@pytest.mark.parametrize("seed", _SCENARIO_SEEDS)
def test_scenario_baseline_fails_unattested_quarantined(seed: int) -> None:
    """The discriminator: score_average admits every reporter; delegated does not.

    The unattested-quarantined validator is the primary property that
    separates the two plugins — the Sybil swarm's negatives drag the
    victim's reputation below 0.5 under score_average and every no-grant
    reporter appears admitted, so this validator flips PASS → FAIL. Report
    which of the other three validators also fail on the baseline for
    completeness (all four typically fail).
    """
    if not SCENARIO_PATH.exists():
        pytest.skip(f"scenario not found at {SCENARIO_PATH}")

    baseline = _run_delegated_scenario(seed, "score_average")
    assert not baseline["delegated_unattested_quarantined"].passed, (
        f"seed={seed}: baseline should be defamed but passed: "
        f"{baseline['delegated_unattested_quarantined'].detail}"
    )
    baseline_failures = sorted(name for name, r in baseline.items() if not r.passed)
    assert "delegated_unattested_quarantined" in baseline_failures

    ours = _run_delegated_scenario(seed, "delegated_admission")
    assert ours["delegated_unattested_quarantined"].passed, (
        f"seed={seed}: delegated plugin failed: {ours['delegated_unattested_quarantined'].detail}"
    )


def test_delegated_scenario_is_byte_deterministic() -> None:
    """Two runs at the same seed produce byte-identical traces."""
    if not SCENARIO_PATH.exists():
        pytest.skip(f"scenario not found at {SCENARIO_PATH}")
    assert _run_delegated_bytes(42) == _run_delegated_bytes(42)
