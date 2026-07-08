# SPDX-License-Identifier: Apache-2.0
"""Problem 04 tests: delegatable capability tokens."""

from __future__ import annotations

import json

import pytest
from nest_core.plugins import PluginRegistry
from nest_core.types import AgentId
from nest_plugins_reference.auth.delegatable import CapabilityError, DelegatableAuth
from nest_plugins_reference.validators.auth_delegation_validators import (
    CapabilityDelegationValidator,
)


def test_delegatable_auth_is_registered() -> None:
    cls = PluginRegistry().resolve("auth", "delegatable")
    assert cls is DelegatableAuth


def test_child_token_is_narrower_and_audience_bound() -> None:
    auth = DelegatableAuth(secret=b"secret")
    parent = auth.issue_root(
        subject="buyer",
        audience="market",
        scopes={"quote", "pay", "admin"},
        ttl_seconds=600,
        max_depth=2,
        now=100.0,
    )
    child = auth.delegate(
        parent,
        subject="broker",
        audience="escrow",
        scopes={"quote", "pay"},
        ttl_seconds=120,
        now=110.0,
    )

    verified = auth.verify_capability(
        child,
        audience="escrow",
        required_scopes={"quote"},
        now=111.0,
    )
    assert verified.subject == "broker"
    assert verified.parent_id == auth.inspect(parent).token_id
    assert verified.scopes == frozenset({"quote", "pay"})

    with pytest.raises(CapabilityError, match="audience"):
        auth.verify_capability(child, audience="market", now=111.0)
    with pytest.raises(CapabilityError, match="scope"):
        auth.verify_capability(child, audience="escrow", required_scopes={"admin"}, now=111.0)


def test_delegate_rejects_scope_escalation_and_longer_lifetime() -> None:
    auth = DelegatableAuth(secret=b"secret")
    parent = auth.issue_root(
        subject="buyer",
        audience="market",
        scopes={"quote"},
        ttl_seconds=60,
        max_depth=2,
        now=100.0,
    )
    with pytest.raises(CapabilityError, match="scope"):
        auth.delegate(parent, subject="broker", scopes={"quote", "pay"}, now=101.0)

    child = auth.delegate(parent, subject="broker", ttl_seconds=3600, now=110.0)
    assert auth.inspect(child).expires_at == auth.inspect(parent).expires_at


def test_depth_limit_and_cascading_revocation() -> None:
    auth = DelegatableAuth(secret=b"secret")
    root = auth.issue_root(
        subject="a0",
        audience="market",
        scopes={"quote"},
        ttl_seconds=600,
        max_depth=1,
        now=100.0,
    )
    child = auth.delegate(root, subject="a1", now=101.0)
    with pytest.raises(CapabilityError, match="delegation depth"):
        auth.delegate(child, subject="a2", now=102.0)

    revoked = auth.revoke_tree(root)
    assert auth.inspect(root).token_id in revoked
    assert auth.inspect(child).token_id in revoked
    with pytest.raises(CapabilityError, match="revoked"):
        auth.verify_capability(child, audience="market", now=103.0)


@pytest.mark.asyncio
async def test_auth_protocol_issue_verify_and_revoke() -> None:
    auth = DelegatableAuth(secret=b"secret")
    token = await auth.issue(AgentId("agent-a"), ["read", "write"])
    ctx = await auth.verify(token)
    assert ctx.subject == AgentId("agent-a")
    assert ctx.scopes == ["read", "write"]
    await auth.revoke(token)
    with pytest.raises(CapabilityError, match="revoked"):
        await auth.verify(token)


def test_validator_catches_adversarial_scenario() -> None:
    report = CapabilityDelegationValidator().validate_events(
        [
            {
                "kind": "root",
                "token": "root",
                "subject": "buyer",
                "audience": "market",
                "scopes": ["quote", "pay"],
            },
            {
                "kind": "delegate",
                "token": "root",
                "subject": "broker",
                "audience": "escrow",
                "scopes": ["quote"],
            },
            {
                "kind": "verify",
                "token": "broker",
                "audience": "escrow",
                "scopes": ["quote"],
            },
            {
                "kind": "verify",
                "token": "broker",
                "audience": "market",
                "expect": "audience",
            },
            {
                "kind": "delegate",
                "token": "broker",
                "subject": "rogue",
                "scopes": ["pay"],
                "expect": "scope",
            },
            {"kind": "revoke", "token": "root"},
            {
                "kind": "verify",
                "token": "broker",
                "audience": "escrow",
                "expect": "revoked",
            },
        ]
    )
    assert report.passed, report.detail


def test_adversarial_rejects_nan_ttl() -> None:
    """NaN or Infinity ttl_seconds must be rejected (CVE-style float abuse)."""
    auth = DelegatableAuth(secret=b"secret")
    with pytest.raises(CapabilityError, match="finite"):
        auth.issue_root(
            subject="buyer",
            audience="market",
            scopes={"read"},
            ttl_seconds=float("nan"),
            max_depth=1,
            now=100.0,
        )
    with pytest.raises(CapabilityError, match="finite"):
        auth.issue_root(
            subject="buyer",
            audience="market",
            scopes={"read"},
            ttl_seconds=float("inf"),
            max_depth=1,
            now=100.0,
        )


def test_adversarial_rejects_wrong_issuer() -> None:
    """Token with tampered issuer field must fail decode."""
    auth = DelegatableAuth(secret=b"secret", issuer="nandatown")
    token = auth.issue_root(
        subject="buyer",
        audience="market",
        scopes={"read"},
        ttl_seconds=60,
        max_depth=1,
        now=100.0,
    )
    # Craft a token with mismatched issuer
    decoded = auth.inspect(token)
    payload = decoded.payload()
    forged = {**payload, "iss": "attacker", "sig": decoded.signature}
    forged_token = json.dumps(forged, sort_keys=True, separators=(",", ":"))
    with pytest.raises(CapabilityError, match="issuer mismatch"):
        auth.verify_capability(forged_token, now=101.0)


def test_adversarial_rejects_nan_in_decoded_token() -> None:
    """Directly crafted JSON with NaN/Inf expiry should fail decode."""
    auth = DelegatableAuth(secret=b"secret", issuer="nandatown")
    forged_payload = {
        "aud": "market",
        "depth": 0,
        "exp": float("nan"),
        "iat": 100.0,
        "iss": "nandatown",
        "jti": "deadbeef",
        "max_depth": 1,
        "parent": None,
        "scopes": ["read"],
        "sig": "00" * 32,
        "sub": "attacker",
    }
    forged_token = json.dumps(forged_payload, sort_keys=True, separators=(",", ":"))
    with pytest.raises(CapabilityError, match="finite"):
        auth.verify_capability(forged_token, now=101.0)


def test_revoke_tree_rejects_unknown_token() -> None:
    """revoke_tree with a tampered/unknown token must not revoke anything."""
    auth = DelegatableAuth(secret=b"secret", issuer="nandatown")
    root = auth.issue_root(
        subject="buyer",
        audience="market",
        scopes={"read"},
        ttl_seconds=60,
        max_depth=1,
        now=100.0,
    )
    child = auth.delegate(root, subject="broker", now=101.0)
    forged = root.replace(root[10], "F")
    with pytest.raises(CapabilityError, match="issuer mismatch|invalid capability signature"):
        auth.revoke_tree(forged)
    # Original tree must still be intact
    auth.verify_capability(child, audience="market", now=102.0)
    auth.verify_capability(root, audience="market", now=102.0)


def test_double_revoke_is_idempotent() -> None:
    """Revoking an already-revoked tree should be a no-op."""
    auth = DelegatableAuth(secret=b"secret", issuer="nandatown")
    root = auth.issue_root(
        subject="buyer",
        audience="market",
        scopes={"read"},
        ttl_seconds=60,
        max_depth=1,
        now=100.0,
    )
    first = auth.revoke_tree(root)
    second = auth.revoke_tree(root)
    assert second == first  # No new revocations
    with pytest.raises(CapabilityError, match="revoked"):
        auth.verify_capability(root, now=101.0)


def test_nan_rejected_in_delegate_child_ttl() -> None:
    """Delegation with NaN child ttl must be rejected."""
    auth = DelegatableAuth(secret=b"secret")
    parent = auth.issue_root(
        subject="buyer",
        audience="market",
        scopes={"read"},
        ttl_seconds=600,
        max_depth=2,
        now=100.0,
    )
    with pytest.raises(CapabilityError, match="finite"):
        auth.delegate(parent, subject="broker", ttl_seconds=float("nan"), now=110.0)
    with pytest.raises(CapabilityError, match="finite"):
        auth.delegate(parent, subject="broker", ttl_seconds=float("inf"), now=110.0)
    with pytest.raises(CapabilityError, match="positive|finite"):
        auth.delegate(parent, subject="broker", ttl_seconds=-1.0, now=110.0)
