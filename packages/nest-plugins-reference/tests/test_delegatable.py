# SPDX-License-Identifier: Apache-2.0
"""Unit tests for DelegatableAuth — delegatable capability tokens.

Covers: root-issue scope clamping, delegation subset, all three attacks
(scope escalation, revoked ancestor, audience mismatch), token tampering,
TTL enforcement, cascading revocation, protocol conformance, and plugin
registry resolution.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import cast

import pytest
from nest_core.layers.auth import Auth
from nest_core.plugins import PluginRegistry
from nest_core.types import AgentId, Token
from nest_plugins_reference.auth.delegatable import (
    AudienceMismatchError,
    DelegatableAuth,
    RevokedAncestorError,
    ScopeEscalationError,
    TtlExceededError,
)
from nest_plugins_reference.identity.ed25519_rotating import Ed25519RotatingIdentity
from nest_plugins_reference.policy import Budget, PolicyManifest, sign_manifest


def _ident(aid: str, seed: bytes = b"seed") -> Ed25519RotatingIdentity:
    return Ed25519RotatingIdentity(AgentId(aid), seed=seed)


def _manifest(aid: str, tools: list[str] | None = None, cap: int = 1000) -> PolicyManifest:
    ident = _ident(aid)
    m = PolicyManifest(
        agent_id=AgentId(aid),
        tools=tools or ["buy", "sell"],
        budget=Budget(cap=cap),
    )
    return sign_manifest(ident, m)


def _tamper_token_payload(token: Token, **updates: object) -> Token:
    payload_json, sig = str(token).rsplit("|", 1)
    payload = json.loads(payload_json)
    payload.update(updates)
    return Token(f"{json.dumps(payload, sort_keys=True)}|{sig}")


def _tamper_token_signature(token: Token) -> Token:
    payload_json, sig = str(token).rsplit("|", 1)
    replacement = "0" if sig[-1] != "0" else "1"
    return Token(f"{payload_json}|{sig[:-1]}{replacement}")


def _register_forged_child(auth: DelegatableAuth, parent: Token, scopes: list[str]) -> Token:
    parent_payload_json, parent_sig = str(parent).rsplit("|", 1)
    parent_data = json.loads(parent_payload_json)
    parent_tid = hashlib.sha256(parent_payload_json.encode()).hexdigest()
    forged_payload = json.dumps(
        {
            "aud": "a2",
            "chain": parent_data["chain"] + [parent_tid],
            "exp": parent_data["iat"] + 60.0,
            "iat": parent_data["iat"],
            "scopes": scopes,
            "sub": "a2",
        },
        sort_keys=True,
    )
    forged_sig = hmac.new(parent_sig.encode(), forged_payload.encode(), hashlib.sha256).hexdigest()
    forged_tid = hashlib.sha256(forged_payload.encode()).hexdigest()
    sigs = cast("dict[str, str]", object.__getattribute__(auth, "_sigs"))
    payloads = cast("dict[str, str]", object.__getattribute__(auth, "_payloads"))
    sigs[forged_tid] = forged_sig
    payloads[forged_tid] = forged_payload
    return Token(f"{forged_payload}|{forged_sig}")


# ---------------------------------------------------------------------------
# Root issuance
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_root_issue_clamps_to_manifest() -> None:
    """Scopes not in the manifest are dropped at issuance."""
    m = _manifest("a1", tools=["buy"])
    auth = DelegatableAuth(manifests={AgentId("a1"): m}, clock=0.0)
    token = await auth.issue(AgentId("a1"), ["tool:buy", "tool:admin", "tool:sell"])
    ctx = await auth.verify(token)
    assert ctx.scopes == ["tool:buy"]


@pytest.mark.asyncio
async def test_root_issue_clamps_tool_spend_and_expose_scopes() -> None:
    """Root issuance clamps all supported scope dimensions to the signed manifest."""
    ident = _ident("a1")
    signed = sign_manifest(
        ident,
        PolicyManifest(
            agent_id=AgentId("a1"),
            tools=["buy"],
            data={"pii": ["seller-1"]},
            budget=Budget(cap=500),
        ),
    )
    auth = DelegatableAuth(
        manifests={AgentId("a1"): signed},
        identities={AgentId("a1"): ident},
        clock=0.0,
    )
    token = await auth.issue(
        AgentId("a1"),
        [
            "tool:buy",
            "tool:admin",
            "spend:250",
            "spend:501",
            "expose:pii:seller-1",
            "expose:pii:seller-2",
            "expose:secret:seller-1",
            "expose:pii:",
        ],
    )

    ctx = await auth.verify(token, presenter=AgentId("a1"))
    assert ctx.scopes == ["tool:buy", "spend:250", "expose:pii:seller-1"]


@pytest.mark.asyncio
async def test_root_issue_no_manifest_gives_empty_scopes() -> None:
    """Subject with no manifest receives empty scopes (deny-all root)."""
    auth = DelegatableAuth(clock=0.0)
    token = await auth.issue(AgentId("unknown"), ["tool:buy"])
    ctx = await auth.verify(token)
    assert ctx.scopes == []


@pytest.mark.asyncio
async def test_root_issue_unsigned_manifest_gives_empty_scopes() -> None:
    """Unsigned manifests are deny-all, even when their content allows a tool."""
    manifest = PolicyManifest(agent_id=AgentId("a1"), tools=["buy"], budget=Budget(cap=1000))
    auth = DelegatableAuth(manifests={AgentId("a1"): manifest}, clock=0.0)
    token = await auth.issue(AgentId("a1"), ["tool:buy"])
    ctx = await auth.verify(token)
    assert ctx.scopes == []


@pytest.mark.asyncio
async def test_root_issue_tampered_manifest_gives_empty_scopes_when_identity_supplied() -> None:
    """A signed manifest widened after signing does not grant root authority."""
    ident = _ident("a1")
    signed = sign_manifest(
        ident,
        PolicyManifest(agent_id=AgentId("a1"), tools=["buy"], budget=Budget(cap=1000)),
    )
    tampered = signed.model_copy(update={"tools": ["buy", "admin"]})
    auth = DelegatableAuth(
        manifests={AgentId("a1"): tampered},
        identities={AgentId("a1"): ident},
        clock=0.0,
    )
    token = await auth.issue(AgentId("a1"), ["tool:admin"])
    ctx = await auth.verify(token)
    assert ctx.scopes == []


@pytest.mark.asyncio
async def test_root_issue_forged_manifest_gives_empty_scopes_when_identity_supplied() -> None:
    """A manifest signed by a different key for the same agent fails closed."""
    attacker = _ident("a1", seed=b"attacker-key")
    honest = _ident("a1")
    forged = sign_manifest(
        attacker,
        PolicyManifest(agent_id=AgentId("a1"), tools=["admin"], budget=Budget(cap=1000)),
    )
    auth = DelegatableAuth(
        manifests={AgentId("a1"): forged},
        identities={AgentId("a1"): honest},
        clock=0.0,
    )
    token = await auth.issue(AgentId("a1"), ["tool:admin"])
    ctx = await auth.verify(token)
    assert ctx.scopes == []


@pytest.mark.asyncio
async def test_root_issue_deduplicates_scopes() -> None:
    """Duplicate scopes are removed; first occurrence is kept."""
    m = _manifest("a1", tools=["buy"])
    auth = DelegatableAuth(manifests={AgentId("a1"): m}, clock=0.0)
    token = await auth.issue(AgentId("a1"), ["tool:buy", "tool:buy", "tool:buy"])
    ctx = await auth.verify(token)
    assert ctx.scopes == ["tool:buy"]


# ---------------------------------------------------------------------------
# Delegation — happy path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_delegate_subset_ok() -> None:
    """Delegating a subset of parent scopes succeeds; child has only those scopes."""
    m = _manifest("a1", tools=["buy", "sell"])
    auth = DelegatableAuth(manifests={AgentId("a1"): m}, clock=0.0)
    root = await auth.issue(AgentId("a1"), ["tool:buy", "tool:sell"])
    child = await auth.delegate(root, AgentId("a2"), ["tool:buy"], ttl=300)
    ctx = await auth.verify(child, presenter=AgentId("a2"))
    assert ctx.scopes == ["tool:buy"]
    assert "tool:sell" not in ctx.scopes


@pytest.mark.asyncio
async def test_delegate_chain_expiry_within_parent() -> None:
    """Child expiry is correctly set to now + ttl."""
    m = _manifest("a1")
    auth = DelegatableAuth(manifests={AgentId("a1"): m}, clock=0.0)
    root = await auth.issue(AgentId("a1"), ["tool:buy", "tool:sell"])
    child = await auth.delegate(root, AgentId("a2"), ["tool:buy"], ttl=120)
    ctx = await auth.verify(child, presenter=AgentId("a2"))
    assert ctx.expires_at == pytest.approx(120.0)


# ---------------------------------------------------------------------------
# Attack 1: Scope escalation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scope_escalation_raises() -> None:
    """Requesting scopes outside the parent raises ScopeEscalationError."""
    m = _manifest("a1", tools=["buy"])
    auth = DelegatableAuth(manifests={AgentId("a1"): m}, clock=0.0)
    root = await auth.issue(AgentId("a1"), ["tool:buy"])
    with pytest.raises(ScopeEscalationError) as exc_info:
        await auth.delegate(root, AgentId("a2"), ["tool:buy", "tool:admin"], ttl=60)
    assert "tool:admin" in exc_info.value.offending


@pytest.mark.asyncio
async def test_equal_scope_delegation_raises() -> None:
    """Delegation must narrow authority; equal-scope child tokens are rejected."""
    m = _manifest("a1", tools=["buy"])
    auth = DelegatableAuth(manifests={AgentId("a1"): m}, clock=0.0)
    root = await auth.issue(AgentId("a1"), ["tool:buy"])
    with pytest.raises(ScopeEscalationError) as exc_info:
        await auth.delegate(root, AgentId("a2"), ["tool:buy"], ttl=60)
    assert exc_info.value.offending == ["tool:buy"]


@pytest.mark.asyncio
async def test_handcrafted_child_token_rejected_even_with_valid_parent_hmac() -> None:
    """A holder cannot bypass delegate() by signing a broader child payload."""
    m = _manifest("a1", tools=["buy"])
    auth = DelegatableAuth(manifests={AgentId("a1"): m}, clock=0.0)
    root = await auth.issue(AgentId("a1"), ["tool:buy"])
    parent_payload, parent_sig = str(root).rsplit("|", 1)
    parent_tid = hashlib.sha256(parent_payload.encode()).hexdigest()
    forged_payload = json.dumps(
        {
            "aud": "a2",
            "chain": [parent_tid],
            "exp": 60.0,
            "iat": 0.0,
            "scopes": ["tool:admin"],
            "sub": "a2",
        },
        sort_keys=True,
    )
    forged_sig = hmac.new(parent_sig.encode(), forged_payload.encode(), hashlib.sha256).hexdigest()
    forged = Token(f"{forged_payload}|{forged_sig}")

    with pytest.raises(ValueError, match="unknown token"):
        await auth.verify(forged, presenter=AgentId("a2"))


# ---------------------------------------------------------------------------
# Attack 2: Cascading revocation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cascading_revocation() -> None:
    """Revoking the root makes child and grandchild verify raise RevokedAncestorError."""
    m = _manifest("a1", tools=["buy", "sell", "query"])
    auth = DelegatableAuth(manifests={AgentId("a1"): m}, clock=0.0)
    root = await auth.issue(AgentId("a1"), ["tool:buy", "tool:sell", "tool:query"])
    child = await auth.delegate(root, AgentId("a2"), ["tool:buy", "tool:sell"], ttl=1800)
    grandchild = await auth.delegate(child, AgentId("a3"), ["tool:buy"], ttl=900)

    await auth.revoke(root)

    with pytest.raises(RevokedAncestorError):
        await auth.verify(child)

    with pytest.raises(RevokedAncestorError):
        await auth.verify(grandchild)


@pytest.mark.asyncio
async def test_revoke_child_not_root() -> None:
    """Revoking a child token does not affect the root, but grandchild fails."""
    m = _manifest("a1", tools=["buy", "sell", "query"])
    auth = DelegatableAuth(manifests={AgentId("a1"): m}, clock=0.0)
    root = await auth.issue(AgentId("a1"), ["tool:buy", "tool:sell", "tool:query"])
    child = await auth.delegate(root, AgentId("a2"), ["tool:buy", "tool:sell"], ttl=1800)
    grandchild = await auth.delegate(child, AgentId("a3"), ["tool:buy"], ttl=900)

    await auth.revoke(child)

    # Root still valid
    ctx = await auth.verify(root)
    assert "tool:buy" in ctx.scopes

    # Child and grandchild fail
    with pytest.raises(RevokedAncestorError):
        await auth.verify(child)

    with pytest.raises(RevokedAncestorError):
        await auth.verify(grandchild)


# ---------------------------------------------------------------------------
# Attack 3: Audience mismatch
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_audience_mismatch_raises() -> None:
    """Verifying with the wrong presenter raises AudienceMismatchError."""
    m = _manifest("a1")
    auth = DelegatableAuth(manifests={AgentId("a1"): m}, clock=0.0)
    root = await auth.issue(AgentId("a1"), ["tool:buy", "tool:sell"])
    child = await auth.delegate(root, AgentId("a2"), ["tool:buy"], ttl=300)

    with pytest.raises(AudienceMismatchError):
        await auth.verify(child, presenter=AgentId("wrong-agent"))


@pytest.mark.asyncio
async def test_audience_match_ok() -> None:
    """Verifying with the correct presenter succeeds."""
    m = _manifest("a1")
    auth = DelegatableAuth(manifests={AgentId("a1"): m}, clock=0.0)
    root = await auth.issue(AgentId("a1"), ["tool:buy", "tool:sell"])
    child = await auth.delegate(root, AgentId("a2"), ["tool:buy"], ttl=300)
    ctx = await auth.verify(child, presenter=AgentId("a2"))
    assert ctx.subject == AgentId("a2")


@pytest.mark.asyncio
async def test_verify_root_no_presenter() -> None:
    """Omitting presenter skips the audience check."""
    m = _manifest("a1")
    auth = DelegatableAuth(manifests={AgentId("a1"): m}, clock=0.0)
    root = await auth.issue(AgentId("a1"), ["tool:buy"])
    ctx = await auth.verify(root)
    assert ctx.subject == AgentId("a1")


@pytest.mark.asyncio
async def test_root_audience_mismatch_raises() -> None:
    """Root tokens are audience-bound when a presenter is supplied."""
    m = _manifest("a1")
    auth = DelegatableAuth(manifests={AgentId("a1"): m}, clock=0.0)
    root = await auth.issue(AgentId("a1"), ["tool:buy"])

    with pytest.raises(AudienceMismatchError):
        await auth.verify(root, presenter=AgentId("wrong-agent"))


# ---------------------------------------------------------------------------
# Token integrity
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("aud", "a3"),
        ("exp", 9999.0),
        ("chain", ["unknown-parent"]),
        ("scopes", ["tool:buy", "tool:admin"]),
    ],
)
async def test_tampered_payload_rejected(field: str, value: object) -> None:
    """Changing signed payload fields while keeping the old signature is rejected."""
    m = _manifest("a1", tools=["buy", "sell"])
    auth = DelegatableAuth(manifests={AgentId("a1"): m}, clock=0.0)
    root = await auth.issue(AgentId("a1"), ["tool:buy", "tool:sell"])
    child = await auth.delegate(root, AgentId("a2"), ["tool:buy"], ttl=300)

    tampered = _tamper_token_payload(child, **{field: value})

    with pytest.raises(ValueError):
        await auth.verify(tampered, presenter=AgentId("a2"))


@pytest.mark.asyncio
async def test_tampered_signature_rejected() -> None:
    """Changing only the signature on a known token is rejected."""
    m = _manifest("a1")
    auth = DelegatableAuth(manifests={AgentId("a1"): m}, clock=0.0)
    root = await auth.issue(AgentId("a1"), ["tool:buy"])

    with pytest.raises(ValueError, match="invalid signature"):
        await auth.verify(_tamper_token_signature(root), presenter=AgentId("a1"))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "forged_scopes",
    [
        ["tool:buy", "tool:sell"],
        ["tool:admin"],
    ],
)
async def test_registered_forged_child_rechecked_by_verify(forged_scopes: list[str]) -> None:
    """Verifier rejects registered children that violate delegation caveats."""
    m = _manifest("a1", tools=["buy", "sell"])
    auth = DelegatableAuth(manifests={AgentId("a1"): m}, clock=0.0)
    root = await auth.issue(AgentId("a1"), ["tool:buy", "tool:sell"])
    forged = _register_forged_child(auth, root, forged_scopes)

    with pytest.raises(ScopeEscalationError):
        await auth.verify(forged, presenter=AgentId("a2"))


@pytest.mark.asyncio
async def test_invalid_token_format_rejected() -> None:
    """A token without the payload/signature separator is malformed."""
    auth = DelegatableAuth(clock=0.0)
    with pytest.raises(ValueError, match="invalid token format"):
        await auth.verify(Token("not-a-token"))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "raw_token",
    [
        "not-json|sig",
        "{}|sig",
        "[]|sig",
        '{"aud":"a1","chain":[],"exp":1,"iat":0,"scopes":[],"sub":"a2"}|sig',
        '{"aud":"a1","chain":"root","exp":1,"iat":0,"scopes":[],"sub":"a1"}|sig',
        '{"aud":"a1","chain":[],"exp":"never","iat":0,"scopes":[],"sub":"a1"}|sig',
        '{"aud":"a1","chain":[],"exp":NaN,"iat":0,"scopes":[],"sub":"a1"}|sig',
        '{"aud":"a1","chain":[],"exp":0,"iat":1,"scopes":[],"sub":"a1"}|sig',
        '{"aud":"a1","chain":[],"exp":1,"iat":0,"scopes":"tool:buy","sub":"a1"}|sig',
    ],
)
async def test_malformed_token_payload_rejected_fail_closed(raw_token: str) -> None:
    """Malformed payloads raise ValueError before any authority is accepted."""
    auth = DelegatableAuth(clock=0.0)
    with pytest.raises(ValueError, match="invalid token payload"):
        await auth.verify(Token(raw_token))


def test_non_finite_injected_clock_rejected() -> None:
    """Injected clocks must be finite so issued expiries stay meaningful."""
    with pytest.raises(ValueError, match="clock must be finite"):
        DelegatableAuth(clock=float("nan"))


# ---------------------------------------------------------------------------
# TTL enforcement
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ttl_exceeds_parent_raises() -> None:
    """TTL that would make child expire after parent raises TtlExceededError."""
    m = _manifest("a1")
    auth = DelegatableAuth(manifests={AgentId("a1"): m}, clock=0.0)
    root = await auth.issue(AgentId("a1"), ["tool:buy", "tool:sell"])
    # root expires at 3600; requesting ttl=3601 exceeds it
    with pytest.raises(TtlExceededError):
        await auth.delegate(root, AgentId("a2"), ["tool:buy"], ttl=3601)


@pytest.mark.asyncio
@pytest.mark.parametrize("ttl", [0.0, -1.0, float("nan"), float("inf")])
async def test_invalid_ttl_rejected(ttl: float) -> None:
    """TTL must be finite and positive; NaN must not become a never-expiring token."""
    m = _manifest("a1", tools=["buy", "sell"])
    auth = DelegatableAuth(manifests={AgentId("a1"): m}, clock=0.0)
    root = await auth.issue(AgentId("a1"), ["tool:buy", "tool:sell"])

    with pytest.raises(ValueError, match="ttl must be a finite positive number"):
        await auth.delegate(root, AgentId("a2"), ["tool:buy"], ttl=ttl)


@pytest.mark.asyncio
async def test_ttl_at_parent_boundary_allowed() -> None:
    """TTL exactly equal to parent remaining lifetime is allowed (check is strict >).

    child_exp = now + ttl = 0 + 3600 = 3600 == parent_exp → child_exp > parent_exp
    is False, so the exact boundary is permitted.
    """
    m = _manifest("a1")
    auth = DelegatableAuth(manifests={AgentId("a1"): m}, clock=0.0)
    root = await auth.issue(AgentId("a1"), ["tool:buy", "tool:sell"])
    # child_exp == parent_exp is exactly equal — the check is >, so this is allowed
    child = await auth.delegate(root, AgentId("a2"), ["tool:buy"], ttl=3600)
    ctx = await auth.verify(child, presenter=AgentId("a2"))
    assert ctx.expires_at == pytest.approx(3600.0)


@pytest.mark.asyncio
async def test_expired_token_rejected_on_verify() -> None:
    """A token cannot be verified after its exp timestamp."""
    m = _manifest("a1")
    auth = DelegatableAuth(manifests={AgentId("a1"): m}, clock=0.0)
    root = await auth.issue(AgentId("a1"), ["tool:buy"])
    auth.set_clock(3600.001)

    with pytest.raises(ValueError, match="expired"):
        await auth.verify(root, presenter=AgentId("a1"))


# ---------------------------------------------------------------------------
# Revoked / expired parent cannot be delegated from
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_revoked_parent_cannot_be_delegated() -> None:
    """Delegating from a revoked parent propagates the revocation error."""
    m = _manifest("a1")
    auth = DelegatableAuth(manifests={AgentId("a1"): m}, clock=0.0)
    root = await auth.issue(AgentId("a1"), ["tool:buy"])
    await auth.revoke(root)
    with pytest.raises(RevokedAncestorError):
        await auth.delegate(root, AgentId("a2"), ["tool:buy"], ttl=60)


@pytest.mark.asyncio
async def test_expired_parent_cannot_be_delegated() -> None:
    """Delegating from an expired parent propagates the expiry error."""
    m = _manifest("a1")
    auth = DelegatableAuth(manifests={AgentId("a1"): m}, clock=0.0)
    root = await auth.issue(AgentId("a1"), ["tool:buy"])
    # Advance clock past root expiry
    auth.set_clock(4000.0)
    with pytest.raises(ValueError, match="expired"):
        await auth.delegate(root, AgentId("a2"), ["tool:buy"], ttl=60)


# ---------------------------------------------------------------------------
# Protocol conformance
# ---------------------------------------------------------------------------


def test_isinstance_auth_protocol() -> None:
    """DelegatableAuth satisfies the Auth runtime-checkable protocol."""
    assert isinstance(DelegatableAuth(), Auth)


# ---------------------------------------------------------------------------
# Plugin registry resolution
# ---------------------------------------------------------------------------


def test_resolvable_via_plugin_registry() -> None:
    """DelegatableAuth is resolvable as ('auth', 'delegatable') via PluginRegistry."""
    cls = PluginRegistry().resolve("auth", "delegatable")
    assert cls is DelegatableAuth
