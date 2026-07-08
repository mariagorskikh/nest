# SPDX-License-Identifier: Apache-2.0
"""Tests for delegatable Auth tokens with cascading revocation."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any, cast

import pytest
from nest_core.layers.auth import Auth
from nest_core.plugins import PluginRegistry
from nest_core.types import AgentId, Token
from nest_plugins_reference.auth import delegatable as delegatable_module
from nest_plugins_reference.auth.delegatable import (
    AudienceMismatchError,
    DelegatableAuth,
    DelegationError,
    ExpiredAncestorError,
    MalformedTokenError,
    RevokedAncestorError,
    ScopeEscalationError,
    TtlEscalationError,
    scope_covers,
)


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _decode(token: Token) -> dict[str, Any]:
    encoded = str(token).split(".", 1)[1]
    padded = encoded + "=" * (-len(encoded) % 4)
    data: Any = json.loads(base64.urlsafe_b64decode(padded.encode()))
    assert isinstance(data, dict)
    return cast("dict[str, Any]", data)


def _encode(data: dict[str, Any]) -> Token:
    raw = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    encoded = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    return Token(f"ndcap1.{encoded}")


def _segment_id(segment: dict[str, Any]) -> str:
    claims = cast("dict[str, Any]", segment["claims"])
    payload = _canonical(claims) + b"." + str(segment["sig"]).encode()
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _append_forged_child(parent: Token, claims: dict[str, Any]) -> Token:
    data = _decode(parent)
    chain = data["chain"]
    assert isinstance(chain, list)
    chain_values = cast("list[Any]", chain)
    parent_segment_obj = chain_values[-1]
    assert isinstance(parent_segment_obj, dict)
    parent_segment = cast("dict[str, Any]", parent_segment_obj)
    parent_claims = cast("dict[str, Any]", parent_segment["claims"])
    claims["pid"] = _segment_id(parent_segment)
    claims["depth"] = int(parent_claims["depth"]) + 1
    key = bytes.fromhex(str(parent_segment["sig"]))
    child = {"claims": claims, "sig": hmac.new(key, _canonical(claims), hashlib.sha256).hexdigest()}
    return _encode({"chain": [*chain, child]})


@pytest.mark.asyncio
async def test_satisfies_auth_protocol() -> None:
    assert isinstance(DelegatableAuth(clock=0.0), Auth)


@pytest.mark.asyncio
async def test_default_clock_uses_current_time(monkeypatch: pytest.MonkeyPatch) -> None:
    now = 100.0
    monkeypatch.setattr(delegatable_module.time, "time", lambda: now)
    auth = DelegatableAuth()
    root = await auth.issue(AgentId("coordinator-0"), ["scribe:*"])

    await auth.verify(root)
    now = 3701.0

    with pytest.raises(ExpiredAncestorError):
        await auth.verify(root)


@pytest.mark.asyncio
async def test_delegates_strictly_narrower_scopes() -> None:
    auth = DelegatableAuth(clock=0.0)
    root = await auth.issue(AgentId("coordinator-0"), ["efs.write:/agents/*", "scribe:verify"])

    child = await auth.delegate(
        root,
        audience=AgentId("leaf-0"),
        scopes_subset=["efs.write:/agents/leaf-0/*", "scribe:verify"],
        ttl=10.0,
    )
    ctx = await auth.verify_for(child, AgentId("leaf-0"))

    assert ctx.subject == AgentId("leaf-0")
    assert ctx.scopes == ["efs.write:/agents/leaf-0/*", "scribe:verify"]
    assert ctx.expires_at == 10.0


@pytest.mark.asyncio
async def test_rejects_scope_escalation() -> None:
    auth = DelegatableAuth(clock=0.0)
    parent = await auth.issue(AgentId("coordinator-0"), ["efs.write:/agents/a/*"])

    with pytest.raises(ScopeEscalationError):
        await auth.delegate(
            parent,
            audience=AgentId("leaf-0"),
            scopes_subset=["efs.write:/agents/b/*"],
            ttl=10.0,
        )


@pytest.mark.parametrize(
    "bad_scope",
    [
        "efs.write:/agents/../private/*",
        "efs.write:/agents/./leaf-0/*",
        "efs.write:/agents//leaf-0/*",
        "efs.write:",
        "efs.write:/",
        "efs.write:agents/leaf-0/*",
        "efs.write:/agents/leaf-0/*/report.json",
        "efs.write:/agents/leaf-0*",
        "efs.write:/agents/%2e%2e/private/*",
    ],
)
@pytest.mark.asyncio
async def test_delegation_rejects_malformed_efs_scope_paths(bad_scope: str) -> None:
    auth = DelegatableAuth(clock=0.0)
    parent = await auth.issue(AgentId("coordinator-0"), ["efs.write:/agents/*"])

    with pytest.raises(ScopeEscalationError, match="Malformed efs.write scope path"):
        await auth.delegate(
            parent,
            audience=AgentId("leaf-0"),
            scopes_subset=[bad_scope],
            ttl=10.0,
        )


@pytest.mark.asyncio
async def test_verify_rejects_manually_forged_scope_escalation() -> None:
    auth = DelegatableAuth(clock=0.0)
    parent = await auth.issue(AgentId("coordinator-0"), ["efs.write:/agents/a/*"])
    forged = _append_forged_child(
        parent,
        {
            "aud": "attacker-0",
            "exp": 10.0,
            "iat": 0.0,
            "scp": ["efs.write:/private/*"],
            "sub": "attacker-0",
        },
    )

    with pytest.raises(ScopeEscalationError):
        await auth.verify(forged)


@pytest.mark.parametrize(
    "bad_scope",
    [
        "efs.write:/agents/../private/*",
        "efs.write:/agents//leaf-0/*",
        "efs.write:/",
    ],
)
@pytest.mark.asyncio
async def test_verify_rejects_forged_malformed_efs_scope_paths(bad_scope: str) -> None:
    auth = DelegatableAuth(clock=0.0)
    parent = await auth.issue(AgentId("coordinator-0"), ["efs.write:/agents/*"])
    forged = _append_forged_child(
        parent,
        {
            "aud": "leaf-0",
            "exp": 10.0,
            "iat": 0.0,
            "scp": [bad_scope],
            "sub": "leaf-0",
        },
    )

    with pytest.raises(ScopeEscalationError, match="Malformed efs.write scope path"):
        await auth.verify(forged)


@pytest.mark.asyncio
async def test_verify_rejects_manually_forged_ttl_escalation() -> None:
    auth = DelegatableAuth(clock=0.0)
    parent = await auth.issue(AgentId("coordinator-0"), ["efs.write:/agents/*"])
    forged = _append_forged_child(
        parent,
        {
            "aud": "leaf-0",
            "exp": 7200.0,
            "iat": 0.0,
            "scp": ["efs.write:/agents/leaf-0/*"],
            "sub": "leaf-0",
        },
    )

    with pytest.raises(TtlEscalationError):
        await auth.verify(forged)


@pytest.mark.asyncio
async def test_verify_rejects_non_finite_timing_claims() -> None:
    auth = DelegatableAuth(clock=0.0)
    parent = await auth.issue(AgentId("coordinator-0"), ["efs.write:/agents/*"])
    forged = _append_forged_child(
        parent,
        {
            "aud": "leaf-0",
            "exp": float("nan"),
            "iat": 0.0,
            "scp": ["efs.write:/agents/leaf-0/*"],
            "sub": "leaf-0",
        },
    )

    with pytest.raises(MalformedTokenError):
        await auth.verify(forged)


@pytest.mark.asyncio
async def test_verify_rejects_issue_time_after_expiry() -> None:
    auth = DelegatableAuth(clock=0.0)
    parent = await auth.issue(AgentId("coordinator-0"), ["efs.write:/agents/*"])
    forged = _append_forged_child(
        parent,
        {
            "aud": "leaf-0",
            "exp": 10.0,
            "iat": 999.0,
            "scp": ["efs.write:/agents/leaf-0/*"],
            "sub": "leaf-0",
        },
    )

    with pytest.raises(TtlEscalationError):
        await auth.verify(forged)


@pytest.mark.asyncio
async def test_delegation_rejects_unchanged_wildcard_scope() -> None:
    auth = DelegatableAuth(clock=0.0)
    parent = await auth.issue(AgentId("coordinator-0"), ["efs.write:/agents/*", "scribe:*"])

    with pytest.raises(ScopeEscalationError):
        await auth.delegate(
            parent,
            audience=AgentId("leaf-0"),
            scopes_subset=["efs.write:/agents/*"],
            ttl=10.0,
        )


@pytest.mark.asyncio
async def test_verify_rejects_manually_forged_unchanged_wildcard_scope() -> None:
    auth = DelegatableAuth(clock=0.0)
    parent = await auth.issue(AgentId("coordinator-0"), ["efs.write:/agents/*", "scribe:*"])
    forged = _append_forged_child(
        parent,
        {
            "aud": "leaf-0",
            "exp": 10.0,
            "iat": 0.0,
            "scp": ["efs.write:/agents/*"],
            "sub": "leaf-0",
        },
    )

    with pytest.raises(ScopeEscalationError):
        await auth.verify(forged)


@pytest.mark.asyncio
async def test_expired_parent_invalidates_child() -> None:
    auth = DelegatableAuth(clock=0.0)
    parent = await auth.issue(AgentId("coordinator-0"), ["efs.write:/agents/*"])
    child = await auth.delegate(
        parent,
        audience=AgentId("leaf-0"),
        scopes_subset=["efs.write:/agents/leaf-0/*"],
        ttl=10.0,
    )

    auth.set_clock(11.0)

    with pytest.raises(ExpiredAncestorError):
        await auth.verify(child)


@pytest.mark.asyncio
async def test_malformed_chain_segments_raise_typed_error() -> None:
    auth = DelegatableAuth(clock=0.0)
    bad_segment = _encode({"chain": [None]})
    missing_claims = _encode({"chain": [{"sig": "00"}]})

    with pytest.raises(MalformedTokenError):
        await auth.verify(bad_segment)
    with pytest.raises(MalformedTokenError):
        await auth.verify(missing_claims)


@pytest.mark.asyncio
async def test_revoking_parent_invalidates_child() -> None:
    auth = DelegatableAuth(clock=0.0)
    parent = await auth.issue(AgentId("coordinator-0"), ["efs.write:/agents/*"])
    child = await auth.delegate(
        parent,
        audience=AgentId("leaf-0"),
        scopes_subset=["efs.write:/agents/leaf-0/*"],
        ttl=10.0,
    )

    await auth.revoke(parent)

    with pytest.raises(RevokedAncestorError):
        await auth.verify(child)


@pytest.mark.asyncio
async def test_verify_for_rejects_wrong_presenter() -> None:
    auth = DelegatableAuth(clock=0.0)
    parent = await auth.issue(AgentId("coordinator-0"), ["scribe:*"])
    child = await auth.delegate(
        parent,
        audience=AgentId("leaf-0"),
        scopes_subset=["scribe:verify"],
        ttl=10.0,
    )

    with pytest.raises(AudienceMismatchError):
        await auth.verify_for(child, AgentId("attacker-0"))


@pytest.mark.asyncio
async def test_verify_presented_alias_checks_presenter() -> None:
    auth = DelegatableAuth(clock=0.0)
    parent = await auth.issue(AgentId("coordinator-0"), ["scribe:*"])
    child = await auth.delegate(
        parent,
        audience=AgentId("leaf-0"),
        scopes_subset=["scribe:verify"],
        ttl=10.0,
    )

    ctx = await auth.verify_presented(child, AgentId("leaf-0"))

    assert ctx.subject == AgentId("leaf-0")


@pytest.mark.asyncio
async def test_delegation_errors_are_value_errors() -> None:
    auth = DelegatableAuth(clock=0.0)
    root = await auth.issue(AgentId("coordinator-0"), ["scribe:*"])
    await auth.revoke(root)

    with pytest.raises(DelegationError, match="revoked"):
        await auth.verify(root)


def test_plugin_registry_resolves_delegatable_auth() -> None:
    assert PluginRegistry().resolve("auth", "delegatable") is DelegatableAuth


def test_scope_covers_requires_path_wildcard_boundary() -> None:
    assert scope_covers(
        "efs.write:/agents/leaf-1/*",
        "efs.write:/agents/leaf-1/report.json",
    )
    assert not scope_covers(
        "efs.write:/agents/leaf-1*",
        "efs.write:/agents/leaf-10/report.json",
    )
    assert not scope_covers("efs.write:/agents/*", "efs.write:/agents/../private/*")
    assert not scope_covers("efs.write:/agents/*", "efs.write:/agents//leaf-0/report.json")
    assert scope_covers("scribe:*", "scribe:publish")
