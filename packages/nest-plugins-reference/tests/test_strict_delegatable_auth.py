# SPDX-License-Identifier: Apache-2.0
"""Tests for strict delegated auth capability tokens.

The suite is deliberately security-shaped: it proves the new plugin blocks
scope escalation, stale-parent delegation, and audience confusion while the
default JWT plugin fails the delegated-auth validator because it has no
delegation surface.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from nest_core.layers.auth import Auth
from nest_core.plugins import PluginRegistry
from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_core.types import AgentId, Token
from nest_plugins_reference.auth.jwt_auth import JwtAuth
from nest_plugins_reference.auth.strict_delegatable import (
    AudienceMismatchError,
    DelegationError,
    RevokedAncestorError,
    ScopeEscalationError,
    StrictDelegatableAuth,
)
from nest_plugins_reference.validators import check_strict_delegated_auth_attack_suite

_CHILD_KEY_DOMAIN = b"nest.delegatable-strict.child-key.v1|"
_SCOPES = ["read", "write", "approve", "audit", "export"]
_SCENARIO_PATH = Path(__file__).resolve().parents[3] / "scenarios" / "strict_delegated_auth.yaml"
_TOKEN_SIGN_DOMAIN = b"nest.delegatable-strict.token.v1|"


def _legacy_issuer_sign(
    secret: bytes,
    payload_b64: str,
    parent_hash: str | None,
) -> str:
    key = secret
    if parent_hash is not None:
        key = hmac.new(
            secret,
            _CHILD_KEY_DOMAIN + parent_hash.encode(),
            hashlib.sha256,
        ).digest()
    return hmac.new(
        key,
        _TOKEN_SIGN_DOMAIN + payload_b64.encode(),
        hashlib.sha256,
    ).hexdigest()


class MutableClock:
    """Small deterministic clock for token-expiry tests."""

    def __init__(self, value: float = 1000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


def test_strict_delegatable_auth_is_auth_protocol() -> None:
    auth = StrictDelegatableAuth(clock=1000.0)
    assert isinstance(auth, Auth)


def test_registry_resolves_strict_delegatable_auth() -> None:
    cls = PluginRegistry().resolve("auth", "delegatable_strict")
    assert cls is StrictDelegatableAuth


@pytest.mark.asyncio
async def test_issue_verify_root_token() -> None:
    auth = StrictDelegatableAuth(secret=b"test-secret", clock=1000.0)
    token = await auth.issue(AgentId("coordinator"), ["read", "write"])

    ctx = await auth.verify(token)

    assert ctx.subject == AgentId("coordinator")
    assert ctx.scopes == ["read", "write"]
    assert ctx.issued_at == 1000.0
    assert ctx.expires_at == 4600.0


@pytest.mark.asyncio
async def test_delegate_strict_scope_subset_to_audience() -> None:
    auth = StrictDelegatableAuth(secret=b"test-secret", clock=1000.0)
    parent = await auth.issue(AgentId("coordinator"), ["orders:read", "orders:write"])

    child = await auth.delegate(parent, AgentId("worker-1"), ["orders:read"], ttl=120.0)
    ctx = await auth.verify_for(child, AgentId("worker-1"))

    assert ctx.subject == AgentId("worker-1")
    assert ctx.scopes == ["orders:read"]
    assert ctx.expires_at == 1120.0


@pytest.mark.asyncio
async def test_scope_escalation_is_rejected() -> None:
    auth = StrictDelegatableAuth(clock=1000.0)
    parent = await auth.issue(AgentId("coordinator"), ["orders:read", "orders:write"])

    with pytest.raises(ScopeEscalationError, match="strict subset"):
        await auth.delegate(parent, AgentId("worker-1"), ["orders:read", "admin"], ttl=60.0)

    with pytest.raises(ScopeEscalationError, match="strict subset"):
        await auth.delegate(
            parent,
            AgentId("worker-2"),
            ["orders:read", "orders:write"],
            ttl=60.0,
        )


@pytest.mark.asyncio
async def test_parent_revocation_cascades_to_child_and_grandchild() -> None:
    auth = StrictDelegatableAuth(clock=1000.0)
    parent = await auth.issue(AgentId("coordinator"), ["read", "write", "comment"])
    child = await auth.delegate(parent, AgentId("worker-1"), ["read", "write"], ttl=120.0)
    grandchild = await auth.delegate(child, AgentId("leaf-1"), ["read"], ttl=30.0)

    await auth.revoke(parent)

    with pytest.raises(RevokedAncestorError, match="Ancestor"):
        await auth.verify(child)
    with pytest.raises(RevokedAncestorError, match="Ancestor"):
        await auth.verify(grandchild)


@pytest.mark.asyncio
async def test_child_expires_no_later_than_parent_horizon() -> None:
    clock = MutableClock(1000.0)
    auth = StrictDelegatableAuth(clock=clock)
    parent = await auth.issue(AgentId("coordinator"), ["read", "write"])
    child = await auth.delegate(parent, AgentId("worker-1"), ["read"], ttl=3600.0)

    clock.value = 4700.0

    with pytest.raises(DelegationError, match="expired"):
        await auth.verify(child)


@pytest.mark.asyncio
async def test_child_cannot_outlive_parent() -> None:
    clock = MutableClock(1000.0)
    auth = StrictDelegatableAuth(clock=clock)
    parent = await auth.issue(AgentId("coordinator"), ["read", "write"])
    clock.value = 4500.0

    with pytest.raises(DelegationError, match="no longer than parent"):
        await auth.delegate(parent, AgentId("worker-1"), ["read"], ttl=200.0)


@pytest.mark.asyncio
async def test_audience_confusion_is_rejected() -> None:
    auth = StrictDelegatableAuth(clock=1000.0)
    parent = await auth.issue(AgentId("coordinator"), ["files:read", "files:write"])
    child = await auth.delegate(parent, AgentId("worker-a"), ["files:read"], ttl=60.0)

    with pytest.raises(AudienceMismatchError, match="worker-a"):
        await auth.verify_for(child, AgentId("worker-b"))


@pytest.mark.asyncio
async def test_strict_delegated_auth_validator_passes_new_plugin() -> None:
    report = await check_strict_delegated_auth_attack_suite(StrictDelegatableAuth(clock=1000.0))
    assert report.passed, report.detail
    assert report.evidence["rejections"] == {
        "audience_confusion": "AudienceMismatchError",
        "scope_escalation": "ScopeEscalationError",
        "stale_parent": "RevokedAncestorError",
        "token_forgery": "DelegationError",
    }


@pytest.mark.asyncio
async def test_strict_delegated_auth_validator_fails_default_jwt() -> None:
    report = await check_strict_delegated_auth_attack_suite(JwtAuth(clock=1000.0))
    assert not report.passed
    assert report.evidence["missing_api"] is True


@pytest.mark.asyncio
async def test_key_confusion_forged_child_rejected_at_signature_gate() -> None:
    auth = StrictDelegatableAuth(secret=b"test-secret", clock=1000.0)
    parent = await auth.issue(AgentId("coordinator"), ["orders:read", "orders:write"])
    _, parent_signature = str(parent).rsplit(".", 1)
    parent_hash = hashlib.sha256(str(parent).encode()).hexdigest()
    forged_claims = {
        "aud": "worker",
        "exp": 1060.0,
        "iat": 1000.0,
        "jti": "forged-child",
        "parent": parent_hash,
        "scopes": ["orders:read", "admin"],
        "sub": "coordinator",
    }
    forged_raw = json.dumps(forged_claims, sort_keys=True, separators=(",", ":")).encode()
    forged_payload = base64.urlsafe_b64encode(forged_raw).decode().rstrip("=")
    forged_signature = hmac.new(
        parent_signature.encode(),
        _TOKEN_SIGN_DOMAIN + forged_payload.encode(),
        hashlib.sha256,
    ).hexdigest()
    forged = Token(f"{forged_payload}.{forged_signature}")

    with pytest.raises(DelegationError, match="signature"):
        await auth.verify(forged)


@pytest.mark.asyncio
async def test_non_ascii_signature_raises_delegation_error() -> None:
    auth = StrictDelegatableAuth(secret=b"test-secret", clock=1000.0)
    token = await auth.issue(AgentId("coordinator"), ["orders:read"])
    payload, _ = str(token).rsplit(".", 1)

    with pytest.raises(DelegationError, match="signature"):
        await auth.verify(Token(f"{payload}.not-ascii-\N{SNOWMAN}"))


@pytest.mark.asyncio
async def test_child_signature_is_derived_from_parent_token_not_issuer_secret() -> None:
    auth = StrictDelegatableAuth(secret=b"test-secret", clock=1000.0)
    parent = await auth.issue(AgentId("coordinator"), ["orders:read", "orders:write"])
    child = await auth.delegate(parent, AgentId("worker"), ["orders:read"], ttl=60.0)
    child_payload, child_signature = str(child).rsplit(".", 1)
    _, parent_signature = str(parent).rsplit(".", 1)
    parent_hash = hashlib.sha256(str(parent).encode()).hexdigest()
    holder_key = hmac.new(
        parent_signature.encode(),
        _CHILD_KEY_DOMAIN + parent_hash.encode(),
        hashlib.sha256,
    ).digest()
    holder_signature = hmac.new(
        holder_key,
        _TOKEN_SIGN_DOMAIN + child_payload.encode(),
        hashlib.sha256,
    ).hexdigest()
    issuer_secret_signature = _legacy_issuer_sign(b"test-secret", child_payload, parent_hash)

    assert child_signature == holder_signature
    assert child_signature != issuer_secret_signature


@pytest.mark.asyncio
async def test_legacy_issuer_secret_child_signature_is_rejected() -> None:
    auth = StrictDelegatableAuth(secret=b"test-secret", clock=1000.0)
    parent = await auth.issue(AgentId("coordinator"), ["orders:read", "orders:write"])
    child = await auth.delegate(parent, AgentId("worker"), ["orders:read"], ttl=60.0)
    child_payload, _ = str(child).rsplit(".", 1)
    parent_hash = hashlib.sha256(str(parent).encode()).hexdigest()
    bad_signature = _legacy_issuer_sign(b"test-secret", child_payload, parent_hash)
    bad_child = Token(f"{child_payload}.{bad_signature}")

    with pytest.raises(DelegationError, match="signature"):
        await auth.verify(bad_child)


@pytest.mark.asyncio
async def test_malformed_tokens_raise_delegation_error() -> None:
    auth = StrictDelegatableAuth(clock=1000.0)

    for raw in ("not-a-token", "a.b", "W10.bad-signature"):
        with pytest.raises(DelegationError):
            await auth.verify(Token(raw))


@given(scopes=st.lists(st.sampled_from(_SCOPES), min_size=2, max_size=5, unique=True))
@settings(max_examples=25, deadline=None)
def test_delegated_scope_subset_property(scopes: list[str]) -> None:
    async def check() -> None:
        auth = StrictDelegatableAuth(clock=1000.0)
        parent = await auth.issue(AgentId("coordinator"), scopes)
        child_scopes = scopes[:-1]
        child = await auth.delegate(parent, AgentId("worker"), child_scopes, ttl=60.0)
        child_ctx = await auth.verify_for(child, AgentId("worker"))

        assert set(child_ctx.scopes) < set(scopes)
        with pytest.raises(ScopeEscalationError):
            await auth.delegate(parent, AgentId("attacker"), scopes, ttl=60.0)

    asyncio.run(check())


@pytest.mark.asyncio
async def test_strict_delegated_auth_scenario_emits_tree_trace(tmp_path: Path) -> None:
    config = ScenarioConfig.from_yaml(_SCENARIO_PATH)
    config.output.trace = str(tmp_path / "strict_delegated_auth.jsonl")
    runner = ScenarioRunner(config)

    trace_path = await runner.run()

    events = [json.loads(line) for line in trace_path.read_text().splitlines()]
    messages = [str(event.get("msg", "")) for event in events]
    sent_messages = [str(event.get("msg", "")) for event in events if event.get("kind") == "send"]
    assert len(events) > 0
    assert runner.metrics["agent_count"] == 16.0
    assert runner.metrics["message_count"] > 0.0
    assert any("attack:scope_escalation:blocked" in msg for msg in messages)
    assert any("attack:stale_parent:blocked" in msg for msg in messages)
    assert any("attack:audience_confusion:blocked" in msg for msg in messages)
    leaf_acks = [msg for msg in sent_messages if msg.startswith("leaf:verified:")]
    assert len(leaf_acks) == 12
