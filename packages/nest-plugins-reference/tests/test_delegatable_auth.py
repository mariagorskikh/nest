# SPDX-License-Identifier: Apache-2.0
"""Tests for the delegatable auth plugin."""

from __future__ import annotations

import pytest
from nest_core.types import AgentId
from nest_plugins_reference.auth.delegatable import (
    AudienceMismatchError,
    DelegatableAuth,
    ExpiredParentError,
    RevokedAncestorError,
    ScopeEscalationError,
    TtlViolationError,
)


class TestDelegatableAuth:
    @pytest.mark.asyncio
    async def test_issue_verify_root(self) -> None:
        auth = DelegatableAuth(secret=b"test-secret", clock=0.0)
        token = await auth.issue(AgentId("coordinator"), ["read", "write", "delegate"])
        ctx = await auth.verify(token)
        assert ctx.subject == AgentId("coordinator")
        assert ctx.scopes == ["delegate", "read", "write"]

    @pytest.mark.asyncio
    async def test_delegate_valid_child(self) -> None:
        auth = DelegatableAuth(secret=b"test-secret", clock=0.0)
        root = await auth.issue(AgentId("coordinator"), ["read", "write", "delegate"])
        child = await auth.delegate(root, AgentId("leaf-0"), ["read"], ttl=600)
        ctx = await auth.verify(child, presenter=AgentId("leaf-0"))
        assert ctx.subject == AgentId("leaf-0")
        assert ctx.scopes == ["read"]

    @pytest.mark.asyncio
    async def test_scope_escalation_raises(self) -> None:
        auth = DelegatableAuth(secret=b"test-secret", clock=0.0)
        root = await auth.issue(AgentId("coordinator"), ["read", "write"])
        with pytest.raises(ScopeEscalationError):
            await auth.delegate(root, AgentId("leaf-0"), ["read", "admin"], ttl=100)

    @pytest.mark.asyncio
    async def test_ttl_violation_raises(self) -> None:
        auth = DelegatableAuth(secret=b"test-secret", clock=0.0, root_ttl=100.0)
        root = await auth.issue(AgentId("coordinator"), ["read", "write", "delegate"])
        with pytest.raises(TtlViolationError):
            await auth.delegate(root, AgentId("leaf-0"), ["read"], ttl=200)

    @pytest.mark.asyncio
    async def test_revoked_parent_blocks_child(self) -> None:
        auth = DelegatableAuth(secret=b"test-secret", clock=0.0)
        root = await auth.issue(AgentId("coordinator"), ["read", "write", "delegate"])
        child = await auth.delegate(root, AgentId("leaf-0"), ["read"], ttl=600)
        await auth.revoke(root)
        with pytest.raises(RevokedAncestorError):
            await auth.verify(child, presenter=AgentId("leaf-0"))

    @pytest.mark.asyncio
    async def test_revoked_grandparent_blocks_grandchild(self) -> None:
        auth = DelegatableAuth(secret=b"test-secret", clock=0.0)
        root = await auth.issue(AgentId("coordinator"), ["read", "write", "delegate"])
        mid = await auth.delegate(root, AgentId("intermediary-0"), ["read", "delegate"], ttl=800)
        leaf = await auth.delegate(mid, AgentId("leaf-0"), ["read"], ttl=400)
        await auth.revoke(root)
        with pytest.raises(RevokedAncestorError):
            await auth.verify(leaf, presenter=AgentId("leaf-0"))

    @pytest.mark.asyncio
    async def test_expired_parent_blocks_child(self) -> None:
        auth = DelegatableAuth(secret=b"test-secret", clock=0.0, root_ttl=100.0)
        root = await auth.issue(AgentId("coordinator"), ["read", "write", "delegate"])
        child = await auth.delegate(root, AgentId("leaf-0"), ["read"], ttl=50)
        auth.set_clock(150.0)
        with pytest.raises(ExpiredParentError):
            await auth.verify(child, presenter=AgentId("leaf-0"))

    @pytest.mark.asyncio
    async def test_audience_mismatch_fails(self) -> None:
        auth = DelegatableAuth(secret=b"test-secret", clock=0.0)
        root = await auth.issue(AgentId("coordinator"), ["read", "write", "delegate"])
        child = await auth.delegate(root, AgentId("leaf-0"), ["read"], ttl=600)
        with pytest.raises(AudienceMismatchError):
            await auth.verify(child, presenter=AgentId("leaf-1"))

    @pytest.mark.asyncio
    async def test_deterministic_tokens(self) -> None:
        auth1 = DelegatableAuth(secret=b"test-secret", clock=0.0)
        auth2 = DelegatableAuth(secret=b"test-secret", clock=0.0)
        t1 = await auth1.issue(AgentId("coordinator"), ["read", "delegate"])
        t2 = await auth2.issue(AgentId("coordinator"), ["read", "delegate"])
        assert str(t1) == str(t2)

    @pytest.mark.asyncio
    async def test_jwt_fails_adversarial_validator(self) -> None:
        """Default jwt cannot block scope escalation in the delegated_auth trace."""
        from pathlib import Path

        from nest_core.runner import ScenarioRunner
        from nest_core.scenario import ScenarioConfig
        from nest_core.validators import validate_trace

        yaml_path = Path("scenarios/delegated_auth.yaml")
        if not yaml_path.exists():
            pytest.skip("scenario yaml not present yet")

        config = ScenarioConfig.from_yaml(yaml_path)
        config.layers.auth = "jwt"
        config.output.trace = "./traces/delegated_auth_jwt_contrast.jsonl"

        runner = ScenarioRunner(config)
        await runner.run()

        results = validate_trace(Path(config.output.trace), "delegated_auth")
        assert results, "expected delegated_auth validators to run"
        assert any(not r.passed for r in results), "jwt must fail at least one validator"
