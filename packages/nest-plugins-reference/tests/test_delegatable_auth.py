# SPDX-License-Identifier: Apache-2.0
"""Tests for the delegatable auth plugin."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from nest_core.plugins import PluginRegistry
from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_core.types import AgentId
from nest_core.validators import (
    validate_delegated_auth_stale_parent,
    validate_delegated_auth_transitive_revocation,
    validate_trace,
)
from nest_plugins_reference.auth.delegatable import (
    AudienceMismatchError,
    DelegatableAuth,
    ExpiredParentError,
    RevokedAncestorError,
    ScopeEscalationError,
    TtlViolationError,
)

SCENARIO_PATH = Path(__file__).resolve().parents[3] / "scenarios" / "delegated_auth.yaml"


def _swap_auth(config: ScenarioConfig, plugin_name: str) -> ScenarioConfig:
    new_layers = config.layers.model_copy(update={"auth": plugin_name})
    return config.model_copy(update={"layers": new_layers})


def _run_scenario(plugin_name: str, tmp_path: Path, seed: int = 42) -> Path:
    config = ScenarioConfig.from_yaml(str(SCENARIO_PATH))
    config = _swap_auth(config, plugin_name)
    config = config.model_copy(update={"seed": seed})
    trace_path = tmp_path / f"delegated_auth_{plugin_name}_{seed}.jsonl"
    config = config.model_copy(
        update={"output": config.output.model_copy(update={"trace": str(trace_path)})}
    )
    runner = ScenarioRunner(config, registry=PluginRegistry())
    asyncio.run(runner.run())
    return trace_path


class TestDelegatableAuth:
    @pytest.mark.asyncio
    async def test_issue_verify_root(self) -> None:
        auth = DelegatableAuth(secret=b"test-secret", clock=0.0)
        token = await auth.issue(AgentId("coordinator"), ["read", "write", "delegate"])
        ctx = await auth.verify(token)
        assert ctx.subject == AgentId("coordinator")
        assert ctx.scopes == ["delegate", "read", "write"]

    @pytest.mark.asyncio
    async def test_root_verifies_without_presenter(self) -> None:
        auth = DelegatableAuth(secret=b"test-secret", clock=0.0)
        token = await auth.issue(AgentId("coordinator"), ["read", "delegate"])
        ctx = await auth.verify(token, presenter=None)
        assert ctx.subject == AgentId("coordinator")

    @pytest.mark.asyncio
    async def test_delegate_valid_child(self) -> None:
        auth = DelegatableAuth(secret=b"test-secret", clock=0.0)
        root = await auth.issue(AgentId("coordinator"), ["read", "write", "delegate"])
        child = await auth.delegate(root, AgentId("leaf-0"), ["read"], ttl=600)
        ctx = await auth.verify(child, presenter=AgentId("leaf-0"))
        assert ctx.subject == AgentId("leaf-0")
        assert ctx.scopes == ["read"]

    @pytest.mark.asyncio
    async def test_delegated_fails_without_presenter(self) -> None:
        auth = DelegatableAuth(secret=b"test-secret", clock=0.0)
        root = await auth.issue(AgentId("coordinator"), ["read", "write", "delegate"])
        child = await auth.delegate(root, AgentId("leaf-0"), ["read"], ttl=600)
        with pytest.raises(AudienceMismatchError):
            await auth.verify(child, presenter=None)

    @pytest.mark.asyncio
    async def test_scope_escalation_raises(self) -> None:
        auth = DelegatableAuth(secret=b"test-secret", clock=0.0)
        root = await auth.issue(AgentId("coordinator"), ["read", "write", "delegate"])
        with pytest.raises(ScopeEscalationError):
            await auth.delegate(root, AgentId("leaf-0"), ["read", "admin"], ttl=100)

    @pytest.mark.asyncio
    async def test_parent_without_delegate_scope_cannot_delegate(self) -> None:
        auth = DelegatableAuth(secret=b"test-secret", clock=0.0)
        root = await auth.issue(AgentId("coordinator"), ["read", "write"])
        with pytest.raises(ScopeEscalationError, match="delegate scope"):
            await auth.delegate(root, AgentId("leaf-0"), ["read"], ttl=100)

    @pytest.mark.asyncio
    async def test_leaf_cannot_sub_delegate(self) -> None:
        auth = DelegatableAuth(secret=b"test-secret", clock=0.0)
        root = await auth.issue(AgentId("coordinator"), ["read", "write", "delegate"])
        leaf = await auth.delegate(root, AgentId("leaf-0"), ["read"], ttl=600)
        with pytest.raises(ScopeEscalationError, match="delegate scope"):
            await auth.delegate(leaf, AgentId("leaf-99"), ["read"], ttl=100)

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
    async def test_jwt_auth_uses_deterministic_clock(self) -> None:
        from nest_plugins_reference.auth.jwt_auth import JwtAuth

        auth1 = JwtAuth(secret=b"test-secret", clock=0.0)
        auth2 = JwtAuth(secret=b"test-secret", clock=0.0)
        t1 = await auth1.issue(AgentId("coordinator"), ["read"])
        t2 = await auth2.issue(AgentId("coordinator"), ["read"])
        assert str(t1) == str(t2)
        assert "0.0" in str(t1) or '"iat": 0.0' in str(t1)


@pytest.mark.skipif(not SCENARIO_PATH.exists(), reason=f"scenario not at {SCENARIO_PATH}")
def test_delegatable_auth_passes_all_validators(tmp_path: Path) -> None:
    trace_path = _run_scenario("delegatable", tmp_path)
    results = validate_trace(trace_path, "delegated_auth")
    assert results
    assert all(r.passed for r in results), [
        f"{r.name}: {r.detail}" for r in results if not r.passed
    ]


@pytest.mark.skipif(not SCENARIO_PATH.exists(), reason=f"scenario not at {SCENARIO_PATH}")
def test_jwt_fails_adversarial_validator(tmp_path: Path) -> None:
    repo_trace = Path("traces/delegated_auth_jwt_contrast.jsonl")
    if repo_trace.exists():
        repo_trace.unlink()
    trace_path = _run_scenario("jwt", tmp_path)
    results = validate_trace(trace_path, "delegated_auth")
    assert results
    assert any(not r.passed for r in results), "jwt must fail at least one validator"
    assert not repo_trace.exists()


@pytest.mark.skipif(not SCENARIO_PATH.exists(), reason=f"scenario not at {SCENARIO_PATH}")
def test_yaml_root_scopes_are_load_bearing(tmp_path: Path) -> None:
    config = ScenarioConfig.from_yaml(str(SCENARIO_PATH))
    config = _swap_auth(config, "delegatable")
    custom_scopes = ["read", "delegate"]
    task = config.task.model_copy(
        update={"config": {**(config.task.config or {}), "root_scopes": custom_scopes}}
    )
    config = config.model_copy(update={"task": task})
    trace_path = tmp_path / "custom_root_scopes.jsonl"
    config = config.model_copy(
        update={"output": config.output.model_copy(update={"trace": str(trace_path)})}
    )
    runner = ScenarioRunner(config, registry=PluginRegistry())
    asyncio.run(runner.run())
    issue_lines = [
        line
        for line in trace_path.read_text(encoding="utf-8").splitlines()
        if "auth_issue:coordinator-0:" in line
    ]
    assert issue_lines
    assert "delegate,read" in issue_lines[0] or "read,delegate" in issue_lines[0]
    assert "write" not in issue_lines[0]


@pytest.mark.skipif(not SCENARIO_PATH.exists(), reason=f"scenario not at {SCENARIO_PATH}")
def test_yaml_delegation_tree_is_load_bearing(tmp_path: Path) -> None:
    config = ScenarioConfig.from_yaml(str(SCENARIO_PATH))
    config = _swap_auth(config, "delegatable")
    custom_tree = {
        "coordinator-0": ["intermediary-0"],
        "intermediary-0": ["leaf-0"],
    }
    task = config.task.model_copy(
        update={"config": {**(config.task.config or {}), "delegation_tree": custom_tree}}
    )
    config = config.model_copy(
        update={
            "task": task,
            "agents": config.agents.model_copy(update={"count": 4}),
        }
    )
    trace_path = tmp_path / "custom_tree.jsonl"
    config = config.model_copy(
        update={"output": config.output.model_copy(update={"trace": str(trace_path)})}
    )
    runner = ScenarioRunner(config, registry=PluginRegistry())
    asyncio.run(runner.run())
    text = trace_path.read_text(encoding="utf-8")
    assert "auth_delegate:coordinator-0:intermediary-0:" in text
    assert "auth_delegate:intermediary-0:leaf-0:" in text
    assert "auth_delegate:coordinator-0:intermediary-1:" not in text


def test_stale_parent_and_transitive_validators_are_independent() -> None:
    stale_only = [
        {"kind": "send", "agent": "auditor-0", "msg": "auth_attack:stale_parent"},
        {
            "kind": "send",
            "agent": "auditor-0",
            "msg": "auth_revoke:coordinator-0:intermediary-0:t1",
        },
        {
            "kind": "send",
            "agent": "auditor-0",
            "msg": "auth_verify:leaf-0:t9:rejected:RevokedAncestorError",
        },
    ]
    transitive_only = [
        {"kind": "send", "agent": "auditor-0", "msg": "auth_attack:transitive_revocation"},
        {"kind": "send", "agent": "auditor-0", "msg": "auth_revoke:coordinator-0:coordinator-0:t0"},
        {
            "kind": "send",
            "agent": "auditor-0",
            "msg": "auth_verify:leaf-0:t5:rejected:RevokedAncestorError",
        },
    ]
    assert validate_delegated_auth_stale_parent(stale_only)[0].passed is True
    assert validate_delegated_auth_transitive_revocation(transitive_only)[0].passed is True
    assert validate_delegated_auth_stale_parent(transitive_only)[0].passed is False
    assert validate_delegated_auth_transitive_revocation(stale_only)[0].passed is False


_DELEGATION_CASES = [
    pytest.param(["read"], ["read", "delegate"], True, id="valid_subset_with_delegate"),
    pytest.param(
        ["read", "write", "delegate"], ["read", "write", "delegate"], False, id="equal_scopes"
    ),
    pytest.param(["read", "admin"], ["read", "write", "delegate"], False, id="superset_scopes"),
    pytest.param(["read"], ["read", "write"], False, id="missing_delegate_scope"),
]


class TestDelegationTable:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(("child_scopes", "parent_scopes", "should_succeed"), _DELEGATION_CASES)
    async def test_delegate_scope_table(
        self,
        child_scopes: list[str],
        parent_scopes: list[str],
        should_succeed: bool,
    ) -> None:
        auth = DelegatableAuth(secret=b"test-secret", clock=0.0)
        root = await auth.issue(AgentId("coordinator"), parent_scopes)
        if should_succeed:
            child = await auth.delegate(root, AgentId("leaf-0"), child_scopes, ttl=100)
            await auth.verify(child, presenter=AgentId("leaf-0"))
        else:
            with pytest.raises(ScopeEscalationError):
                await auth.delegate(root, AgentId("leaf-0"), child_scopes, ttl=100)

    @pytest.mark.asyncio
    async def test_child_ttl_too_long(self) -> None:
        auth = DelegatableAuth(secret=b"test-secret", clock=0.0, root_ttl=100.0)
        root = await auth.issue(AgentId("coordinator"), ["read", "delegate"])
        with pytest.raises(TtlViolationError):
            await auth.delegate(root, AgentId("leaf-0"), ["read"], ttl=200)

    @pytest.mark.asyncio
    async def test_missing_presenter(self) -> None:
        auth = DelegatableAuth(secret=b"test-secret", clock=0.0)
        root = await auth.issue(AgentId("coordinator"), ["read", "delegate"])
        child = await auth.delegate(root, AgentId("leaf-0"), ["read"], ttl=100)
        with pytest.raises(AudienceMismatchError):
            await auth.verify(child, presenter=None)

    @pytest.mark.asyncio
    async def test_wrong_presenter(self) -> None:
        auth = DelegatableAuth(secret=b"test-secret", clock=0.0)
        root = await auth.issue(AgentId("coordinator"), ["read", "delegate"])
        child = await auth.delegate(root, AgentId("leaf-0"), ["read"], ttl=100)
        with pytest.raises(AudienceMismatchError):
            await auth.verify(child, presenter=AgentId("leaf-1"))

    @pytest.mark.asyncio
    async def test_revoked_ancestor(self) -> None:
        auth = DelegatableAuth(secret=b"test-secret", clock=0.0)
        root = await auth.issue(AgentId("coordinator"), ["read", "delegate"])
        child = await auth.delegate(root, AgentId("leaf-0"), ["read"], ttl=100)
        await auth.revoke(root)
        with pytest.raises(RevokedAncestorError):
            await auth.verify(child, presenter=AgentId("leaf-0"))


@settings(max_examples=25, deadline=None)
@given(
    child_scope=st.sampled_from(["read", "write"]),
    parent_has_delegate=st.booleans(),
    ttl=st.integers(min_value=1, max_value=50),
)
@pytest.mark.asyncio
async def test_delegation_property(
    child_scope: str,
    parent_has_delegate: bool,
    ttl: int,
) -> None:
    parent_scopes = ["read", "write"]
    if parent_has_delegate:
        parent_scopes.append("delegate")
    auth = DelegatableAuth(secret=b"test-secret", clock=0.0, root_ttl=100.0)
    root = await auth.issue(AgentId("coordinator"), parent_scopes)
    should_succeed = parent_has_delegate and child_scope in {"read", "write"} and ttl <= 100
    if should_succeed:
        child = await auth.delegate(root, AgentId("leaf-0"), [child_scope], ttl=float(ttl))
        await auth.verify(child, presenter=AgentId("leaf-0"))
    else:
        with pytest.raises((ScopeEscalationError, TtlViolationError)):
            await auth.delegate(root, AgentId("leaf-0"), [child_scope], ttl=float(ttl))
