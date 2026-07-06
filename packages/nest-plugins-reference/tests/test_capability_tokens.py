# SPDX-License-Identifier: Apache-2.0
"""Unit, attack, and scenario tests for capability-token auth."""

from __future__ import annotations

import asyncio
import tempfile
from dataclasses import dataclass
from pathlib import Path

import pytest
from nest_core.plugins import PluginRegistry
from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_core.types import AgentId
from nest_core.validators import validate_trace
from nest_plugins_reference.auth.capability_tokens import (
    AudienceMismatchError,
    CapabilityTokens,
    RevocationStore,
    RevocationViewStaleError,
    RevokedAncestorError,
    ScopeEscalationError,
    TtlEscalationError,
)

SCENARIO_PATH = (
    Path(__file__).resolve().parents[3] / "scenarios" / "capability_tokens_delegated_auth.yaml"
)
VALIDATOR_KEY = "capability_tokens_delegated_auth"


@dataclass
class _Clock:
    now: float = 0.0

    def __call__(self) -> float:
        return self.now


@pytest.mark.asyncio
async def test_issue_verify_root_subject_and_scopes() -> None:
    """Root tokens satisfy the base Auth protocol."""
    auth = CapabilityTokens(secret=b"test-secret", clock=0.0)
    token = await auth.issue(AgentId("coordinator"), ["write", "read", "read"])
    ctx = await auth.verify_for_audience(token, AgentId("coordinator"))
    assert ctx.subject == AgentId("coordinator")
    assert ctx.scopes == ["read", "write"]


@pytest.mark.asyncio
async def test_offline_holder_attenuates_without_reissuance() -> None:
    """A holder mints a child from the parent token, and the verifier replays it."""
    auth = CapabilityTokens(secret=b"test-secret", clock=0.0)
    root = await auth.issue(AgentId("coordinator"), ["alpha:read", "alpha:write"])
    child = await auth.delegate(root, AgentId("worker"), ["alpha:read"], ttl=30)
    ctx = await auth.verify_for_audience(child, AgentId("worker"))
    assert ctx.subject == AgentId("worker")
    assert ctx.scopes == ["alpha:read"]
    assert ctx.expires_at == 30


@pytest.mark.asyncio
async def test_attack_scope_escalation_denied_before_child_exists() -> None:
    """Attack: child asks for admin when parent only has read."""
    auth = CapabilityTokens(secret=b"test-secret", clock=0.0)
    root = await auth.issue(AgentId("coordinator"), ["read"])
    with pytest.raises(ScopeEscalationError):
        await auth.delegate(root, AgentId("worker"), ["read", "admin"], ttl=10)


@pytest.mark.asyncio
async def test_attack_ttl_extension_denied_at_delegation_boundary() -> None:
    """Attack: child tries to outlive the parent."""
    clock = _Clock(0.0)
    auth = CapabilityTokens(secret=b"test-secret", root_ttl=10, clock=clock)
    root = await auth.issue(AgentId("coordinator"), ["read"])
    clock.now = 4
    with pytest.raises(TtlEscalationError):
        await auth.delegate(root, AgentId("worker"), ["read"], ttl=7)


@pytest.mark.asyncio
async def test_attack_revoked_ancestor_cascades_to_child() -> None:
    """Attack: child replay after parent revocation must die by construction."""
    auth = CapabilityTokens(secret=b"test-secret", clock=0.0)
    root = await auth.issue(AgentId("coordinator"), ["read", "write"])
    parent = await auth.delegate(root, AgentId("intermediary"), ["read"], ttl=100)
    child = await auth.delegate(parent, AgentId("leaf"), ["read"], ttl=20)
    await auth.revoke(parent)
    with pytest.raises(RevokedAncestorError):
        await auth.verify_for_audience(child, AgentId("leaf"))


@pytest.mark.asyncio
async def test_attack_audience_confusion_rejected() -> None:
    """Attack: stolen child token is presented by the wrong agent."""
    auth = CapabilityTokens(secret=b"test-secret", clock=0.0)
    root = await auth.issue(AgentId("coordinator"), ["read"])
    child = await auth.delegate(root, AgentId("intended-worker"), ["read"], ttl=10)
    with pytest.raises(AudienceMismatchError):
        await auth.verify_for_audience(child, AgentId("wrong-worker"))


@pytest.mark.asyncio
async def test_attack_confused_deputy_unscoped_resource_rejected() -> None:
    """Attack: deputy presents its own token to act for a third party on write."""
    auth = CapabilityTokens(secret=b"test-secret", clock=0.0)
    root = await auth.issue(AgentId("coordinator"), ["payments:read"])
    deputy = await auth.delegate(root, AgentId("deputy"), ["payments:read"], ttl=10)
    ctx = await auth.authorize(deputy, AgentId("deputy"), "payments:read")
    assert ctx.scopes == ["payments:read"]
    with pytest.raises(ScopeEscalationError):
        await auth.authorize(deputy, AgentId("deputy"), "payments:write")


@pytest.mark.asyncio
async def test_attack_partitioned_revocation_view_fails_closed() -> None:
    """Attack: verifier cut off from revocation epoch must reject, not guess."""
    store = RevocationStore()
    issuer = CapabilityTokens(secret=b"test-secret", clock=0.0, revocation_store=store)
    stale = CapabilityTokens(
        secret=b"test-secret",
        clock=0.0,
        revocation_store=store,
        stale_after=0,
        auto_sync=False,
    )
    root = await issuer.issue(AgentId("coordinator"), ["read"])
    child = await issuer.delegate(root, AgentId("worker"), ["read"], ttl=10)
    await issuer.revoke(root)
    with pytest.raises(RevocationViewStaleError):
        await stale.verify_for_audience(child, AgentId("worker"))


def _swap_auth(config: ScenarioConfig, plugin_name: str) -> ScenarioConfig:
    new_layers = config.layers.model_copy(update={"auth": plugin_name})
    return config.model_copy(update={"layers": new_layers})


def _run_scenario(plugin_name: str, seed: int = 42) -> Path:
    config = ScenarioConfig.from_yaml(str(SCENARIO_PATH))
    config = _swap_auth(config, plugin_name)
    config = config.model_copy(update={"seed": seed})
    tmp = Path(tempfile.mkdtemp())
    trace_path = tmp / f"capability_tokens_delegated_auth_{plugin_name}_{seed}.jsonl"
    config = config.model_copy(
        update={"output": config.output.model_copy(update={"trace": str(trace_path)})}
    )
    runner = ScenarioRunner(config, registry=PluginRegistry())
    asyncio.run(runner.run())
    return trace_path


@pytest.mark.skipif(not SCENARIO_PATH.exists(), reason=f"scenario not at {SCENARIO_PATH}")
def test_capability_tokens_pass_delegated_auth_validators() -> None:
    """The capability plugin passes every adversarial delegated-auth validator."""
    trace_path = _run_scenario("capability_tokens")
    results = validate_trace(trace_path, VALIDATOR_KEY)
    assert all(r.passed for r in results), [
        f"{r.name}: {r.detail}" for r in results if not r.passed
    ]


@pytest.mark.skipif(not SCENARIO_PATH.exists(), reason=f"scenario not at {SCENARIO_PATH}")
def test_default_jwt_fails_delegated_auth_validators() -> None:
    """The default JWT plugin lacks offline delegation and must fail the validator suite."""
    trace_path = _run_scenario("jwt")
    results = validate_trace(trace_path, VALIDATOR_KEY)
    by_name = {r.name: r for r in results}
    assert not by_name["delegated_auth_tree_exercised"].passed
    assert not by_name["delegated_auth_scope_escalation_blocked"].passed
    assert not by_name["delegated_auth_audience_confusion_blocked"].passed
    assert not by_name["delegated_auth_confused_deputy_blocked"].passed
    assert not by_name["delegated_auth_epoch_fence_fail_closed"].passed


@pytest.mark.skipif(not SCENARIO_PATH.exists(), reason=f"scenario not at {SCENARIO_PATH}")
@pytest.mark.parametrize("seed", [42, 7, 1337])
def test_delegated_auth_scenario_deterministic_under_seed_bank(seed: int) -> None:
    """Each seed replays to byte-identical traces and passes validators."""
    first = _run_scenario("capability_tokens", seed=seed).read_bytes()
    second = _run_scenario("capability_tokens", seed=seed).read_bytes()
    assert first == second

    trace_path = _run_scenario("capability_tokens", seed=seed)
    results = validate_trace(trace_path, VALIDATOR_KEY)
    assert all(r.passed for r in results), [
        f"{r.name}: {r.detail}" for r in results if not r.passed
    ]


def test_plugin_registry_resolves_capability_tokens_builtin() -> None:
    """Registry wiring exposes the plugin under the requested auth name."""
    cls = PluginRegistry().resolve("auth", "capability_tokens")
    assert cls is CapabilityTokens
