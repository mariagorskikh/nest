# SPDX-License-Identifier: Apache-2.0
"""Tests for the policy layer, reference plugins, and policy_guard scenario."""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

import pytest
from nest_core.layers.policy import Policy, PolicyEffect, PolicyRequest
from nest_core.plugins import PluginRegistry
from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_core.types import AgentId
from nest_core.validators import ValidationResult, validate_trace
from nest_plugins_reference.policy.allow_all import AllowAllPolicy
from nest_plugins_reference.policy.strict import StrictPolicy

SCENARIO_PATH = Path(__file__).resolve().parents[3] / "scenarios" / "policy_guard.yaml"
_ACTOR = AgentId("agent-1")
_SEEDS = [42, 7, 1337]


def _decide(policy: Policy, request: PolicyRequest) -> PolicyEffect:
    decision = asyncio.run(policy.decide(request, now=10.0))
    return decision.effect


def _run_scenario(seed: int, policy: str = "strict_rules") -> dict[str, ValidationResult]:
    config = ScenarioConfig.from_yaml(str(SCENARIO_PATH))
    config = config.model_copy(
        update={
            "seed": seed,
            "task": config.task.model_copy(update={"config": {"policy_plugin": policy}}),
        }
    )
    with tempfile.TemporaryDirectory() as tmp:
        trace_path = Path(tmp) / f"policy_{seed}_{policy}.jsonl"
        config = config.model_copy(
            update={"output": config.output.model_copy(update={"trace": str(trace_path)})}
        )
        runner = ScenarioRunner(config, registry=PluginRegistry())
        asyncio.run(runner.run())
        results = validate_trace(trace_path, "policy_guard")
    return {r.name: r for r in results}


def _run_bytes(seed: int) -> bytes:
    config = ScenarioConfig.from_yaml(str(SCENARIO_PATH)).model_copy(update={"seed": seed})
    with tempfile.TemporaryDirectory() as tmp:
        trace_path = Path(tmp) / "policy_replay.jsonl"
        config = config.model_copy(
            update={"output": config.output.model_copy(update={"trace": str(trace_path)})}
        )
        runner = ScenarioRunner(config, registry=PluginRegistry())
        asyncio.run(runner.run())
        return trace_path.read_bytes()


def test_strict_policy_satisfies_protocol() -> None:
    """The strict plugin conforms to the runtime-checkable Policy Protocol."""
    assert isinstance(StrictPolicy(), Policy)


def test_registry_resolves_policy_plugins() -> None:
    """Both policy plugins are discoverable through the registry."""
    registry = PluginRegistry()
    assert registry.resolve("policy", "strict_rules") is StrictPolicy
    assert registry.resolve("policy", "allow_all") is AllowAllPolicy


def test_strict_policy_permits_safe_public_read() -> None:
    """A declared public read is safe enough for autonomous execution."""
    request = PolicyRequest(actor=_ACTOR, action="read", resource="catalog/public")
    assert _decide(StrictPolicy(), request) == PolicyEffect.PERMIT


def test_strict_policy_denies_sensitive_public_export() -> None:
    """Sensitive data cannot be sent to a public resource."""
    request = PolicyRequest(
        actor=_ACTOR,
        action="publish",
        resource="web/public",
        data_classes=["pii.email"],
    )
    assert _decide(StrictPolicy(), request) == PolicyEffect.DENY


def test_strict_policy_requires_approval_for_large_payment() -> None:
    """Large transfers require approval instead of autonomous execution."""
    request = PolicyRequest(
        actor=_ACTOR,
        action="pay",
        resource="vendor/settlement",
        amount=900,
    )
    assert _decide(StrictPolicy(), request) == PolicyEffect.APPROVAL_REQUIRED


def test_strict_policy_requires_approval_for_missing_payment_amount() -> None:
    """Unknown transfer amount cannot be treated as a zero-value transfer."""
    request = PolicyRequest(
        actor=_ACTOR,
        action="pay",
        resource="vendor/settlement",
    )
    assert _decide(StrictPolicy(), request) == PolicyEffect.APPROVAL_REQUIRED


def test_strict_policy_spend_permission_is_monotonic() -> None:
    """Raising payment amount never makes a strict decision more permissive."""
    policy = StrictPolicy(approval_threshold=100)
    ordered = {
        PolicyEffect.DENY: 0,
        PolicyEffect.APPROVAL_REQUIRED: 1,
        PolicyEffect.PERMIT: 2,
    }
    previous = _decide(
        policy,
        PolicyRequest(actor=_ACTOR, action="pay", resource="vendor/settlement", amount=0),
    )
    for amount in [1, 50, 100, 101, 250, 1000]:
        current = _decide(
            policy,
            PolicyRequest(
                actor=_ACTOR,
                action="pay",
                resource="vendor/settlement",
                amount=amount,
            ),
        )
        assert ordered[current] <= ordered[previous]
        previous = current


def test_strict_policy_denies_unknown_action() -> None:
    """Deny-by-default catches undeclared authority-changing actions."""
    request = PolicyRequest(actor=_ACTOR, action="admin", resource="registry/root")
    assert _decide(StrictPolicy(), request) == PolicyEffect.DENY


def test_allow_all_is_the_unsafe_foil() -> None:
    """The baseline intentionally permits an action strict policy blocks."""
    request = PolicyRequest(
        actor=_ACTOR,
        action="publish",
        resource="web/public",
        data_classes=["pii.email"],
    )
    assert _decide(AllowAllPolicy(), request) == PolicyEffect.PERMIT


@pytest.mark.parametrize("seed", _SEEDS)
def test_policy_guard_scenario_strict_passes_every_validator(seed: int) -> None:
    """The strict policy passes all end-to-end policy_guard validators."""
    results = _run_scenario(seed)
    expected = {
        "policy_safe_read_permitted",
        "policy_blocks_sensitive_public_export",
        "policy_requires_approval_for_high_value_payment",
        "policy_requires_approval_for_unknown_amount_payment",
        "policy_denies_unknown_admin_action",
    }
    assert expected <= set(results), f"missing validators: {expected - set(results)}"
    for name, result in results.items():
        assert result.passed, f"seed={seed} {name} failed: {result.detail}"


def test_policy_guard_allow_all_fails_adversarial_validators() -> None:
    """The permissive baseline fails every restrictive policy invariant."""
    results = _run_scenario(42, policy="allow_all")
    assert results["policy_safe_read_permitted"].passed is True
    assert results["policy_blocks_sensitive_public_export"].passed is False
    assert results["policy_requires_approval_for_high_value_payment"].passed is False
    assert results["policy_requires_approval_for_unknown_amount_payment"].passed is False
    assert results["policy_denies_unknown_admin_action"].passed is False


def test_policy_guard_trace_is_byte_deterministic() -> None:
    """Same seed, same policy, same trace bytes."""
    assert _run_bytes(42) == _run_bytes(42)
