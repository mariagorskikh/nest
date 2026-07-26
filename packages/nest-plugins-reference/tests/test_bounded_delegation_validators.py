# SPDX-License-Identifier: Apache-2.0
"""Tests for the bounded-delegation adversarial validators.

Each validator is exercised twice: against audits a correct plugin would
emit (must pass) and against audits the merged plugins would emit (must
fail). The charter's bar for "adversarial" is that a validator fails
against the reference implementation, so the failing direction is the
one that matters.

``TestAgainstLivePlugins`` drives real plugin instances rather than
hand-built events, closing the gap between "the validator rejects this
dict" and "the validator rejects what the plugin actually produces".
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from nest_core.types import AgentId
from nest_plugins_reference.auth.bounded_delegation import (
    BoundedDelegationAuth,
    DelegationDepthExceededError,
)
from nest_plugins_reference.auth.mesh_revocable import MeshRevocableAuth
from nest_plugins_reference.validators.bounded_delegation_validators import (
    check_chain_depth_bounded,
    check_depth_attack_refused,
    check_pruning_preserves_liveness,
    check_revocations_pruned,
    extract_bounded_audits,
)

SECRET = b"bounded-delegation-validator-secret"


def audit(**fields: Any) -> dict[str, Any]:
    """Build one audit payload with the required type tag."""
    return {"type": "bounded_delegation_audit", **fields}


class TestExtraction:
    def test_extracts_bare_payloads(self) -> None:
        events = [audit(action="verify"), {"type": "other"}]
        assert len(extract_bounded_audits(events)) == 1

    def test_extracts_payloads_wrapped_in_msg(self) -> None:
        events = [{"msg": json.dumps(audit(action="verify"))}]
        assert len(extract_bounded_audits(events)) == 1

    def test_ignores_unparseable_msg(self) -> None:
        assert extract_bounded_audits([{"msg": "not json at all"}]) == []

    def test_ignores_foreign_event_types(self) -> None:
        events = [{"msg": json.dumps({"type": "delegation_audit"})}]
        assert extract_bounded_audits(events) == []


class TestCheckChainDepthBounded:
    def test_passes_when_all_within_bound(self) -> None:
        audits = [audit(verified=True, depth=d, max_depth=8) for d in (1, 3, 8)]
        assert check_chain_depth_bounded(audits).passed

    def test_fails_when_a_verification_exceeds_bound(self) -> None:
        audits = [audit(verified=True, depth=9, max_depth=8)]
        report = check_chain_depth_bounded(audits)
        assert not report.passed
        assert "9" in report.detail

    def test_refused_attempts_do_not_count(self) -> None:
        """A refused over-deep mint is the defence working, not a breach."""
        audits = [audit(verified=False, granted=False, depth=99, max_depth=8)]
        assert check_chain_depth_bounded(audits).passed

    def test_reports_the_deepest_violation(self) -> None:
        audits = [
            audit(verified=True, depth=9, max_depth=8),
            audit(verified=True, depth=40, max_depth=8),
        ]
        report = check_chain_depth_bounded(audits)
        assert "40" in report.detail
        assert len(report.evidence) == 2

    def test_missing_depth_fields_are_skipped(self) -> None:
        assert check_chain_depth_bounded([audit(verified=True)]).passed


class TestCheckDepthAttackRefused:
    def test_passes_when_an_attack_was_refused(self) -> None:
        audits = [audit(action="delegate", granted=False, reason="depth")]
        assert check_depth_attack_refused(audits).passed

    def test_fails_when_no_delegation_was_attempted(self) -> None:
        report = check_depth_attack_refused([audit(action="verify")])
        assert not report.passed
        assert "never exercised" in report.detail

    def test_fails_when_every_delegation_was_granted(self) -> None:
        """A scenario that never provokes the bound proves nothing."""
        audits = [audit(action="delegate", granted=True) for _ in range(5)]
        report = check_depth_attack_refused(audits)
        assert not report.passed
        assert "never provoked" in report.detail

    def test_refusal_for_another_reason_does_not_count(self) -> None:
        audits = [audit(action="delegate", granted=False, reason="scope")]
        assert not check_depth_attack_refused(audits).passed


class TestCheckRevocationsPruned:
    def test_passes_when_nothing_prunable_remains(self) -> None:
        audits = [audit(action="gossip", prunable=0, retained=3)]
        assert check_revocations_pruned(audits).passed

    def test_fails_when_a_replica_retains_prunable_entries(self) -> None:
        audits = [audit(action="gossip", prunable=7, retained=7)]
        report = check_revocations_pruned(audits)
        assert not report.passed
        assert "7" in report.detail

    def test_fails_when_pruning_was_never_observed(self) -> None:
        report = check_revocations_pruned([audit(action="verify")])
        assert not report.passed
        assert "never observed" in report.detail

    def test_reports_the_worst_replica(self) -> None:
        audits = [
            audit(action="gossip", prunable=2),
            audit(action="gossip", prunable=11),
        ]
        assert "11" in check_revocations_pruned(audits).detail


class TestCheckPruningPreservesLiveness:
    def test_passes_when_no_revoked_token_verified(self) -> None:
        audits = [audit(verified=True, leaf_revoked=False)]
        assert check_pruning_preserves_liveness(audits).passed

    def test_fails_when_a_live_revocation_was_lost(self) -> None:
        audits = [audit(verified=True, leaf_revoked=True, leaf_expired=False)]
        report = check_pruning_preserves_liveness(audits)
        assert not report.passed
        assert "still mattered" in report.detail

    def test_expired_revoked_token_is_not_a_violation(self) -> None:
        """Pruning an expired entry is the whole point; expiry still bites."""
        audits = [audit(verified=True, leaf_revoked=True, leaf_expired=True)]
        assert check_pruning_preserves_liveness(audits).passed


class TestAgainstLivePlugins:
    """Drive real plugins and validate the audits they produce."""

    @pytest.mark.asyncio
    async def test_bounded_plugin_passes_depth_checks(self) -> None:
        auth = BoundedDelegationAuth(secret=SECRET, clock=0.0, max_depth=3)
        audits: list[dict[str, Any]] = []
        token = await auth.issue(AgentId("coordinator"), ["read"])

        for i in range(5):
            try:
                token = await auth.delegate(token, AgentId(f"w{i}"), ["read"], ttl=60.0)
            except DelegationDepthExceededError:
                audits.append(audit(action="delegate", granted=False, reason="depth"))
                break
            audits.append(audit(action="delegate", granted=True))

        summary = auth.chain_summary(token)
        await auth.verify(token)
        audits.append(
            audit(
                action="verify",
                verified=True,
                depth=summary["depth"],
                max_depth=summary["max_depth"],
            )
        )

        assert check_chain_depth_bounded(audits).passed
        assert check_depth_attack_refused(audits).passed

    @pytest.mark.asyncio
    async def test_merged_plugin_fails_depth_checks(self) -> None:
        """The same scenario against mesh_revocable must fail both checks."""
        auth = MeshRevocableAuth(secret=SECRET, clock=0.0)
        audits: list[dict[str, Any]] = []
        token = await auth.issue(AgentId("coordinator"), ["read"])

        for i in range(5):
            token = await auth.delegate(token, AgentId(f"w{i}"), ["read"], ttl=60.0)
            audits.append(audit(action="delegate", granted=True))

        await auth.verify(token)
        audits.append(audit(action="verify", verified=True, depth=6, max_depth=3))

        assert not check_chain_depth_bounded(audits).passed
        assert not check_depth_attack_refused(audits).passed

    @pytest.mark.asyncio
    async def test_bounded_plugin_passes_pruning_check(self) -> None:
        auth = BoundedDelegationAuth(secret=SECRET, clock=0.0, prune_grace=10.0)
        for i in range(8):
            token = await auth.issue(AgentId(f"a{i}"), ["read"])
            await auth.revoke(token)
        auth.advance_to(100_000.0)
        auth.prune_revocations()
        audits = [audit(action="gossip", **auth.revocation_stats())]
        assert check_revocations_pruned(audits).passed

    @pytest.mark.asyncio
    async def test_merged_plugin_fails_pruning_check(self) -> None:
        """mesh_revocable retains every entry, so prunable stays non-zero."""
        issuer = MeshRevocableAuth(secret=SECRET, clock=0.0)
        for i in range(8):
            token = await issuer.issue(AgentId(f"a{i}"), ["read"])
            await issuer.revoke(token)

        # A replica far past every token's expiry still holds all eight,
        # because a G-Set has no way to drop anything. The scenario reports
        # that count as prunable, and the validator rejects it.
        future = MeshRevocableAuth(secret=SECRET, clock=100_000.0)
        future.merge_revocations(issuer.export_revocations())
        retained = len(json.loads(future.export_revocations())["revoked"])
        assert retained == 8

        audits = [audit(action="gossip", prunable=retained, retained=retained)]
        assert not check_revocations_pruned(audits).passed
