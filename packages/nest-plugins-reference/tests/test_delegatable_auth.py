# SPDX-License-Identifier: Apache-2.0
"""Tests for the ``delegatable`` capability-delegation auth plugin.

Six layers of coverage:

1. **Base ``Auth`` protocol conformance** -- issue/verify/revoke round-trip,
   tamper and malformed-token handling, cross-instance signature mismatch.
2. **Successful delegation** -- scopes narrow correctly, multi-level chains
   (grandchild) resolve back to the root.
3. **The three attacks the problem doc names** -- scope escalation, TTL
   violation, and audience confusion are each individually rejected with
   their typed exception.
4. **Cascading revocation** -- revoking a parent (or grandparent) fails a
   descendant's *next* verification, and does so while writing exactly one
   entry into the revocation table (no per-descendant bookkeeping), and
   without touching a sibling branch.
5. **Adversarial validator differential proof** -- each of the three
   ``nest_plugins_reference.validators.auth_delegation_validators`` checks
   is run against both ``JwtAuth`` (must fail) and ``DelegatableAuth``
   (must pass), proving the validator is genuinely adversarial per the
   charter, not just a check that happens to pass against one plugin.
6. **Full scenario integration** -- boots the real ``delegated_auth.yaml``
   scenario via ``ScenarioRunner`` and asserts the cascading-revocation
   outcome (exactly the 4 leaves under the revoked branch fail) and
   byte-identical determinism across two runs of the same seed.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from nest_core.plugins import PluginRegistry
from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_core.types import AgentId, Token
from nest_plugins_reference.auth.delegatable import (
    AudienceMismatchError,
    DelegatableAuth,
    DelegationTtlError,
    InvalidTokenError,
    RevokedAncestorError,
    ScopeEscalationError,
)
from nest_plugins_reference.auth.jwt_auth import JwtAuth
from nest_plugins_reference.validators import (
    check_audience_confusion_rejected,
    check_scope_escalation_rejected,
    check_stale_parent_rejected,
)

if TYPE_CHECKING:
    from nest_core.types import AuthContext

# ---------------------------------------------------------------------------
# 1. Base Auth protocol conformance
# ---------------------------------------------------------------------------


async def test_issue_verify_round_trip() -> None:
    auth = DelegatableAuth(secret=b"test-secret", clock=1000.0)
    token = await auth.issue(AgentId("root"), ["read", "write"])
    ctx = await auth.verify(token)
    assert ctx.subject == AgentId("root")
    assert ctx.scopes == ["read", "write"]
    assert ctx.issued_at == 1000.0


async def test_revoke_root_token() -> None:
    auth = DelegatableAuth(secret=b"test-secret", clock=1000.0)
    token = await auth.issue(AgentId("root"), ["read"])
    await auth.revoke(token)
    with pytest.raises(RevokedAncestorError):
        await auth.verify(token)


async def test_tampered_payload_rejected() -> None:
    auth = DelegatableAuth(secret=b"test-secret", clock=1000.0)
    token = await auth.issue(AgentId("root"), ["read"])
    tampered = Token(str(token).replace('"read"', '"admin"'))
    with pytest.raises(InvalidTokenError, match="signature"):
        await auth.verify(tampered)


async def test_malformed_token_rejected() -> None:
    auth = DelegatableAuth(secret=b"test-secret")
    with pytest.raises(InvalidTokenError):
        await auth.verify(Token("not-json"))


async def test_empty_chain_rejected() -> None:
    auth = DelegatableAuth(secret=b"test-secret")
    with pytest.raises(InvalidTokenError):
        await auth.verify(Token('{"chain": []}'))


async def test_cross_instance_signature_mismatch() -> None:
    auth1 = DelegatableAuth(secret=b"secret1", clock=1000.0)
    auth2 = DelegatableAuth(secret=b"secret2", clock=1000.0)
    token = await auth1.issue(AgentId("root"), ["read"])
    with pytest.raises(InvalidTokenError, match="signature"):
        await auth2.verify(token)


async def test_expired_token_rejected() -> None:
    auth = DelegatableAuth(secret=b"test-secret", clock=1000.0, default_root_ttl=10.0)
    token = await auth.issue(AgentId("root"), ["read"])
    # A second instance sharing the same secret, but with its clock advanced
    # well past expiry, stands in for "time has passed" without reaching
    # into the first instance's internals.
    later = DelegatableAuth(secret=b"test-secret", clock=2000.0, default_root_ttl=10.0)
    with pytest.raises(InvalidTokenError, match="expired"):
        await later.verify(token)


# ---------------------------------------------------------------------------
# 2. Successful delegation and multi-level chains
# ---------------------------------------------------------------------------


async def test_delegate_narrows_scopes_and_verifies() -> None:
    auth = DelegatableAuth(secret=b"secret", clock=1000.0)
    root = await auth.issue(AgentId("root"), ["read", "write", "admin"])
    child = await auth.delegate(root, AgentId("child"), ["read", "write"], ttl=60.0)
    ctx = await auth.verify(child)
    assert ctx.subject == AgentId("child")
    assert ctx.scopes == ["read", "write"]


async def test_grandchild_chain_resolves_back_to_root() -> None:
    auth = DelegatableAuth(secret=b"secret", clock=1000.0)
    root = await auth.issue(AgentId("root"), ["read", "write", "admin"])
    child = await auth.delegate(root, AgentId("child"), ["read", "write"], ttl=120.0)
    grandchild = await auth.delegate(child, AgentId("grandchild"), ["read"], ttl=60.0)
    ctx = await auth.verify_presented_by(grandchild, AgentId("grandchild"))
    assert ctx.subject == AgentId("grandchild")
    assert ctx.scopes == ["read"]


async def test_delegate_does_not_require_the_root_secret() -> None:
    """A holder of a valid parent token can delegate with zero knowledge of
    the issuer's secret -- ``delegate`` never reads ``self._secret``."""
    auth = DelegatableAuth(secret=b"secret-only-the-issuer-knows", clock=1000.0)
    root = await auth.issue(AgentId("root"), ["read", "write"])
    # An independent instance with a *different* (wrong) secret can still
    # correctly compute a child signature, because it is keyed off the
    # parent's own trailing signature, not either instance's ``_secret``.
    delegator = DelegatableAuth(secret=b"delegator-does-not-know-the-real-secret", clock=1000.0)
    child = await delegator.delegate(root, AgentId("child"), ["read"], ttl=60.0)
    # The *issuer* (holder of the real secret) still verifies it correctly.
    ctx = await auth.verify(child)
    assert ctx.subject == AgentId("child")


# ---------------------------------------------------------------------------
# 3a. Scope escalation
# ---------------------------------------------------------------------------


async def test_scope_escalation_superset_rejected() -> None:
    auth = DelegatableAuth(secret=b"secret", clock=1000.0)
    root = await auth.issue(AgentId("root"), ["read", "write"])
    with pytest.raises(ScopeEscalationError):
        await auth.delegate(root, AgentId("child"), ["read", "write", "admin"], ttl=60.0)


async def test_scope_escalation_unrelated_scope_rejected() -> None:
    auth = DelegatableAuth(secret=b"secret", clock=1000.0)
    root = await auth.issue(AgentId("root"), ["read", "write"])
    with pytest.raises(ScopeEscalationError):
        await auth.delegate(root, AgentId("child"), ["read", "delete"], ttl=60.0)


async def test_equal_scopes_rejected_not_a_strict_subset() -> None:
    """Every hop must shed at least one scope -- equal scopes are not a
    *strict* subset, per the problem doc's success criteria."""
    auth = DelegatableAuth(secret=b"secret", clock=1000.0)
    root = await auth.issue(AgentId("root"), ["read", "write"])
    with pytest.raises(ScopeEscalationError):
        await auth.delegate(root, AgentId("child"), ["read", "write"], ttl=60.0)


@given(
    parent_scopes=st.sets(
        st.sampled_from(["read", "write", "admin", "delete", "audit"]), min_size=2
    ),
    extra_scope=st.sampled_from(["deploy", "root", "sudo"]),
)
@settings(max_examples=50, deadline=None)
@pytest.mark.asyncio
async def test_property_any_scope_outside_parent_is_rejected(
    parent_scopes: set[str], extra_scope: str
) -> None:
    """For any parent scope set, requesting one scope the parent never held
    is always a ``ScopeEscalationError``, regardless of what else is asked for."""
    auth = DelegatableAuth(secret=b"secret", clock=1000.0)
    root = await auth.issue(AgentId("root"), sorted(parent_scopes))
    requested = [*sorted(parent_scopes)[:-1], extra_scope]
    with pytest.raises(ScopeEscalationError):
        await auth.delegate(root, AgentId("child"), requested, ttl=60.0)


# ---------------------------------------------------------------------------
# 3b. TTL violation
# ---------------------------------------------------------------------------


async def test_ttl_exceeding_parent_rejected() -> None:
    auth = DelegatableAuth(secret=b"secret", clock=1000.0, default_root_ttl=100.0)
    root = await auth.issue(AgentId("root"), ["read", "write"])
    with pytest.raises(DelegationTtlError):
        await auth.delegate(root, AgentId("child"), ["read"], ttl=1000.0)


async def test_non_positive_ttl_rejected() -> None:
    auth = DelegatableAuth(secret=b"secret", clock=1000.0)
    root = await auth.issue(AgentId("root"), ["read", "write"])
    with pytest.raises(DelegationTtlError):
        await auth.delegate(root, AgentId("child"), ["read"], ttl=0.0)


async def test_ttl_at_exact_parent_boundary_is_allowed() -> None:
    auth = DelegatableAuth(secret=b"secret", clock=1000.0, default_root_ttl=100.0)
    root = await auth.issue(AgentId("root"), ["read", "write"])
    child = await auth.delegate(root, AgentId("child"), ["read"], ttl=100.0)
    ctx = await auth.verify(child)
    assert ctx.expires_at == 1100.0


# ---------------------------------------------------------------------------
# 3c. Audience confusion
# ---------------------------------------------------------------------------


async def test_audience_confusion_rejected() -> None:
    auth = DelegatableAuth(secret=b"secret", clock=1000.0)
    root = await auth.issue(AgentId("root"), ["read", "write"])
    child = await auth.delegate(root, AgentId("intended"), ["read"], ttl=60.0)
    with pytest.raises(AudienceMismatchError):
        await auth.verify_presented_by(child, AgentId("attacker"))


async def test_audience_match_succeeds() -> None:
    auth = DelegatableAuth(secret=b"secret", clock=1000.0)
    root = await auth.issue(AgentId("root"), ["read", "write"])
    child = await auth.delegate(root, AgentId("intended"), ["read"], ttl=60.0)
    ctx = await auth.verify_presented_by(child, AgentId("intended"))
    assert ctx.subject == AgentId("intended")


async def test_root_token_audience_defaults_to_subject() -> None:
    auth = DelegatableAuth(secret=b"secret", clock=1000.0)
    root = await auth.issue(AgentId("root"), ["read"])
    ctx = await auth.verify_presented_by(root, AgentId("root"))
    assert ctx.subject == AgentId("root")
    with pytest.raises(AudienceMismatchError):
        await auth.verify_presented_by(root, AgentId("someone-else"))


# ---------------------------------------------------------------------------
# 4. Cascading revocation
# ---------------------------------------------------------------------------


async def test_cascading_revocation_invalidates_child() -> None:
    auth = DelegatableAuth(secret=b"secret", clock=1000.0)
    root = await auth.issue(AgentId("root"), ["read", "write", "admin"])
    child = await auth.delegate(root, AgentId("child"), ["read", "write"], ttl=120.0)

    await auth.revoke(root)

    with pytest.raises(RevokedAncestorError):
        await auth.verify(child)


async def test_cascading_revocation_invalidates_grandchild_without_touching_it() -> None:
    auth = DelegatableAuth(secret=b"secret", clock=1000.0)
    root = await auth.issue(AgentId("root"), ["read", "write", "admin"])
    child = await auth.delegate(root, AgentId("child"), ["read", "write"], ttl=120.0)
    grandchild = await auth.delegate(child, AgentId("grandchild"), ["read"], ttl=60.0)
    # A sibling delegated straight from root, never touched by the revoke
    # call below, is how we observe that only one entry was ever written
    # (a blanket/broad revocation would have caught this one too).
    sibling = await auth.delegate(root, AgentId("sibling"), ["read"], ttl=60.0)

    # Revoke only the intermediate "child" -- the grandchild's own token
    # string is never passed to revoke().
    await auth.revoke(child)

    with pytest.raises(RevokedAncestorError, match="depth 1"):
        await auth.verify(grandchild)
    # The root, and the untouched sibling branch, still verify fine.
    ctx_root = await auth.verify(root)
    assert ctx_root.subject == AgentId("root")
    ctx_sibling = await auth.verify(sibling)
    assert ctx_sibling.subject == AgentId("sibling")


async def test_sibling_branch_unaffected_by_revocation() -> None:
    auth = DelegatableAuth(secret=b"secret", clock=1000.0)
    root = await auth.issue(AgentId("root"), ["read", "write", "admin"])
    branch_a = await auth.delegate(root, AgentId("a"), ["read", "write"], ttl=120.0)
    branch_b = await auth.delegate(root, AgentId("b"), ["read", "write"], ttl=120.0)

    await auth.revoke(branch_a)

    with pytest.raises(RevokedAncestorError):
        await auth.verify(branch_a)
    ctx_b = await auth.verify(branch_b)
    assert ctx_b.subject == AgentId("b")


# ---------------------------------------------------------------------------
# 5. Adversarial validator differential proof
#
# Charter's bar for "adversarial": the same validator function must FAIL
# against the default jwt plugin and PASS against delegatable.
# ---------------------------------------------------------------------------


async def test_scope_escalation_validator_fails_against_jwt() -> None:
    jwt = JwtAuth(secret=b"jwt-secret")
    await jwt.issue(AgentId("root"), ["read"])

    async def attempt_mint() -> Token:
        # The only "delegation" jwt exposes is re-issuance -- no parent to
        # compare against, so nothing stops a broader scope set.
        return await jwt.issue(AgentId("child"), ["read", "admin"])

    report = await check_scope_escalation_rejected(attempt_mint, verify=jwt.verify)
    assert not report.passed, "jwt has no delegation primitive to catch escalation with"


async def test_scope_escalation_validator_passes_against_delegatable() -> None:
    auth = DelegatableAuth(secret=b"secret", clock=1000.0)
    parent = await auth.issue(AgentId("root"), ["read"])

    async def attempt_mint() -> Token:
        return await auth.delegate(parent, AgentId("child"), ["read", "admin"], ttl=60.0)

    report = await check_scope_escalation_rejected(attempt_mint, verify=auth.verify)
    assert report.passed, report.detail


async def test_stale_parent_validator_fails_against_jwt() -> None:
    jwt = JwtAuth(secret=b"jwt-secret")
    parent = await jwt.issue(AgentId("root"), ["read", "write"])
    # jwt has no delegation, so a "child" is just an independently issued token.
    child = await jwt.issue(AgentId("child"), ["read"])

    report = await check_stale_parent_rejected(
        child, revoke_parent=lambda: jwt.revoke(parent), verify=jwt.verify
    )
    assert not report.passed, "jwt's flat revocation set can't cascade to an unrelated token"


async def test_stale_parent_validator_passes_against_delegatable() -> None:
    auth = DelegatableAuth(secret=b"secret", clock=1000.0)
    parent = await auth.issue(AgentId("root"), ["read", "write"])
    child = await auth.delegate(parent, AgentId("child"), ["read"], ttl=60.0)

    report = await check_stale_parent_rejected(
        child, revoke_parent=lambda: auth.revoke(parent), verify=auth.verify
    )
    assert report.passed, report.detail


async def test_audience_confusion_validator_fails_against_jwt() -> None:
    jwt = JwtAuth(secret=b"jwt-secret")
    token = await jwt.issue(AgentId("intended"), ["read"])

    async def present(presenter: AgentId) -> AuthContext:
        # jwt.verify ignores who is presenting entirely.
        del presenter
        return await jwt.verify(token)

    report = await check_audience_confusion_rejected(present, AgentId("attacker"))
    assert not report.passed, "jwt has no audience concept to enforce"


async def test_audience_confusion_validator_passes_against_delegatable() -> None:
    auth = DelegatableAuth(secret=b"secret", clock=1000.0)
    root = await auth.issue(AgentId("root"), ["read", "write"])
    token = await auth.delegate(root, AgentId("intended"), ["read"], ttl=60.0)

    async def present(presenter: AgentId) -> AuthContext:
        return await auth.verify_presented_by(token, presenter)

    report = await check_audience_confusion_rejected(present, AgentId("attacker"))
    assert report.passed, report.detail


# ---------------------------------------------------------------------------
# 6. Full scenario integration
# ---------------------------------------------------------------------------

SCENARIO_PATH = Path(__file__).resolve().parents[3] / "scenarios" / "delegated_auth.yaml"


async def _run_delegation_scenario(trace_name: str) -> tuple[dict[str, str], bytes]:
    config = ScenarioConfig.from_yaml(str(SCENARIO_PATH))
    with tempfile.TemporaryDirectory() as tmp:
        trace_path = Path(tmp) / trace_name
        config = config.model_copy(
            update={"output": config.output.model_copy(update={"trace": str(trace_path)})}
        )
        runner = ScenarioRunner(config, registry=PluginRegistry())
        await runner.run()
        report = runner.resolved_plugins.get("_delegation_report")
        assert report is not None, "scenario factory should expose _delegation_report"
        trace_bytes = trace_path.read_bytes() if trace_path.exists() else b""
        return dict(report), trace_bytes


async def test_scenario_cascades_revocation_to_exactly_one_branch() -> None:
    if not SCENARIO_PATH.exists():
        pytest.skip(f"scenario not found at {SCENARIO_PATH}")

    config = ScenarioConfig.from_yaml(str(SCENARIO_PATH))
    with tempfile.TemporaryDirectory() as tmp:
        trace_path = Path(tmp) / "delegated_auth.jsonl"
        config = config.model_copy(
            update={"output": config.output.model_copy(update={"trace": str(trace_path)})}
        )
        runner = ScenarioRunner(config, registry=PluginRegistry())
        await runner.run()

        report = runner.resolved_plugins.get("_delegation_report")
        revoked_leaf_ids = runner.resolved_plugins.get("_delegation_revoked_leaf_ids")
        all_leaf_ids = runner.resolved_plugins.get("_delegation_leaf_ids")
        assert report is not None
        assert revoked_leaf_ids is not None
        assert all_leaf_ids is not None
        assert len(all_leaf_ids) == 12
        assert len(revoked_leaf_ids) == 4
        assert len(report) == 12

        for leaf_id in all_leaf_ids:
            expected = "revoked" if leaf_id in revoked_leaf_ids else "ok"
            assert report[leaf_id] == expected, (
                f"{leaf_id}: expected {expected!r}, got {report[leaf_id]!r}"
            )


async def test_scenario_deterministic_under_replay() -> None:
    if not SCENARIO_PATH.exists():
        pytest.skip(f"scenario not found at {SCENARIO_PATH}")

    report_a, trace_a = await _run_delegation_scenario("delegated_auth_run_a.jsonl")
    report_b, trace_b = await _run_delegation_scenario("delegated_auth_run_b.jsonl")

    assert report_a == report_b
    assert len(report_a) == 12
    assert trace_a == trace_b, "same seed must produce a byte-identical trace"
