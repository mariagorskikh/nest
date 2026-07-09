# SPDX-License-Identifier: Apache-2.0
"""Validator + adversarial-discrimination tests for delegatable capability tokens.

Two layers of coverage:

1. **Validator unit tests** — direct calls against ``delegatable`` exercising
   the accept / reject path of each of the three required checks.
2. **Adversarial discrimination** — the same three attacks run against the
   default ``jwt`` plugin MUST be reported as unmitigated (``passed=False``,
   or the honest "plugin cannot even attempt this" case for methods `jwt`
   doesn't have at all), and against ``delegatable`` MUST be caught
   (``passed=True``). This is the charter's bar: "an adversarial validator
   that catches a class of attacks the default reference plugin would fail."

``jwt`` has no ``delegate``/``verify_with_audience`` methods, so it cannot
even attempt scope-subset enforcement or audience binding — calling those
paths against it produces the "plugin has no delegate()" / "no
verify_with_audience()" failure reports directly. For stale-parent use,
``jwt`` *does* have ``issue``/``verify``/``revoke``, so the comparison is
apples-to-apples: two independently issued jwt tokens have no parent-child
relationship at all, so revoking one predictably never affects the other —
which is exactly the bug class this validator exists to catch.
"""

from __future__ import annotations

from nest_core.types import AgentId
from nest_plugins_reference.auth.delegatable import DelegatableAuth
from nest_plugins_reference.auth.jwt_auth import JwtAuth
from nest_plugins_reference.validators import (
    check_audience_enforced,
    check_no_scope_escalation,
    check_no_stale_parent_use,
)

_DELEGATOR = AgentId("orchestrator")
_AUDIENCE = AgentId("worker-1")
_ATTACKER = AgentId("attacker")


def _delegatable() -> DelegatableAuth:
    return DelegatableAuth(secret=b"validator-test-secret", clock=0.0)


def _jwt() -> JwtAuth:
    return JwtAuth(secret=b"validator-test-secret", clock=0.0)


# ---------------------------------------------------------------------------
# Validator unit tests (against delegatable, the plugin they ship next to)
# ---------------------------------------------------------------------------


class TestScopeEscalationValidator:
    async def test_reports_passed_when_escalation_is_rejected(self) -> None:
        report = await check_no_scope_escalation(
            _delegatable(), _DELEGATOR, ["read"], _AUDIENCE, ["read", "admin"]
        )
        assert report.passed, report.detail

    async def test_reports_passed_for_a_genuinely_valid_subset(self) -> None:
        report = await check_no_scope_escalation(
            _delegatable(), _DELEGATOR, ["read", "write"], _AUDIENCE, ["read"]
        )
        assert report.passed, report.detail


class TestStaleParentValidator:
    async def test_reports_passed_when_descendants_die_with_parent(self) -> None:
        auth = _delegatable()
        root = await auth.issue(_DELEGATOR, ["read"])
        child = await auth.delegate(root, _AUDIENCE, ["read"], ttl=60.0)
        grandchild = await auth.delegate(child, AgentId("worker-1-1"), ["read"], ttl=30.0)
        report = await check_no_stale_parent_use(auth, root, [child, grandchild])
        assert report.passed, report.detail


class TestAudienceValidator:
    async def test_reports_passed_when_impersonation_is_rejected(self) -> None:
        auth = _delegatable()
        root = await auth.issue(_DELEGATOR, ["read"])
        child = await auth.delegate(root, _AUDIENCE, ["read"], ttl=60.0)
        report = await check_audience_enforced(auth, child, _AUDIENCE, _ATTACKER)
        assert report.passed, report.detail


# ---------------------------------------------------------------------------
# Adversarial discrimination: jwt MUST FAIL, delegatable MUST PASS
# ---------------------------------------------------------------------------


class TestDiscriminationScopeEscalation:
    async def test_jwt_cannot_prevent_scope_escalation(self) -> None:
        report = await check_no_scope_escalation(
            _jwt(), _DELEGATOR, ["read"], _AUDIENCE, ["read", "admin"]
        )
        assert not report.passed, "jwt has no delegate() — it must not be reported as passing"

    async def test_delegatable_prevents_scope_escalation(self) -> None:
        report = await check_no_scope_escalation(
            _delegatable(), _DELEGATOR, ["read"], _AUDIENCE, ["read", "admin"]
        )
        assert report.passed, report.detail


class TestDiscriminationStaleParent:
    async def test_jwt_tokens_have_no_parent_child_relationship(self) -> None:
        """Two unrelated jwt tokens: revoking one must never touch the other.

        This *is* the vulnerability: jwt's flat ``_revoked: set[str]`` keyed
        by exact token string has no notion of lineage, so there is nothing
        for revocation to cascade through. The "descendant" here is not
        actually derived from the "parent" (jwt cannot express that at all)
        -- it is a second, independent token, and it predictably survives.
        """
        auth = _jwt()
        root = await auth.issue(_DELEGATOR, ["read"])
        unrelated = await auth.issue(_AUDIENCE, ["read"])
        report = await check_no_stale_parent_use(auth, root, [unrelated])
        assert not report.passed, "an unrelated jwt token must not be reported as revoked"

    async def test_delegatable_cascades_revocation_through_real_chain(self) -> None:
        auth = _delegatable()
        root = await auth.issue(_DELEGATOR, ["read"])
        child = await auth.delegate(root, _AUDIENCE, ["read"], ttl=60.0)
        report = await check_no_stale_parent_use(auth, root, [child])
        assert report.passed, report.detail


class TestDiscriminationAudience:
    async def test_jwt_has_no_audience_concept_at_all(self) -> None:
        auth = _jwt()
        token = await auth.issue(_AUDIENCE, ["read"])
        report = await check_audience_enforced(auth, token, _AUDIENCE, _ATTACKER)
        assert not report.passed, "jwt has no verify_with_audience() — must not pass"

    async def test_delegatable_enforces_audience(self) -> None:
        auth = _delegatable()
        root = await auth.issue(_DELEGATOR, ["read"])
        child = await auth.delegate(root, _AUDIENCE, ["read"], ttl=60.0)
        report = await check_audience_enforced(auth, child, _AUDIENCE, _ATTACKER)
        assert report.passed, report.detail
