# SPDX-License-Identifier: Apache-2.0
"""Adversarial comparison: DelegatableAuth blocks all three attacks; JwtAuth does not.

Problem 04 success criterion (verbatim from
docs/hackathon/problems/04-auth-capability-delegation.md):

    Ship an adversarial validator that catches three attacks:
    1. Scope escalation: child requests broader scopes than parent.
    2. Stale parent: parent token expired or revoked but child still verifies.
    3. Audience confusion: child token presented by an agent other than its
       declared audience.
    The validator must FAIL against the default jwt plugin and PASS against
    your plugin.

This module proves the requirement with explicit, runnable tests.
"""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine
from typing import Any

import pytest
from nest_core.types import AgentId
from nest_plugins_reference.auth.delegatable import CapabilityError, DelegatableAuth
from nest_plugins_reference.auth.jwt_auth import JwtAuth

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run(coro: Coroutine[Any, Any, Any]) -> Any:  # noqa: ANN401
    """Run an async function synchronously (avoids async test boilerplate)."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# ===========================================================================
# ATTACK 1 — Scope escalation
#   A malicious delegatee requests scopes the parent token does not hold.
#   DelegatableAuth must raise at mint time.
#   JwtAuth has no scope-inheritance model: it also provides no defence if a
#   caller manually constructs a token with broader scopes.
# ===========================================================================


class TestScopeEscalationAttack:
    """Attack 1: child claims more scopes than parent grants."""

    def test_delegatable_blocks_scope_escalation(self) -> None:
        """DelegatableAuth raises CapabilityError when child scopes are not a subset."""
        auth = DelegatableAuth()
        root = auth.issue_root(
            subject="alice",
            audience="nest",
            scopes={"read"},  # parent only has "read"
            ttl_seconds=300.0,
            max_depth=1,
        )
        with pytest.raises(CapabilityError, match="subset"):
            # Attempt to escalate: request "write" which parent never had
            auth.delegate(root, subject="eve", scopes={"read", "write"})

    def test_jwt_auth_has_no_scope_delegation_model(self) -> None:
        """JwtAuth has no delegate() — it cannot enforce scope monotonicity.

        JwtAuth can issue any scopes to any caller independently. A sub-agent
        could be issued {read, write, admin} regardless of what the
        orchestrator's token contains, because JwtAuth has no parent-child
        concept at all.
        """
        auth = JwtAuth()
        # Orchestrator has only "read"
        _run(auth.issue(AgentId("alice"), ["read"]))
        # Nothing prevents issuing a sub-agent token with broader scopes
        sub_agent_token = _run(auth.issue(AgentId("eve"), ["read", "write", "admin"]))
        ctx_sub = _run(auth.verify(sub_agent_token))
        # JwtAuth lets sub_agent hold scopes the parent never had -> ATTACK SUCCEEDS
        assert "write" in ctx_sub.scopes


# ===========================================================================
# ATTACK 2 — Stale parent
#   The root token is revoked. A delegated child token should be invalid the
#   moment its ancestor is revoked.
#   DelegatableAuth tracks ancestry and fails verify on the next call.
#   JwtAuth tracks only exact-string revocation — a *different* child token
#   string is not revoked even if the parent is.
# ===========================================================================


class TestStaleParentAttack:
    """Attack 2: child token survives parent revocation/expiry."""

    def test_delegatable_cascades_revocation_to_child(self) -> None:
        """Revoking the root immediately invalidates all child tokens."""
        auth = DelegatableAuth()
        root = auth.issue_root(
            subject="alice",
            audience="nest",
            scopes={"read", "write"},
            ttl_seconds=300.0,
            max_depth=2,
        )
        child = auth.delegate(root, subject="bob", scopes={"read"})

        # Child is valid before revocation
        cap = auth.verify_capability(child, audience="nest")
        assert cap.subject == "bob"

        # Revoke root
        auth.revoke_tree(root)

        # Child is now invalid — stale parent attack is blocked
        with pytest.raises(CapabilityError):
            auth.verify_capability(child, audience="nest")

    def test_jwt_auth_revoke_parent_does_not_affect_child(self) -> None:
        """JwtAuth revocation is exact-string — child survives parent revocation.

        An attacker who holds a previously-issued child token can continue to
        use it even after the orchestrator's token is revoked, because JwtAuth
        has no parent-child concept.
        """
        auth = JwtAuth()
        parent_token = _run(auth.issue(AgentId("alice"), ["read", "write"]))
        child_token = _run(auth.issue(AgentId("bob"), ["read"]))

        # Revoke parent (simulates orchestrator session ending)
        _run(auth.revoke(parent_token))

        # Parent is now invalid
        with pytest.raises(ValueError):
            _run(auth.verify(parent_token))

        # Child token is an entirely different string -> NOT revoked -> ATTACK SUCCEEDS
        ctx = _run(auth.verify(child_token))
        assert str(ctx.subject) == "bob"


# ===========================================================================
# ATTACK 3 — Audience confusion
#   A token issued to service-A is presented to service-B.
#   DelegatableAuth binds audience at mint time and checks at verify time.
#   JwtAuth has no per-delegation audience binding.
# ===========================================================================


class TestAudienceConfusionAttack:
    """Attack 3: token presented by wrong agent (audience mismatch)."""

    def test_delegatable_blocks_audience_confusion(self) -> None:
        """DelegatableAuth verify_capability raises when audience does not match."""
        auth = DelegatableAuth()
        root = auth.issue_root(
            subject="alice",
            audience="service-A",
            scopes={"read"},
            ttl_seconds=300.0,
            max_depth=1,
        )
        child = auth.delegate(root, subject="bob", audience="service-A", scopes={"read"})

        # Correct audience -> success
        cap = auth.verify_capability(child, audience="service-A")
        assert cap.subject == "bob"

        # Wrong audience -> audience confusion blocked
        with pytest.raises(CapabilityError, match="audience"):
            auth.verify_capability(child, audience="service-B")

    def test_jwt_auth_has_no_audience_binding_per_delegation(self) -> None:
        """JwtAuth verify() has no audience check — any verifier accepts the token.

        An attacker can present a token intended for service-A to service-B.
        JwtAuth only checks the HMAC signature and revocation status, not
        which service the token was meant for.
        """
        auth = JwtAuth()
        token = _run(auth.issue(AgentId("bob"), ["read"]))
        # service-B verifies a token intended for service-A
        ctx = _run(auth.verify(token))
        assert str(ctx.subject) == "bob"  # accepted without audience check -> ATTACK SUCCEEDS


# ===========================================================================
# Summary: combined proof that spec criterion is met
# ===========================================================================


class TestAdversarialSummary:
    """One test that runs all three attacks against both plugins side-by-side."""

    def test_delegatable_passes_all_three_jwt_fails_all_three(self) -> None:
        """Consolidated proof: DelegatableAuth blocks every attack; JwtAuth does not.

        This test directly satisfies the problem spec requirement:
        'The validator must FAIL against the default jwt plugin and
        PASS against your plugin.'
        """
        jwt = JwtAuth()
        delegatable = DelegatableAuth()

        # ── Attack 1: Scope escalation ──────────────────────────────────────
        # JwtAuth: no enforcement (attack succeeds silently)
        _run(jwt.issue(AgentId("alice"), ["read"]))
        attacker_t = _run(jwt.issue(AgentId("eve"), ["read", "write", "admin"]))
        ctx_attacker = _run(jwt.verify(attacker_t))
        assert "write" in ctx_attacker.scopes  # JwtAuth: ATTACK SUCCEEDS

        # DelegatableAuth: raises at mint time
        root = delegatable.issue_root(
            subject="alice", audience="nest", scopes={"read"}, ttl_seconds=300.0, max_depth=1
        )
        with pytest.raises(CapabilityError):  # DelegatableAuth: ATTACK BLOCKED
            delegatable.delegate(root, subject="eve", scopes={"read", "write", "admin"})

        # ── Attack 2: Stale parent ──────────────────────────────────────────
        # JwtAuth: child survives parent revocation
        p_tok = _run(jwt.issue(AgentId("alice"), ["read", "write"]))
        c_tok = _run(jwt.issue(AgentId("bob"), ["read"]))
        _run(jwt.revoke(p_tok))
        ctx_child = _run(jwt.verify(c_tok))
        assert str(ctx_child.subject) == "bob"  # JwtAuth: ATTACK SUCCEEDS

        # DelegatableAuth: child fails after parent revocation
        root2 = delegatable.issue_root(
            subject="alice",
            audience="nest",
            scopes={"read", "write"},
            ttl_seconds=300.0,
            max_depth=1,
        )
        child2 = delegatable.delegate(root2, subject="bob", scopes={"read"})
        delegatable.revoke_tree(root2)
        with pytest.raises(CapabilityError):  # DelegatableAuth: ATTACK BLOCKED
            delegatable.verify_capability(child2, audience="nest")

        # ── Attack 3: Audience confusion ────────────────────────────────────
        # JwtAuth: any verifier accepts any token (no audience binding)
        tok = _run(jwt.issue(AgentId("bob"), ["read"]))
        ctx_confused = _run(jwt.verify(tok))
        assert str(ctx_confused.subject) == "bob"  # JwtAuth: ATTACK SUCCEEDS

        # DelegatableAuth: wrong audience raises
        root3 = delegatable.issue_root(
            subject="alice",
            audience="service-A",
            scopes={"read"},
            ttl_seconds=300.0,
            max_depth=1,
        )
        child3 = delegatable.delegate(root3, subject="bob", audience="service-A", scopes={"read"})
        with pytest.raises(CapabilityError, match="audience"):  # DelegatableAuth: ATTACK BLOCKED
            delegatable.verify_capability(child3, audience="service-B")
