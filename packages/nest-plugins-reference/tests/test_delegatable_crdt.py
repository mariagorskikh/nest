# SPDX-License-Identifier: Apache-2.0
"""Tests for the delegatable capability-token auth plugin.

Covers the public contract (issue/delegate/verify/revoke), the three attack
classes the plugin defeats (scope escalation, stale/revoked parent, audience
confusion), determinism, and the CRDT semantics of the revocation set —
example-based for the spec and ``hypothesis`` property-based for the invariants.

Example::

    pytest packages/nest-plugins-reference/tests/test_delegatable_auth.py
"""

from __future__ import annotations

import asyncio
import json

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from nest_core.types import AgentId, Token
from nest_plugins_reference.auth.delegatable_crdt import (
    AudienceMismatchError,
    CrdtDelegatableAuth,
    DelegationError,
    ExpiredTokenError,
    LogicalClock,
    MalformedTokenError,
    RevocationSet,
    RevokedAncestorError,
    ScopeEscalationError,
)

SCOPES = ["read", "write", "delete", "admin", "exec"]


def _auth(now: float = 0.0) -> CrdtDelegatableAuth:
    return CrdtDelegatableAuth(secret=b"test-secret", clock=LogicalClock(now))


# ---------------------------------------------------------------------------
# Contract / happy path
# ---------------------------------------------------------------------------


class TestContract:
    async def test_issue_and_verify_root(self) -> None:
        auth = _auth()
        token = await auth.issue(AgentId("root"), ["read", "write"])
        ctx = await auth.verify(token)
        assert ctx.subject == AgentId("root")
        assert set(ctx.scopes) == {"read", "write"}

    async def test_delegate_narrows_and_binds_audience(self) -> None:
        auth = _auth()
        root = await auth.issue(AgentId("a"), ["read", "write"])
        child = await auth.delegate(root, AgentId("b"), ["read"], ttl=100.0)
        ctx = await auth.verify(child, presenter=AgentId("b"))
        assert ctx.subject == AgentId("b")
        assert ctx.scopes == ["read"]
        assert auth.describe(child).depth == 1
        assert auth.describe(root).depth == 0

    async def test_verify_without_presenter_is_backward_compatible(self) -> None:
        auth = _auth()
        token = await auth.issue(AgentId("a"), ["read"])
        # Base Auth protocol shape: verify(token) with no presenter must work.
        ctx = await auth.verify(token)
        assert ctx.subject == AgentId("a")

    async def test_multi_level_chain_verifies(self) -> None:
        auth = _auth()
        root = await auth.issue(AgentId("a"), ["read", "write", "delete"])
        c1 = await auth.delegate(root, AgentId("b"), ["read", "write"], ttl=100.0)
        c2 = await auth.delegate(c1, AgentId("c"), ["read"], ttl=50.0)
        ctx = await auth.verify(c2, presenter=AgentId("c"))
        assert ctx.scopes == ["read"]
        assert auth.describe(c2).depth == 2


# ---------------------------------------------------------------------------
# Attack 1 — scope escalation
# ---------------------------------------------------------------------------


class TestScopeEscalation:
    async def test_widening_scope_raises(self) -> None:
        auth = _auth()
        root = await auth.issue(AgentId("a"), ["read"])
        with pytest.raises(ScopeEscalationError):
            await auth.delegate(root, AgentId("b"), ["read", "write"], ttl=100.0)

    async def test_equal_scope_ok(self) -> None:
        auth = _auth()
        root = await auth.issue(AgentId("a"), ["read", "write"])
        child = await auth.delegate(root, AgentId("b"), ["read", "write"], ttl=100.0)
        assert set(auth.describe(child).scopes) == {"read", "write"}

    async def test_escalation_blocked_at_second_hop(self) -> None:
        auth = _auth()
        root = await auth.issue(AgentId("a"), ["read", "write"])
        c1 = await auth.delegate(root, AgentId("b"), ["read"], ttl=100.0)
        # c1 only holds "read"; it cannot hand out "write" even though root had it.
        with pytest.raises(ScopeEscalationError):
            await auth.delegate(c1, AgentId("c"), ["write"], ttl=50.0)


# ---------------------------------------------------------------------------
# Attack 2 — stale / revoked parent, and cascading revocation
# ---------------------------------------------------------------------------


class TestCascadingRevocation:
    async def test_revoke_root_cascades_to_all_descendants(self) -> None:
        auth = _auth()
        root = await auth.issue(AgentId("a"), ["read"])
        child = await auth.delegate(root, AgentId("b"), ["read"], ttl=100.0)
        grandchild = await auth.delegate(child, AgentId("c"), ["read"], ttl=50.0)
        await auth.revoke(root)
        for tok in (root, child, grandchild):
            with pytest.raises(RevokedAncestorError):
                await auth.verify(tok)

    async def test_revoke_is_targeted_to_subtree(self) -> None:
        auth = _auth()
        root = await auth.issue(AgentId("a"), ["read", "write"])
        branch_a = await auth.delegate(root, AgentId("b"), ["read"], ttl=100.0)
        branch_b = await auth.delegate(root, AgentId("c"), ["write"], ttl=100.0)
        await auth.revoke(branch_a)
        with pytest.raises(RevokedAncestorError):
            await auth.verify(branch_a, presenter=AgentId("b"))
        # Sibling branch is untouched.
        ctx = await auth.verify(branch_b, presenter=AgentId("c"))
        assert ctx.scopes == ["write"]

    async def test_delegating_from_revoked_parent_raises(self) -> None:
        auth = _auth()
        root = await auth.issue(AgentId("a"), ["read"])
        child = await auth.delegate(root, AgentId("b"), ["read"], ttl=100.0)
        await auth.revoke(child)
        with pytest.raises(RevokedAncestorError):
            await auth.delegate(child, AgentId("c"), ["read"], ttl=10.0)

    async def test_revocation_by_construction_kills_future_children(self) -> None:
        # Revoke the parent, THEN mint a child from the (still-held) parent token
        # on a fresh replica that has merged the revocation: it must be dead.
        issuer = _auth()
        root = await issuer.issue(AgentId("a"), ["read"])
        child = await issuer.delegate(root, AgentId("b"), ["read"], ttl=100.0)
        await issuer.revoke(root)
        # A child minted before revocation still carries the root seal -> dead.
        with pytest.raises(RevokedAncestorError):
            await issuer.verify(child)


# ---------------------------------------------------------------------------
# Attack 3 — audience confusion
# ---------------------------------------------------------------------------


class TestAudienceConfusion:
    async def test_wrong_presenter_rejected(self) -> None:
        auth = _auth()
        root = await auth.issue(AgentId("a"), ["read"])
        child = await auth.delegate(root, AgentId("b"), ["read"], ttl=100.0)
        with pytest.raises(AudienceMismatchError):
            await auth.verify(child, presenter=AgentId("mallory"))

    async def test_correct_presenter_accepted(self) -> None:
        auth = _auth()
        root = await auth.issue(AgentId("a"), ["read"])
        child = await auth.delegate(root, AgentId("b"), ["read"], ttl=100.0)
        ctx = await auth.verify(child, presenter=AgentId("b"))
        assert ctx.subject == AgentId("b")


# ---------------------------------------------------------------------------
# Expiry and TTL clamping (correctness of time bounds)
# ---------------------------------------------------------------------------


class TestExpiry:
    async def test_child_ttl_clamped_to_parent(self) -> None:
        auth = _auth()
        root = await auth.issue(AgentId("a"), ["read"])  # expiry 0 + 3600
        parent_exp = auth.describe(root).expires_at
        child = await auth.delegate(root, AgentId("b"), ["read"], ttl=10_000.0)
        assert auth.describe(child).expires_at == parent_exp

    async def test_expired_token_rejected(self) -> None:
        auth = _auth()
        root = await auth.issue(AgentId("a"), ["read"])
        child = await auth.delegate(root, AgentId("b"), ["read"], ttl=5.0)
        auth.set_now(10.0)  # advance past the child's expiry
        with pytest.raises(ExpiredTokenError):
            await auth.verify(child, presenter=AgentId("b"))

    async def test_non_positive_ttl_rejected(self) -> None:
        auth = _auth()
        root = await auth.issue(AgentId("a"), ["read"])
        with pytest.raises(DelegationError):
            await auth.delegate(root, AgentId("b"), ["read"], ttl=0.0)


# ---------------------------------------------------------------------------
# Tamper / malformed input (forgery resistance)
# ---------------------------------------------------------------------------


class TestMalformed:
    async def test_tampered_scope_rejected(self) -> None:
        auth = _auth()
        token = await auth.issue(AgentId("a"), ["read"])
        tampered = Token(str(token).replace('"read"', '"admin"'))
        with pytest.raises(MalformedTokenError):
            await auth.verify(tampered)

    async def test_non_json_rejected(self) -> None:
        auth = _auth()
        with pytest.raises(MalformedTokenError):
            await auth.verify(Token("not a token"))

    async def test_missing_fields_rejected(self) -> None:
        auth = _auth()
        with pytest.raises(MalformedTokenError):
            await auth.verify(Token(json.dumps({"root": {"subject": "a"}})))


# ---------------------------------------------------------------------------
# Determinism (no uuid, no wall-clock)
# ---------------------------------------------------------------------------


class TestDeterminism:
    async def test_identical_inputs_yield_identical_tokens(self) -> None:
        a = CrdtDelegatableAuth(secret=b"k", clock=LogicalClock(0.0))
        b = CrdtDelegatableAuth(secret=b"k", clock=LogicalClock(0.0))
        ta = await a.issue(AgentId("x"), ["read", "write"])
        tb = await b.issue(AgentId("x"), ["read", "write"])
        assert ta == tb

    async def test_delegation_is_deterministic(self) -> None:
        a = CrdtDelegatableAuth(secret=b"k", clock=LogicalClock(0.0))
        b = CrdtDelegatableAuth(secret=b"k", clock=LogicalClock(0.0))
        ra = await a.delegate(await a.issue(AgentId("x"), ["read"]), AgentId("y"), ["read"], 5.0)
        rb = await b.delegate(await b.issue(AgentId("x"), ["read"]), AgentId("y"), ["read"], 5.0)
        assert ra == rb


# ---------------------------------------------------------------------------
# RevocationSet — G-Set CRDT semantics
# ---------------------------------------------------------------------------


class TestRevocationSetCRDT:
    def test_merge_is_union(self) -> None:
        a = RevocationSet()
        b = RevocationSet()
        a.revoke("x")
        b.revoke("y")
        a.merge(b)
        assert "x" in a
        assert "y" in a

    def test_merge_does_not_mutate_source(self) -> None:
        a = RevocationSet()
        b = RevocationSet()
        a.revoke("x")
        b.merge(a)
        assert "x" in b
        assert "x" in a  # b.merge(a) must not empty a
        assert len(a) == 1

    def test_monotone_never_shrinks(self) -> None:
        a = RevocationSet()
        a.revoke("x")
        a.revoke("x")  # idempotent add
        a.merge(RevocationSet())  # merging empty removes nothing
        assert "x" in a
        assert len(a) == 1


# ---------------------------------------------------------------------------
# Partition tolerance / convergence (the distributed core)
# ---------------------------------------------------------------------------


class TestConvergence:
    async def test_verifier_accepts_until_it_merges_the_revocation(self) -> None:
        issuer = CrdtDelegatableAuth(secret=b"k", clock=LogicalClock(0.0))
        verifier = CrdtDelegatableAuth(secret=b"k", clock=LogicalClock(0.0))
        token = await issuer.issue(AgentId("a"), ["read"])

        # Verifier accepts — it has not heard about any revocation.
        assert (await verifier.verify(token)).subject == AgentId("a")

        await issuer.revoke(token)
        # Honest partition window: verifier still accepts (hasn't merged yet).
        assert (await verifier.verify(token)).subject == AgentId("a")

        verifier.merge(issuer)  # gossip / partition heal
        with pytest.raises(RevokedAncestorError):
            await verifier.verify(token)

    async def test_once_revoked_observed_never_accepts_again(self) -> None:
        issuer = CrdtDelegatableAuth(secret=b"k", clock=LogicalClock(0.0))
        verifier = CrdtDelegatableAuth(secret=b"k", clock=LogicalClock(0.0))
        token = await issuer.issue(AgentId("a"), ["read"])
        await issuer.revoke(token)
        verifier.merge(issuer)
        # Monotone safety: repeated verification stays rejected.
        for _ in range(3):
            with pytest.raises(RevokedAncestorError):
                await verifier.verify(token)


# ---------------------------------------------------------------------------
# Property-based invariants
# ---------------------------------------------------------------------------


class TestProperties:
    @settings(max_examples=200)
    @given(
        parent=st.lists(st.sampled_from(SCOPES), unique=True, min_size=1),
        child=st.lists(st.sampled_from(SCOPES), unique=True, min_size=1),
    )
    def test_delegate_iff_subset(self, parent: list[str], child: list[str]) -> None:
        async def run() -> None:
            auth = _auth()
            root = await auth.issue(AgentId("a"), parent)
            if set(child) <= set(parent):
                tok = await auth.delegate(root, AgentId("b"), child, ttl=100.0)
                assert set(auth.describe(tok).scopes) == set(child)
            else:
                with pytest.raises(ScopeEscalationError):
                    await auth.delegate(root, AgentId("b"), child, ttl=100.0)

        asyncio.run(run())

    @settings(max_examples=100)
    @given(depth=st.integers(min_value=1, max_value=6), revoke_at=st.integers(min_value=0))
    def test_revoking_any_ancestor_severs_all_at_or_below(self, depth: int, revoke_at: int) -> None:
        revoke_level = revoke_at % (depth + 1)  # 0..depth

        async def run() -> None:
            auth = _auth()
            tokens: list[Token] = [await auth.issue(AgentId("a0"), ["read"])]
            for i in range(1, depth + 1):
                tokens.append(
                    await auth.delegate(tokens[-1], AgentId(f"a{i}"), ["read"], ttl=100.0)
                )
            await auth.revoke(tokens[revoke_level])
            for level, tok in enumerate(tokens):
                if level >= revoke_level:
                    with pytest.raises(RevokedAncestorError):
                        await auth.verify(tok)
                else:
                    assert (await auth.verify(tok)) is not None

        asyncio.run(run())

    @settings(max_examples=200)
    @given(
        xs=st.sets(st.text(min_size=1, max_size=6)),
        ys=st.sets(st.text(min_size=1, max_size=6)),
    )
    def test_merge_commutative_and_idempotent(self, xs: set[str], ys: set[str]) -> None:
        def built(seals: set[str]) -> RevocationSet:
            r = RevocationSet()
            for s in seals:
                r.revoke(s)
            return r

        ab = built(xs)
        ab.merge(built(ys))
        ba = built(ys)
        ba.merge(built(xs))
        assert ab.snapshot() == ba.snapshot() == (xs | ys)  # commutative
        ab.merge(built(ys))
        assert ab.snapshot() == (xs | ys)  # idempotent

    @settings(max_examples=100)
    @given(
        subject=st.text(alphabet="abcdefghij", min_size=1, max_size=8),
        scopes=st.lists(st.sampled_from(SCOPES), unique=True, min_size=1),
    )
    def test_issue_is_deterministic(self, subject: str, scopes: list[str]) -> None:
        async def run() -> None:
            a = CrdtDelegatableAuth(secret=b"k", clock=LogicalClock(0.0))
            b = CrdtDelegatableAuth(secret=b"k", clock=LogicalClock(0.0))
            assert (await a.issue(AgentId(subject), scopes)) == (
                await b.issue(AgentId(subject), scopes)
            )

        asyncio.run(run())
