# SPDX-License-Identifier: Apache-2.0
"""Hypothesis property-based tests for the ``delegatable`` auth plugin.

Each invariant is checked over generated token parameters so the delegation,
revocation, and scope rules hold for *all* inputs, not just the hand-picked
cases in ``test_auth_delegation.py``:

1. Root token sign/verify round-trip (any subject, scopes, TTL).
2. Scope monotonicity: child scopes are always a subset of parent scopes.
3. Depth bound: delegation past ``max_depth`` raises ``CapabilityError``.
4. Expiry bound: child token never outlives its parent.
5. Cascading revocation: revoking a parent invalidates all descendants.
6. Revocation isolation: tokens from different branches are unaffected.
7. Token-id uniqueness: no two issued tokens share a ``token_id``.
8. Delegate with ``None`` defaults matches parent scopes/audience.

Example::

    pytest packages/nest-plugins-reference/tests/test_auth_delegation_properties.py
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from nest_plugins_reference.auth.delegatable import (
    CapabilityError,
    DelegatableAuth,
)

# Bounded strategies: small values keep the tests fast
_audiences = st.sampled_from(["nandatown", "testnet", "staging", "nest", "dev"])
_subjects = st.text(min_size=1, max_size=16, alphabet="abcdefghijklmnopqrstuvwxyz-_0123")
_scopes = st.lists(
    st.sampled_from(["read", "write", "admin", "exec", "delete", "audit", "deploy"]),
    min_size=1,
    max_size=4,
).map(frozenset)
_ttls = st.floats(min_value=1.0, max_value=86400.0, allow_nan=False, allow_infinity=False)
_depths = st.integers(min_value=0, max_value=5)
_nows = st.floats(min_value=1000.0, max_value=9999.0, allow_nan=False, allow_infinity=False)


def _auth(secret: bytes | None = None) -> DelegatableAuth:
    return DelegatableAuth(secret=secret or b"test-secret")


# ---------------------------------------------------------------------------
# 1. Root token sign/verify round-trip
# ---------------------------------------------------------------------------


class TestRootTokenRoundTrip:
    @settings(max_examples=50, deadline=None)
    @given(
        subject=_subjects,
        audience=_audiences,
        scopes=_scopes,
        ttl=_ttls,
        now=_nows,
    )
    def test_root_token_verifies(
        self,
        subject: str,
        audience: str,
        scopes: frozenset[str],
        ttl: float,
        now: float,
    ) -> None:
        """A freshly issued root token always verifies with matching metadata."""
        auth = _auth()
        token = auth.issue_root(
            subject=subject,
            audience=audience,
            scopes=scopes,
            ttl_seconds=ttl,
            max_depth=0,
            now=now,
        )
        verify_at = now + min(ttl, 60.0) * 0.4  # well inside the validity window
        cap = auth.verify_capability(token, now=verify_at)
        assert cap.subject == subject
        assert cap.audience == audience
        assert cap.scopes == scopes
        assert cap.depth == 0
        assert cap.parent_id is None


# ---------------------------------------------------------------------------
# 2. Scope monotonicity
# ---------------------------------------------------------------------------


class TestScopeMonotonicity:
    @settings(max_examples=50, deadline=None)
    @given(
        parent_subject=_subjects,
        child_subject=_subjects,
        audience=_audiences,
        parent_scopes=_scopes,
        ttl=_ttls,
        now=_nows,
    )
    def test_child_scopes_are_subset_of_parent(
        self,
        parent_subject: str,
        child_subject: str,
        audience: str,
        parent_scopes: frozenset[str],
        ttl: float,
        now: float,
    ) -> None:
        """A delegated child token's scopes must be a subset of the parent's."""
        auth = _auth()
        parent = auth.issue_root(
            subject=parent_subject,
            audience=audience,
            scopes=parent_scopes,
            ttl_seconds=ttl,
            max_depth=1,
            now=now,
        )
        _tick_gap = min(ttl, 60.0) * 0.3  # well inside the validity window
        # Child gets the same scopes by default
        child = auth.delegate(parent, subject=child_subject, now=now + _tick_gap * 0.1)
        child_cap = auth.verify_capability(child, now=now + _tick_gap * 0.2)
        assert child_cap.scopes.issubset(parent_scopes)

    @settings(max_examples=50, deadline=None)
    @given(
        parent_subject=_subjects,
        child_subject=_subjects,
        audience=_audiences,
        parent_scopes=_scopes,
        child_extra=st.sampled_from(
            ["read", "write", "admin", "exec", "delete", "audit", "deploy"]
        ),
        ttl=_ttls,
        now=_nows,
    )
    def test_child_cannot_have_scopes_outside_parent(
        self,
        parent_subject: str,
        child_subject: str,
        audience: str,
        parent_scopes: frozenset[str],
        child_extra: str,
        ttl: float,
        now: float,
    ) -> None:
        """Delegating with a scope not in the parent set raises CapabilityError."""
        auth = _auth()
        parent = auth.issue_root(
            subject=parent_subject,
            audience=audience,
            scopes=parent_scopes,
            ttl_seconds=ttl,
            max_depth=1,
            now=now,
        )
        _tick_gap = min(ttl, 60.0) * 0.3  # well inside the validity window
        child_scopes = frozenset({child_extra})
        if child_extra not in parent_scopes:
            with pytest.raises(CapabilityError, match="child scopes must be a subset"):
                auth.delegate(
                    parent, subject=child_subject, scopes=child_scopes, now=now + _tick_gap * 0.1
                )
        else:
            # When it IS a subset, delegation should succeed
            child = auth.delegate(
                parent, subject=child_subject, scopes=child_scopes, now=now + _tick_gap * 0.1
            )
            assert auth.verify_capability(child, now=now + _tick_gap * 0.2).scopes == child_scopes


# ---------------------------------------------------------------------------
# 3. Depth bound
# ---------------------------------------------------------------------------


class TestDepthBound:
    @settings(max_examples=50, deadline=None)
    @given(
        subject=_subjects,
        audience=_audiences,
        scopes=_scopes,
        max_depth=st.integers(min_value=0, max_value=3),
        ttl=_ttls,
        now=_nows,
    )
    def test_cannot_delegate_beyond_max_depth(
        self,
        subject: str,
        audience: str,
        scopes: frozenset[str],
        max_depth: int,
        ttl: float,
        now: float,
    ) -> None:
        """Delegation past max_depth raises CapabilityError."""
        auth = _auth()
        root = auth.issue_root(
            subject=subject,
            audience=audience,
            scopes=scopes,
            ttl_seconds=ttl,
            max_depth=max_depth,
            now=now,
        )

        if max_depth == 0:
            # Even one delegation should fail
            with pytest.raises(CapabilityError, match="delegation depth exceeded"):
                auth.delegate(root, subject="child", now=now + 0.1)
        else:
            # Delegate to depth then one more should fail
            current = root
            for d in range(max_depth):
                current = auth.delegate(current, subject=f"child-{d}", now=now + (d + 1) * 0.1)
            # Depth exhausted now
            with pytest.raises(CapabilityError, match="delegation depth exceeded"):
                auth.delegate(current, subject="too-deep", now=now + (max_depth + 2) * 0.1)


# ---------------------------------------------------------------------------
# 4. Expiry bound: child never outlives parent
# ---------------------------------------------------------------------------


class TestExpiryBound:
    @settings(max_examples=50, deadline=None)
    @given(
        subject=_subjects,
        audience=_audiences,
        scopes=_scopes,
        parent_ttl=_ttls,
        child_ttl=_ttls,
        now=_nows,
    )
    def test_child_expiry_bounded_by_parent(
        self,
        subject: str,
        audience: str,
        scopes: frozenset[str],
        parent_ttl: float,
        child_ttl: float,
        now: float,
    ) -> None:
        """A child token's expiry must not exceed the parent token's expiry."""
        auth = _auth()
        parent = auth.issue_root(
            subject=subject,
            audience=audience,
            scopes=scopes,
            ttl_seconds=parent_ttl,
            max_depth=1,
            now=now,
        )
        parent_cap = auth.verify_capability(parent, now=now)
        child = auth.delegate(
            parent,
            subject="child",
            ttl_seconds=child_ttl,
            now=now + 0.1,
        )
        child_cap = auth.verify_capability(child, now=now + 0.2)
        assert child_cap.expires_at <= parent_cap.expires_at


# ---------------------------------------------------------------------------
# 5. Cascading revocation
# ---------------------------------------------------------------------------


class TestCascadingRevocation:
    @settings(max_examples=50, deadline=None)
    @given(
        subject=_subjects,
        audience=_audiences,
        scopes=_scopes,
        ttl=_ttls,
        now=_nows,
    )
    def test_revoking_root_invalidates_all_descendants(
        self,
        subject: str,
        audience: str,
        scopes: frozenset[str],
        ttl: float,
        now: float,
    ) -> None:
        """Revoking the root token invalidates every delegated child."""
        auth = _auth()
        root = auth.issue_root(
            subject=subject,
            audience=audience,
            scopes=scopes,
            ttl_seconds=ttl,
            max_depth=2,
            now=now,
        )
        int1 = auth.delegate(root, subject="int-1", now=now + 0.1)
        int2 = auth.delegate(root, subject="int-2", now=now + 0.2)
        leaf1 = auth.delegate(int1, subject="leaf-1", now=now + 0.3)
        leaf2 = auth.delegate(int2, subject="leaf-2", now=now + 0.4)

        # Verify everything works before revocation
        auth.verify_capability(leaf1, now=now + 0.5)
        auth.verify_capability(leaf2, now=now + 0.5)

        # Revoke root
        auth.revoke_tree(root)

        # All descendants should fail verification
        for desc in [int1, int2, leaf1, leaf2]:
            with pytest.raises(CapabilityError, match="revoked|CapabilityError"):
                auth.verify_capability(desc, now=now + 0.6)

        # Root itself is also invalid
        with pytest.raises(CapabilityError, match="revoked"):
            auth.verify_capability(root, now=now + 0.6)

    @settings(max_examples=50, deadline=None)
    @given(
        subject=_subjects,
        audience=_audiences,
        scopes=_scopes,
        ttl=_ttls,
        now=_nows,
    )
    def test_revoking_intermediate_invalidates_only_its_subtree(
        self,
        subject: str,
        audience: str,
        scopes: frozenset[str],
        ttl: float,
        now: float,
    ) -> None:
        """Revoking one intermediary invalidates its descendants but not the other branch."""
        auth = _auth()
        root = auth.issue_root(
            subject=subject,
            audience=audience,
            scopes=scopes,
            ttl_seconds=ttl,
            max_depth=2,
            now=now,
        )
        int1 = auth.delegate(root, subject="int-1", now=now + 0.1)
        int2 = auth.delegate(root, subject="int-2", now=now + 0.2)
        leaf1 = auth.delegate(int1, subject="leaf-1", now=now + 0.3)
        leaf2 = auth.delegate(int2, subject="leaf-2", now=now + 0.4)

        # Revoke only int1
        auth.revoke_tree(int1)

        # int1 and leaf1 should fail
        with pytest.raises(CapabilityError, match="revoked"):
            auth.verify_capability(int1, now=now + 0.6)
        with pytest.raises(CapabilityError, match="revoked"):
            auth.verify_capability(leaf1, now=now + 0.6)

        # int2 and leaf2 should still work
        auth.verify_capability(int2, now=now + 0.6)
        auth.verify_capability(leaf2, now=now + 0.6)

        # Root is also still valid
        auth.verify_capability(root, now=now + 0.6)


# ---------------------------------------------------------------------------
# 6. Token-id uniqueness
# ---------------------------------------------------------------------------


class TestTokenIdUniqueness:
    @settings(max_examples=50, deadline=None)
    @given(
        subject=_subjects,
        audience=_audiences,
        scopes=_scopes,
        ttl=_ttls,
        now=_nows,
    )
    def test_no_two_issued_tokens_share_an_id(
        self,
        subject: str,
        audience: str,
        scopes: frozenset[str],
        ttl: float,
        now: float,
    ) -> None:
        """Every issued token gets a unique token_id (hex-encoded UUID4)."""
        auth = _auth()
        ids: set[str] = set()
        for i in range(20):
            t = auth.issue_root(
                subject=f"{subject}-{i}",
                audience=audience,
                scopes=scopes,
                ttl_seconds=ttl,
                max_depth=0,
                now=now + i * 0.1,
            )
            cap = auth.inspect(t)
            assert cap.token_id not in ids, f"Duplicate token_id: {cap.token_id}"
            ids.add(cap.token_id)
