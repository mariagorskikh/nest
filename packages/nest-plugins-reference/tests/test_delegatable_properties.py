# SPDX-License-Identifier: Apache-2.0
"""Hypothesis property-based tests for DelegatableAuth.

Three invariants checked over generated inputs:

(a) Strict scope containment: for any parent scope set and any request,
    the delegated child's scopes are always a strict subset of parent scopes
    (or delegation raises ScopeEscalationError).

(b) Transitive revocation: revoking ANY node in a random chain makes
    verify raise for that node and all descendants.

(c) Determinism: issue+delegate with clock=0.0 and identical inputs
    yields byte-for-byte identical tokens across two separate instances.

Example::

    pytest packages/nest-plugins-reference/tests/test_delegatable_properties.py
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from nest_core.types import AgentId
from nest_plugins_reference.auth.delegatable import (
    DelegatableAuth,
    RevokedAncestorError,
    ScopeEscalationError,
)
from nest_plugins_reference.identity.ed25519_rotating import Ed25519RotatingIdentity
from nest_plugins_reference.policy import Budget, PolicyManifest, sign_manifest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TOOL_SCOPES = ["tool:buy", "tool:sell", "tool:transfer", "tool:query", "tool:report"]

_SCOPE_STRAT = st.lists(
    st.sampled_from(_TOOL_SCOPES),
    min_size=1,
    max_size=5,
    unique=True,
)


def _make_auth(tools: list[str] | None = None) -> DelegatableAuth:
    all_tools = tools or ["buy", "sell", "transfer", "query", "report"]
    ident = Ed25519RotatingIdentity(AgentId("root"), seed=b"prop-seed")
    manifest = PolicyManifest(
        agent_id=AgentId("root"),
        tools=all_tools,
        budget=Budget(cap=100_000),
    )
    signed = sign_manifest(ident, manifest)
    return DelegatableAuth(manifests={AgentId("root"): signed}, clock=0.0)


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# (a) Scope containment invariant
# ---------------------------------------------------------------------------


@settings(max_examples=200)
@given(parent_scopes=_SCOPE_STRAT, requested_scopes=_SCOPE_STRAT)
def test_delegate_scopes_always_subset_of_parent(
    parent_scopes: list[str], requested_scopes: list[str]
) -> None:
    """Child scopes are always a strict subset of parent, or ScopeEscalationError is raised."""
    auth = _make_auth()
    root = _run(auth.issue(AgentId("root"), parent_scopes))
    root_ctx = _run(auth.verify(root))
    actual_parent_scopes = set(root_ctx.scopes)
    requested_scope_set = set(requested_scopes)

    escalation_scopes = [s for s in requested_scopes if s not in actual_parent_scopes]

    if not requested_scope_set < actual_parent_scopes:
        with pytest.raises(ScopeEscalationError) as exc_info:
            _run(auth.delegate(root, AgentId("child"), requested_scopes, ttl=300))
        # All offending scopes must be named in the error
        for s in escalation_scopes:
            assert s in exc_info.value.offending
    else:
        child = _run(auth.delegate(root, AgentId("child"), requested_scopes, ttl=300))
        child_ctx = _run(auth.verify(child, presenter=AgentId("child")))
        assert set(child_ctx.scopes) <= actual_parent_scopes


# ---------------------------------------------------------------------------
# (b) Transitive revocation invariant
# ---------------------------------------------------------------------------


@settings(max_examples=100)
@given(
    depth=st.integers(min_value=1, max_value=4),
    revoke_at=st.integers(min_value=0, max_value=3),
)
def test_revoking_any_node_invalidates_descendants(depth: int, revoke_at: int) -> None:
    """Revoking any node in a chain invalidates that node and every descendant."""
    auth = _make_auth()
    # root -> chain of `depth` delegations
    chain: list[Any] = []

    current_scopes = ["tool:buy", "tool:sell", "tool:transfer", "tool:query", "tool:report"]
    root = _run(auth.issue(AgentId("root"), current_scopes))
    chain.append(root)

    current = root
    for i in range(depth):
        audience = AgentId(f"agent-{i}")
        child_scopes = current_scopes[:-1]
        if not child_scopes:
            break
        try:
            child = _run(auth.delegate(current, audience, child_scopes, ttl=3600))
        except Exception:
            # If ttl exceeds parent for some reason, stop building the chain
            break
        chain.append(child)
        current = child
        current_scopes = child_scopes

    if len(chain) < 2:
        return  # not enough tokens to test

    revoke_idx = min(revoke_at, len(chain) - 1)
    revoke_token = chain[revoke_idx]
    _run(auth.revoke(revoke_token))

    # Every token at revoke_idx and later must fail
    for i in range(revoke_idx, len(chain)):
        with pytest.raises(RevokedAncestorError):
            _run(auth.verify(chain[i]))

    # Every token before revoke_idx should still verify (for depth > 0)
    for i in range(0, revoke_idx):
        # These should not raise RevokedAncestorError
        try:
            _run(auth.verify(chain[i]))
        except RevokedAncestorError:
            pytest.fail(
                f"Token at index {i} (before revoke_idx {revoke_idx}) was unexpectedly invalidated"
            )


# ---------------------------------------------------------------------------
# (c) Determinism invariant
# ---------------------------------------------------------------------------


@settings(max_examples=100)
@given(scopes=_SCOPE_STRAT, child_scopes=_SCOPE_STRAT)
def test_delegate_deterministic_given_clock(scopes: list[str], child_scopes: list[str]) -> None:
    """issue + delegate with clock=0.0 yields identical bytes across two instances."""
    # Filter child scopes to be a subset of tool scopes that could appear in root
    # We'll just use the same scopes for both and accept ScopeEscalationError as a skip

    auth1 = _make_auth()
    auth2 = _make_auth()

    root1 = _run(auth1.issue(AgentId("root"), scopes))
    root2 = _run(auth2.issue(AgentId("root"), scopes))

    assert str(root1) == str(root2), "Root tokens must be identical for same inputs"

    # Only proceed with delegation if child_scopes is a strict subset of root scopes
    root1_ctx = _run(auth1.verify(root1))
    valid_child_scopes = [s for s in child_scopes if s in set(root1_ctx.scopes)]

    if not set(valid_child_scopes) < set(root1_ctx.scopes):
        return  # nothing to test

    # Both instances must produce identical child tokens
    child1 = _run(auth1.delegate(root1, AgentId("child"), valid_child_scopes, ttl=300))
    child2 = _run(auth2.delegate(root2, AgentId("child"), valid_child_scopes, ttl=300))

    assert str(child1) == str(child2), "Child tokens must be identical for same inputs"
