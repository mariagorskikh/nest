# SPDX-License-Identifier: Apache-2.0
"""Hypothesis properties for capability-token attenuation and revocation."""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from nest_core.types import AgentId, Token
from nest_plugins_reference.auth.capability_tokens import (
    CapabilityTokens,
    InvalidChainError,
    RevokedAncestorError,
)

_SCOPE_POOL = [
    "alpha:read",
    "alpha:write",
    "beta:read",
    "payments:read",
    "registry:lookup",
    "memory:append",
]


def _flip_one_character(raw: str, index: int) -> str:
    replacement = "A" if raw[index] != "A" else "B"
    return raw[:index] + replacement + raw[index + 1 :]


@given(
    root_scopes=st.lists(st.sampled_from(_SCOPE_POOL), min_size=1, unique=True),
    selectors=st.lists(st.integers(min_value=0, max_value=1000), min_size=1, max_size=6),
)
@settings(max_examples=150, deadline=None)
@pytest.mark.asyncio
async def test_property_attenuation_monotonicity_never_widens_scope_or_ttl(
    root_scopes: list[str],
    selectors: list[int],
) -> None:
    """Any generated delegation chain only shrinks scopes and expiry."""
    auth = CapabilityTokens(secret=b"property-secret", root_ttl=100.0, clock=0.0)
    token = await auth.issue(AgentId("root"), root_scopes)
    parent_ctx = await auth.verify_for_audience(token, AgentId("root"))
    parent_scopes = set(parent_ctx.scopes)
    parent_exp = float(parent_ctx.expires_at or 0.0)

    for depth, selector in enumerate(selectors):
        ordered_scopes = sorted(parent_scopes)
        child_scope_count = 1 + selector % len(ordered_scopes)
        child_scopes = ordered_scopes[:child_scope_count]
        ttl = float(selector % (int(parent_exp) + 1)) if parent_exp > 0 else 0.0
        audience = AgentId(f"node-{depth}")
        token = await auth.delegate(token, audience, child_scopes, ttl=ttl)
        child_ctx = await auth.verify_for_audience(token, audience)

        assert set(child_ctx.scopes) <= parent_scopes
        assert float(child_ctx.expires_at or 0.0) <= parent_exp
        parent_scopes = set(child_ctx.scopes)
        parent_exp = float(child_ctx.expires_at or 0.0)


@given(
    depth=st.integers(min_value=2, max_value=6),
    revoke_selector=st.integers(min_value=0, max_value=100),
)
@settings(max_examples=100, deadline=None)
@pytest.mark.asyncio
async def test_property_revocation_completeness_kills_every_descendant(
    depth: int,
    revoke_selector: int,
) -> None:
    """Revoking any generated ancestor kills it and all descendants."""
    auth = CapabilityTokens(secret=b"property-secret", root_ttl=100.0, clock=0.0)
    tokens: list[tuple[AgentId, Token]] = []
    token = await auth.issue(AgentId("root"), ["alpha:read", "alpha:write"])
    tokens.append((AgentId("root"), token))
    for index in range(1, depth):
        audience = AgentId(f"node-{index}")
        token = await auth.delegate(token, audience, ["alpha:read"], ttl=float(100 - index))
        tokens.append((audience, token))

    revoke_index = revoke_selector % (depth - 1)
    await auth.revoke(tokens[revoke_index][1])

    for audience, descendant in tokens[revoke_index:]:
        with pytest.raises(RevokedAncestorError):
            await auth.verify_for_audience(descendant, audience)


@given(
    depth=st.integers(min_value=1, max_value=5),
    flip_selector=st.integers(min_value=0, max_value=10_000),
)
@settings(max_examples=120, deadline=None)
@pytest.mark.asyncio
async def test_property_chain_tamper_detection_flipping_any_selected_byte_fails_verify(
    depth: int,
    flip_selector: int,
) -> None:
    """A one-character mutation anywhere selected in the token kills verification."""
    auth = CapabilityTokens(secret=b"property-secret", root_ttl=100.0, clock=0.0)
    token = await auth.issue(AgentId("root"), ["alpha:read", "alpha:write"])
    audience = AgentId("root")
    for index in range(1, depth):
        audience = AgentId(f"node-{index}")
        token = await auth.delegate(token, audience, ["alpha:read"], ttl=float(100 - index))

    raw = str(token)
    tampered = Token(_flip_one_character(raw, flip_selector % len(raw)))
    with pytest.raises(InvalidChainError):
        await auth.verify_for_audience(tampered, audience)
