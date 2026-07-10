# SPDX-License-Identifier: Apache-2.0
"""Unit + adversarial tests for the macaroon capability-token auth plugin.

Covers the happy path (issue → delegate → verify), each typed rejection, the
cascading-revocation invariant, and — via the shared probes in
``capability_delegation_validators`` — the three attacks the plugin must defeat and the
reference ``jwt`` plugin must fail. A cross-plugin parametrization asserts the
"adversarial" property directly: every probe passes against ``macaroon`` and
at least one fails against ``jwt``.
"""

from __future__ import annotations

import pytest
from nest_core.types import AgentId
from nest_plugins_reference.auth.macaroon import (
    AudienceMismatchError,
    MacaroonAuth,
    ExpiredTokenError,
    InvalidTokenError,
    RevokedAncestorError,
    ScopeEscalationError,
    TtlViolationError,
    attenuate,
)
from nest_plugins_reference.auth.jwt_auth import JwtAuth
from nest_plugins_reference.validators.capability_delegation_validators import (
    blind_verify,
    macaroon_delegate,
    naive_jwt_delegate,
    presenter_verify,
    run_all_probes,
)


def _auth() -> MacaroonAuth:
    return MacaroonAuth(secret=b"unit-test-secret", clock=0.0)


@pytest.mark.asyncio
async def test_issue_and_verify_root() -> None:
    """A freshly issued root token verifies and carries its scopes."""
    auth = _auth()
    root = await auth.issue(AgentId("a"), ["read", "write"])
    ctx = await auth.verify(root)
    assert ctx.subject == AgentId("a")
    assert set(ctx.scopes) == {"read", "write"}


@pytest.mark.asyncio
async def test_delegate_narrows_scope_and_binds_audience() -> None:
    """A delegated child carries the subset scope and its audience."""
    auth = _auth()
    root = await auth.issue(AgentId("a"), ["read", "write"])
    child = await auth.delegate(root, AgentId("b"), ["read"], ttl=60.0)
    ctx = await auth.verify(child, presenter=AgentId("b"))
    assert ctx.subject == AgentId("b")
    assert ctx.scopes == ["read"]


@pytest.mark.asyncio
async def test_scope_escalation_rejected_at_mint() -> None:
    """Delegating a scope the parent lacks raises at mint time."""
    auth = _auth()
    root = await auth.issue(AgentId("a"), ["read"])
    with pytest.raises(ScopeEscalationError):
        await auth.delegate(root, AgentId("b"), ["read", "write"], ttl=60.0)


@pytest.mark.asyncio
async def test_scope_escalation_rejected_at_verify_when_chain_tampered() -> None:
    """A hand-forged broadening link verifies its HMAC but fails the subset check."""
    import hashlib
    import hmac
    import json

    auth = _auth()
    root = await auth.issue(AgentId("a"), ["read"])
    child = await auth.delegate(root, AgentId("b"), ["read"], ttl=60.0)
    data = json.loads(str(child))
    broadened = dict(data["chain"][-1])
    broadened["scopes"] = ["read", "write"]
    canon = json.dumps(broadened, sort_keys=True, separators=(",", ":"))
    forged_sig = hmac.new(data["sig"].encode(), canon.encode(), hashlib.sha256).hexdigest()
    forged = json.dumps(
        {"chain": [*data["chain"], broadened], "sig": forged_sig},
        sort_keys=True,
        separators=(",", ":"),
    )
    with pytest.raises(ScopeEscalationError):
        await auth.verify(forged)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_cascading_revocation_two_levels() -> None:
    """Revoking a grandparent invalidates a grandchild."""
    auth = _auth()
    root = await auth.issue(AgentId("a"), ["read", "write"])
    child = await auth.delegate(root, AgentId("b"), ["read"], ttl=120.0)
    grandchild = await auth.delegate(child, AgentId("c"), ["read"], ttl=60.0)
    assert (await auth.verify(grandchild, presenter=AgentId("c"))).scopes == ["read"]
    await auth.revoke(root)
    with pytest.raises(RevokedAncestorError):
        await auth.verify(grandchild, presenter=AgentId("c"))


@pytest.mark.asyncio
async def test_revoking_middle_link_spares_siblings() -> None:
    """Revoking one child does not revoke a sibling delegated from the same root."""
    auth = _auth()
    root = await auth.issue(AgentId("a"), ["read", "write"])
    child1 = await auth.delegate(root, AgentId("b"), ["read"], ttl=60.0)
    child2 = await auth.delegate(root, AgentId("c"), ["write"], ttl=60.0)
    await auth.revoke(child1)
    with pytest.raises(RevokedAncestorError):
        await auth.verify(child1, presenter=AgentId("b"))
    assert (await auth.verify(child2, presenter=AgentId("c"))).scopes == ["write"]


@pytest.mark.asyncio
async def test_audience_confusion_rejected() -> None:
    """Presenting a token from the wrong audience raises."""
    auth = _auth()
    root = await auth.issue(AgentId("a"), ["read"])
    child = await auth.delegate(root, AgentId("b"), ["read"], ttl=60.0)
    with pytest.raises(AudienceMismatchError):
        await auth.verify(child, presenter=AgentId("c"))


@pytest.mark.asyncio
async def test_ttl_nesting_enforced_at_mint() -> None:
    """A child may not outlive its parent."""
    auth = _auth()
    root = await auth.issue(AgentId("a"), ["read"])  # exp = 3600
    # Parent iat=0, exp=3600; a 4000-tick child would exceed it.
    with pytest.raises(TtlViolationError):
        await auth.delegate(root, AgentId("b"), ["read"], ttl=4000.0)


@pytest.mark.asyncio
async def test_midlife_delegation_anchors_ttl_at_now() -> None:
    """Delegating mid-life anchors the child at the current clock, not the root's iat."""
    auth = MacaroonAuth(secret=b"s", clock=0.0)
    root = await auth.issue(AgentId("a"), ["read"])  # iat=0, exp=3600
    auth.set_clock(3000.0)
    child = await auth.delegate(root, AgentId("b"), ["read"], ttl=600.0)
    ctx = await auth.verify(child, presenter=AgentId("b"))
    assert ctx.issued_at == 3000.0
    assert ctx.expires_at == 3600.0  # capped exactly at the parent's expiry
    auth.set_clock(3500.0)
    assert (await auth.verify(child, presenter=AgentId("b"))).scopes == ["read"]


@pytest.mark.asyncio
async def test_midlife_delegation_that_would_outlive_parent_raises() -> None:
    """A ttl the parent cannot cover raises at mint — never a dead-on-arrival child."""
    auth = MacaroonAuth(secret=b"s", clock=0.0)
    root = await auth.issue(AgentId("a"), ["read"])  # exp=3600
    auth.set_clock(3000.0)
    with pytest.raises(TtlViolationError):
        await auth.delegate(root, AgentId("b"), ["read"], ttl=601.0)


@pytest.mark.asyncio
async def test_expiry_enforced_at_verify() -> None:
    """A token past its expiry fails verification against the logical clock."""
    auth = MacaroonAuth(secret=b"s", clock=0.0)
    root = await auth.issue(AgentId("a"), ["read"])
    child = await auth.delegate(root, AgentId("b"), ["read"], ttl=10.0)
    auth.set_clock(11.0)
    with pytest.raises(ExpiredTokenError):
        await auth.verify(child, presenter=AgentId("b"))


@pytest.mark.asyncio
async def test_tampered_signature_rejected() -> None:
    """Flipping a byte in the signature fails the HMAC chain check."""
    auth = _auth()
    root = await auth.issue(AgentId("a"), ["read"])
    tampered = str(root)[:-1] + ("0" if str(root)[-1] != "0" else "1")
    with pytest.raises(InvalidTokenError):
        await auth.verify(tampered)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_attenuate_is_offline_and_matches_delegate() -> None:
    """Offline ``attenuate`` yields a token the verifier accepts identically."""
    auth = _auth()
    root = await auth.issue(AgentId("a"), ["read", "write"])
    offline = attenuate(root, AgentId("b"), ["read"], ttl=60.0)
    ctx = await auth.verify(offline, presenter=AgentId("b"))
    assert ctx.scopes == ["read"]


@pytest.mark.asyncio
async def test_probes_pass_against_macaroon() -> None:
    """All three adversarial probes pass against the real plugin."""
    auth = _auth()
    reports = await run_all_probes(auth, macaroon_delegate, presenter_verify)
    assert all(r.passed for r in reports), [r.detail for r in reports if not r.passed]


@pytest.mark.asyncio
async def test_probes_fail_against_reference_jwt() -> None:
    """At least one probe fails against the reference jwt plugin (adversarial bar)."""
    auth = JwtAuth(secret=b"s", clock=0.0)
    reports = await run_all_probes(auth, naive_jwt_delegate, blind_verify)
    assert not all(r.passed for r in reports)
