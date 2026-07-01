# SPDX-License-Identifier: Apache-2.0
"""Conformance, adversarial, and property tests for the delegatable auth plugin.

Coverage:

* **Protocol conformance** — implements ``nest_core.layers.auth.Auth`` and the
  happy-path issue/verify round-trip.
* **Delegation semantics** — scope narrowing, ttl clamping, and the macaroon
  property that delegation needs the parent token but *not* the root secret.
* **Adversarial (verify-time) defenses** — hand-forged tokens that widen scope
  or outlive their parent carry a *valid signature* (an attacker holds the
  parent's tip signature and can append a link), yet ``verify`` rejects them.
* **Cascading revocation** — revoking an ancestor fails every descendant;
  revoking a child leaves the parent intact.
* **Determinism** — identical operations produce byte-identical tokens.
* **Property-based** — random subset delegations never widen scope; random
  chains revoke transitively.
* **Validator discrimination** — the shipped adversarial validator FAILS
  against the reference ``jwt`` plugin and PASSES against this one.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
from typing import Any

from hypothesis import given, settings
from hypothesis import strategies as st
from nest_core.types import AgentId, Token
from nest_plugins_reference.auth.delegatable import (
    AudienceConfusionError,
    DelegatableAuth,
    ExpiredTokenError,
    InvalidTokenError,
    RevokedAncestorError,
    ScopeEscalationError,
    TokenTtlError,
)
from nest_plugins_reference.auth.jwt_auth import JwtAuth
from nest_plugins_reference.validators import (
    GrantObservation,
    check_delegation_safety,
)

COORD = AgentId("coordinator-0")
BOB = AgentId("worker-bob")
ALICE = AgentId("worker-alice")
MALLORY = AgentId("mallory-0")


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Protocol conformance + happy path
# ---------------------------------------------------------------------------


def test_implements_auth_protocol() -> None:
    """Runtime structural check against the Auth protocol."""
    from nest_core.layers.auth import Auth

    assert isinstance(DelegatableAuth(), Auth)


def test_issue_and_verify_roundtrip() -> None:
    auth = DelegatableAuth(secret=b"s")
    root = _run(auth.issue(COORD, ["write", "read", "read"]))  # dupes tolerated
    ctx = _run(auth.verify(root))
    assert ctx.subject == COORD
    assert ctx.scopes == ["read", "write"]  # normalized: sorted + deduped


def test_describe_exposes_chain_root_first() -> None:
    auth = DelegatableAuth(secret=b"s")
    root = _run(auth.issue(COORD, ["read"]))
    child = _run(auth.delegate(root, BOB, ["read"], ttl=100))
    links = auth.describe(child)
    assert len(links) == 2
    assert links[0].parent is None
    assert links[0].sub == str(COORD)
    assert links[1].parent == links[0].jti
    assert links[1].sub == str(BOB)


# ---------------------------------------------------------------------------
# Delegation semantics
# ---------------------------------------------------------------------------


def test_delegate_narrows_scopes() -> None:
    auth = DelegatableAuth(secret=b"s")
    root = _run(auth.issue(COORD, ["read", "write", "admin"]))
    child = _run(auth.delegate(root, BOB, ["read"], ttl=100))
    ctx = _run(auth.verify(child))
    assert ctx.subject == BOB
    assert ctx.scopes == ["read"]


def test_delegate_rejects_scope_escalation() -> None:
    auth = DelegatableAuth(secret=b"s")
    root = _run(auth.issue(COORD, ["read"]))
    try:
        _run(auth.delegate(root, BOB, ["read", "admin"], ttl=100))
    except ScopeEscalationError:
        return
    raise AssertionError("delegate should have raised ScopeEscalationError")


def test_delegate_needs_parent_token_not_root_secret() -> None:
    """Macaroon property: a party without the authority's secret can delegate."""
    authority = DelegatableAuth(secret=b"the-real-secret")
    root = _run(authority.issue(COORD, ["read", "write"]))

    # A different agent holds only the parent token and a *wrong* secret.
    delegator = DelegatableAuth(secret=b"wrong-secret")
    child = _run(delegator.delegate(root, BOB, ["read"], ttl=100))

    # The authority still verifies the child: the child's signature is anchored
    # to the parent's tip signature, which never required the root secret.
    ctx = _run(authority.verify(child))
    assert ctx.subject == BOB and ctx.scopes == ["read"]


def test_ttl_clamped_to_parent_expiry() -> None:
    auth = DelegatableAuth(secret=b"s", clock=0, root_ttl=500)
    root = _run(auth.issue(COORD, ["read"]))  # exp = 500
    child = _run(auth.delegate(root, BOB, ["read"], ttl=10_000))  # asks to outlive
    (root_link, child_link) = auth.describe(child)
    assert child_link.exp == root_link.exp == 500  # clamped, never outlives parent


def test_delegate_rejects_nonpositive_ttl() -> None:
    auth = DelegatableAuth(secret=b"s")
    root = _run(auth.issue(COORD, ["read"]))
    try:
        _run(auth.delegate(root, BOB, ["read"], ttl=0))
    except TokenTtlError:
        return
    raise AssertionError("ttl=0 should raise TokenTtlError")


# ---------------------------------------------------------------------------
# Verify-time defenses against forged (validly-signed) tokens
# ---------------------------------------------------------------------------


def _canon(link: dict[str, Any]) -> bytes:
    return json.dumps(link, sort_keys=True, separators=(",", ":")).encode()


def _jti(sub: str, scopes: list[str], iat: int, exp: int, parent: str | None) -> str:
    material = json.dumps(
        {"sub": sub, "scopes": scopes, "iat": iat, "exp": exp, "parent": parent},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(material).hexdigest()[:16]


def _forge_child(parent_token: Token, audience: AgentId, scopes: list[str], exp: int) -> Token:
    """Append a validly-signed child link to a parent token, off-protocol.

    Uses only the parent's tip signature (public, in the token) — exactly what a
    real attacker holding the parent token could compute.  The resulting token
    has a correct HMAC chain and content-addressed ids; only ``verify``'s
    semantic monotonicity checks can catch it.
    """
    body = json.loads(str(parent_token))
    parent_link = body["chain"][-1]
    norm = sorted(set(scopes))
    jti = _jti(str(audience), norm, 0, exp, parent_link["jti"])
    child = {
        "jti": jti,
        "sub": str(audience),
        "scopes": norm,
        "iat": 0,
        "exp": exp,
        "parent": parent_link["jti"],
    }
    new_chain = [*body["chain"], child]
    sig = hmac.new(body["sig"].encode(), _canon(child), hashlib.sha256).hexdigest()
    forged = {"chain": new_chain, "sig": sig}
    return Token(json.dumps(forged, sort_keys=True, separators=(",", ":")))


def test_verify_rejects_forged_scope_widening() -> None:
    auth = DelegatableAuth(secret=b"s", root_ttl=1000)
    root = _run(auth.issue(COORD, ["read"]))
    forged = _forge_child(root, BOB, ["read", "admin"], exp=1000)  # widened scope
    try:
        _run(auth.verify(forged))
    except ScopeEscalationError:
        return
    raise AssertionError("verify must reject a validly-signed but scope-widened token")


def test_verify_rejects_forged_ttl_extension() -> None:
    auth = DelegatableAuth(secret=b"s", root_ttl=1000)
    root = _run(auth.issue(COORD, ["read"]))
    forged = _forge_child(root, BOB, ["read"], exp=5000)  # outlives parent (exp 1000)
    try:
        _run(auth.verify(forged))
    except TokenTtlError:
        return
    raise AssertionError("verify must reject a child that outlives its parent")


def test_verify_rejects_tampered_scope_without_jti_fix() -> None:
    auth = DelegatableAuth(secret=b"s")
    root = _run(auth.issue(COORD, ["read"]))
    body = json.loads(str(root))
    body["chain"][0]["scopes"] = ["read", "admin"]  # tamper, leave jti stale
    tampered = Token(json.dumps(body))
    try:
        _run(auth.verify(tampered))
    except InvalidTokenError:
        return
    raise AssertionError("verify must reject a link whose id no longer matches content")


def test_verify_rejects_malformed_token() -> None:
    auth = DelegatableAuth(secret=b"s")
    try:
        _run(auth.verify(Token("not-json")))
    except InvalidTokenError:
        return
    raise AssertionError("verify must reject non-JSON tokens")


# ---------------------------------------------------------------------------
# Audience binding
# ---------------------------------------------------------------------------


def test_verify_presented_accepts_declared_audience() -> None:
    auth = DelegatableAuth(secret=b"s")
    root = _run(auth.issue(COORD, ["read"]))
    child = _run(auth.delegate(root, BOB, ["read"], ttl=100))
    ctx = _run(auth.verify_presented(child, BOB))
    assert ctx.subject == BOB


def test_verify_presented_rejects_audience_confusion() -> None:
    auth = DelegatableAuth(secret=b"s")
    root = _run(auth.issue(COORD, ["read"]))
    child = _run(auth.delegate(root, BOB, ["read"], ttl=100))
    try:
        _run(auth.verify_presented(child, MALLORY))
    except AudienceConfusionError:
        return
    raise AssertionError("a token minted for BOB must not verify when MALLORY presents it")


# ---------------------------------------------------------------------------
# Cascading revocation
# ---------------------------------------------------------------------------


def test_revoke_ancestor_cascades_to_descendants() -> None:
    auth = DelegatableAuth(secret=b"s")
    root = _run(auth.issue(COORD, ["read", "write"]))
    child = _run(auth.delegate(root, BOB, ["read", "write"], ttl=1000))
    grandchild = _run(auth.delegate(child, ALICE, ["read"], ttl=500))

    assert _run(auth.verify(grandchild)).subject == ALICE  # ok before revoke
    _run(auth.revoke(root))  # revoke the *root*

    for tok in (root, child, grandchild):
        try:
            _run(auth.verify(tok))
        except RevokedAncestorError:
            continue
        raise AssertionError("revoking the root must fail every descendant")


def test_revoke_child_leaves_parent_valid() -> None:
    auth = DelegatableAuth(secret=b"s")
    root = _run(auth.issue(COORD, ["read", "write"]))
    child = _run(auth.delegate(root, BOB, ["read"], ttl=1000))
    _run(auth.revoke(child))

    assert _run(auth.verify(root)).subject == COORD  # parent unaffected
    try:
        _run(auth.verify(child))
    except RevokedAncestorError:
        return
    raise AssertionError("the revoked child itself must fail")


def test_expired_token_rejected_against_logical_clock() -> None:
    auth = DelegatableAuth(secret=b"s", clock=0, root_ttl=1000)
    root = _run(auth.issue(COORD, ["read"]))
    child = _run(auth.delegate(root, BOB, ["read"], ttl=50))  # exp = 50
    assert _run(auth.verify(child)).subject == BOB
    auth.advance(100)  # now = 100 > 50
    try:
        _run(auth.verify(child))
    except ExpiredTokenError:
        return
    raise AssertionError("verify must reject a token expired against the logical clock")


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


def test_same_ops_produce_byte_identical_tokens() -> None:
    def build() -> tuple[str, str]:
        auth = DelegatableAuth(secret=b"seed", clock=0)
        root = _run(auth.issue(COORD, ["read", "write"]))
        child = _run(auth.delegate(root, BOB, ["read"], ttl=100))
        return str(root), str(child)

    assert build() == build()


# ---------------------------------------------------------------------------
# Property-based
# ---------------------------------------------------------------------------

_SCOPE_POOL = ["read", "write", "admin", "delete", "list"]


@settings(max_examples=60, deadline=None)
@given(
    root_scopes=st.sets(st.sampled_from(_SCOPE_POOL), min_size=1),
    requested=st.sets(st.sampled_from(_SCOPE_POOL), min_size=1),
)
def test_property_delegation_never_widens(root_scopes: set[str], requested: set[str]) -> None:
    """delegate accepts iff requested ⊆ root, and verify returns exactly it."""
    auth = DelegatableAuth(secret=b"s")
    root = _run(auth.issue(COORD, sorted(root_scopes)))
    if requested <= root_scopes:
        child = _run(auth.delegate(root, BOB, sorted(requested), ttl=100))
        ctx = _run(auth.verify(child))
        assert set(ctx.scopes) == requested
    else:
        try:
            _run(auth.delegate(root, BOB, sorted(requested), ttl=100))
        except ScopeEscalationError:
            return
        raise AssertionError("a superset request must raise ScopeEscalationError")


@settings(max_examples=40, deadline=None)
@given(depth=st.integers(min_value=1, max_value=6), revoke_at=st.integers(min_value=0))
def test_property_revocation_cascades_at_any_depth(depth: int, revoke_at: int) -> None:
    """Revoking link k fails links k..depth and leaves links 0..k-1 valid."""
    revoke_at = revoke_at % depth if depth else 0
    auth = DelegatableAuth(secret=b"s", root_ttl=10_000)
    chain_tokens: list[Token] = [_run(auth.issue(COORD, ["read"]))]
    for i in range(1, depth):
        parent = chain_tokens[-1]
        chain_tokens.append(_run(auth.delegate(parent, AgentId(f"a-{i}"), ["read"], ttl=1000)))

    _run(auth.revoke(chain_tokens[revoke_at]))

    for i, tok in enumerate(chain_tokens):
        if i < revoke_at:
            assert _run(auth.verify(tok)).scopes == ["read"]  # ancestors unaffected
        else:
            try:
                _run(auth.verify(tok))
            except RevokedAncestorError:
                continue
            raise AssertionError(f"link {i} at/under revoked {revoke_at} must fail")


# ---------------------------------------------------------------------------
# Adversarial validator discrimination — jwt FAILS, delegatable PASSES
# ---------------------------------------------------------------------------


def _fake_jti(token: Token) -> str:
    return hashlib.sha256(str(token).encode()).hexdigest()[:16]


def _probe_delegatable() -> tuple[list[GrantObservation], dict[str, tuple[str, ...]], set[str]]:
    """Drive the delegatable plugin through all three attacks + one legit grant."""
    auth = DelegatableAuth(secret=b"s", root_ttl=10_000)
    grants: list[GrantObservation] = []
    parent_scopes: dict[str, tuple[str, ...]] = {}

    # Subtree 1 — revoked, used for the scope-escalation and stale-ancestor probes.
    root1 = _run(auth.issue(COORD, ["read", "write"]))
    root1_jti = auth.describe(root1)[-1].jti
    parent_scopes[root1_jti] = ("read", "write")

    # Attack: scope escalation — refused at delegate.
    try:
        _run(auth.delegate(root1, BOB, ["read", "write", "admin"], ttl=100))
        esc_verified = True
    except ScopeEscalationError:
        esc_verified = False
    grants.append(
        GrantObservation(
            jti="escalation-attempt",
            parent_jti=root1_jti,
            audience=BOB,
            scopes=("read", "write", "admin"),
            presenter=BOB,
            verified=esc_verified,
        )
    )

    # Attack: stale ancestor — child verifies now, then root1 is revoked.
    child = _run(auth.delegate(root1, BOB, ["read"], ttl=100))
    child_jti = auth.describe(child)[-1].jti
    _run(auth.revoke(root1))
    try:
        _run(auth.verify_presented(child, BOB))
        stale_verified = True
    except RevokedAncestorError:
        stale_verified = False
    grants.append(
        GrantObservation(
            jti=child_jti,
            parent_jti=root1_jti,
            audience=BOB,
            scopes=("read",),
            presenter=BOB,
            verified=stale_verified,
        )
    )

    # Subtree 2 — not revoked, used for the audience-confusion + legit probes.
    root2 = _run(auth.issue(ALICE, ["read"]))
    root2_jti = auth.describe(root2)[-1].jti
    parent_scopes[root2_jti] = ("read",)

    # Attack: audience confusion — token for BOB presented by MALLORY.
    child2 = _run(auth.delegate(root2, BOB, ["read"], ttl=100))
    child2_jti = auth.describe(child2)[-1].jti
    try:
        _run(auth.verify_presented(child2, MALLORY))
        conf_verified = True
    except AudienceConfusionError:
        conf_verified = False
    grants.append(
        GrantObservation(
            jti=child2_jti,
            parent_jti=root2_jti,
            audience=BOB,
            scopes=("read",),
            presenter=MALLORY,
            verified=conf_verified,
        )
    )

    # A legitimate grant that must verify cleanly (so PASS is not vacuous).
    child_ok = _run(auth.delegate(root2, ALICE, ["read"], ttl=100))
    child_ok_jti = auth.describe(child_ok)[-1].jti
    _run(auth.verify_presented(child_ok, ALICE))
    grants.append(
        GrantObservation(
            jti=child_ok_jti,
            parent_jti=root2_jti,
            audience=ALICE,
            scopes=("read",),
            presenter=ALICE,
            verified=True,
        )
    )
    return grants, parent_scopes, {root1_jti}


def _probe_jwt() -> tuple[list[GrantObservation], dict[str, tuple[str, ...]], set[str]]:
    """Drive the flat jwt plugin through the same three attacks — all succeed."""
    auth = JwtAuth(clock=0.0)
    grants: list[GrantObservation] = []
    parent_scopes: dict[str, tuple[str, ...]] = {}

    root1 = _run(auth.issue(COORD, ["read", "write"]))
    root1_jti = _fake_jti(root1)
    parent_scopes[root1_jti] = ("read", "write")

    # Attack: scope escalation — jwt re-issues with any scopes; verify accepts.
    esc = _run(auth.issue(BOB, ["read", "write", "admin"]))
    _run(auth.verify(esc))  # succeeds
    grants.append(
        GrantObservation(
            jti=_fake_jti(esc),
            parent_jti=root1_jti,
            audience=BOB,
            scopes=("read", "write", "admin"),
            presenter=BOB,
            verified=True,
        )
    )

    # Attack: stale ancestor — revoking the "parent" string leaves the child valid.
    child = _run(auth.issue(BOB, ["read"]))
    _run(auth.revoke(root1))
    _run(auth.verify(child))  # still succeeds
    grants.append(
        GrantObservation(
            jti=_fake_jti(child),
            parent_jti=root1_jti,
            audience=BOB,
            scopes=("read",),
            presenter=BOB,
            verified=True,
        )
    )

    root2 = _run(auth.issue(ALICE, ["read"]))
    root2_jti = _fake_jti(root2)
    parent_scopes[root2_jti] = ("read",)

    # Attack: audience confusion — no audience binding, anyone may present.
    child2 = _run(auth.issue(BOB, ["read"]))
    _run(auth.verify(child2))  # MALLORY presenting: jwt cannot tell
    grants.append(
        GrantObservation(
            jti=_fake_jti(child2),
            parent_jti=root2_jti,
            audience=BOB,
            scopes=("read",),
            presenter=MALLORY,
            verified=True,
        )
    )
    return grants, parent_scopes, {root1_jti}


def test_validator_passes_against_delegatable() -> None:
    grants, parent_scopes, revoked = _probe_delegatable()
    audit = check_delegation_safety(grants, parent_scopes=parent_scopes, revoked_jtis=revoked)
    assert audit.passed, {k: v.detail for k, v in audit.reports.items()}


def test_validator_fails_against_jwt() -> None:
    grants, parent_scopes, revoked = _probe_jwt()
    audit = check_delegation_safety(grants, parent_scopes=parent_scopes, revoked_jtis=revoked)
    assert not audit.passed
    assert not audit.reports["scope_escalation"].passed
    assert not audit.reports["stale_ancestor"].passed
    assert not audit.reports["audience_confusion"].passed
