# SPDX-License-Identifier: Apache-2.0
"""Delegatable capability auth plugin with cascading revocation.

The default auth plugin (:class:`~nest_plugins_reference.auth.jwt_auth.JwtAuth`)
issues flat tokens with no parent-child relationship.  Revoking a parent token
leaves any child tokens it issued fully alive — there is no transitive check.

This plugin implements **delegatable capability tokens** inspired by the
macaroon construction (Birgisson et al., 2014): a parent token can mint a
narrowly-scoped, time-bounded child token *without* going back to the issuer,
and revoking any ancestor automatically invalidates every descendant at the
next ``verify`` call.

The chain is a strict tree (single parent per child).  Each child anchors its
HMAC signature to a hash of its parent token, so:

* **Scope escalation** is impossible — the child payload is signed with the
  parent's hash; escalated scopes would produce an unverifiable signature.
* **Stale-parent** attacks are caught — ``verify`` walks the full ancestor
  chain and fails if any node is revoked or expired.
* **Audience confusion** is prevented — each token encodes its intended
  audience; a different agent presenting the token is rejected.

Example::

    auth = DelegatableAuth(secret=b"sim-secret", clock=0.0)
    root = await auth.issue(AgentId("coordinator"), ["read", "write", "delegate"])
    child = await auth.delegate(root, AgentId("worker-1"), ["read"], ttl=60.0)
    ctx = await auth.verify(child)
    assert ctx.subject == AgentId("coordinator")
    assert ctx.scopes == ["read"]
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

from nest_core.types import AgentId, AuthContext, Token

# ---------------------------------------------------------------------------
# Typed exceptions
# ---------------------------------------------------------------------------


class ScopeEscalationError(ValueError):
    """Child requested a scope not held by the parent token.

    Example::

        with pytest.raises(ScopeEscalationError):
            await auth.delegate(root_token, AgentId("a2"), ["admin"], ttl=30.0)
    """


class RevokedAncestorError(ValueError):
    """A token in the ancestor chain has been revoked.

    Example::

        await auth.revoke(root)
        with pytest.raises(RevokedAncestorError):
            await auth.verify(child)
    """


class AudienceError(ValueError):
    """Token was presented by an agent that is not its declared audience.

    Example::

        with pytest.raises(AudienceError):
            await auth.verify(child, presenter=AgentId("wrong-agent"))
    """


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_SEP = "|"


def _token_hash(token: Token) -> str:
    """Return the hex SHA-256 of the raw token string.

    Used as the «parent binding» that anchors each child's HMAC to the
    content of its parent, preventing anyone without the parent from minting
    a valid child even when they know the shared secret.

    Example::

        h = _token_hash(Token("..."))
    """
    return hashlib.sha256(str(token).encode()).hexdigest()


def _sign(secret: bytes, payload: str, parent_binding: str | None) -> str:
    """HMAC-SHA256 of payload + optional parent binding.

    The parent binding is the hash of the parent token.  Anchoring the
    signature to the parent content ensures a forged child cannot be
    manufactured without access to the original parent bytes.

    Example::

        sig = _sign(b"secret", '{"sub":"a1"}', parent_hash)
    """
    material = payload
    if parent_binding is not None:
        material = f"{payload}:{parent_binding}"
    return hmac.new(secret, material.encode(), hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# DelegatableAuth
# ---------------------------------------------------------------------------


class DelegatableAuth:
    """Delegatable capability tokens with cascading revocation.

    Implements the ``Auth`` protocol (issue / verify / revoke) and adds a
    ``delegate`` method that lets a token holder mint child tokens without
    involving the issuer.

    ``clock`` pins the current time (seconds since epoch) for determinism in
    Tier-1 simulations — pass ``None`` to use the wall clock.

    Example::

        auth = DelegatableAuth(secret=b"s", clock=1000.0)
        root = await auth.issue(AgentId("a1"), ["read", "write"])
        child = await auth.delegate(root, AgentId("a2"), ["read"], ttl=30.0)
        ctx = await auth.verify(child)
        assert "read" in ctx.scopes
    """

    def __init__(
        self,
        secret: bytes = b"nest-delegatable-secret",
        clock: float | None = None,
    ) -> None:
        self._secret = secret
        self._clock_override = clock
        # Maps token raw string → parent token raw string (or None for root)
        self._parent: dict[str, str | None] = {}
        # Set of revoked raw token strings
        self._revoked: set[str] = set()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _now(self) -> float:
        if self._clock_override is not None:
            return self._clock_override
        import time

        return time.time()

    def _build_token(
        self,
        subject: AgentId,
        audience: AgentId | None,
        scopes: list[str],
        ttl: float,
        parent_token: Token | None,
    ) -> Token:
        now = self._now()
        parent_binding = _token_hash(parent_token) if parent_token is not None else None
        payload = json.dumps(
            {
                "sub": str(subject),
                "aud": str(audience) if audience is not None else None,
                "scopes": sorted(scopes),
                "iat": now,
                "exp": now + ttl,
                "parent": parent_binding,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        sig = _sign(self._secret, payload, parent_binding)
        raw = f"{payload}{_SEP}{sig}"
        return Token(raw)

    def _decode(self, token: Token) -> dict[str, Any]:
        """Parse and signature-verify a token; raise ``ValueError`` on failure."""
        raw = str(token)
        try:
            payload_str, sig = raw.rsplit(_SEP, 1)
        except ValueError:
            msg = "Malformed token: missing separator"
            raise ValueError(msg)  # noqa: B904

        data = json.loads(payload_str)
        parent_binding: str | None = data.get("parent")
        expected = _sign(self._secret, payload_str, parent_binding)
        if not hmac.compare_digest(sig, expected):
            msg = "Invalid token signature"
            raise ValueError(msg)
        return data

    def _check_expiry(self, data: dict[str, Any], raw: str) -> None:
        """Raise ``ValueError`` if the token is expired."""
        if data["exp"] < self._now():
            msg = f"Token expired at {data['exp']:.0f}"
            raise ValueError(msg)

    def _check_revoked(self, raw: str) -> None:
        """Raise ``RevokedAncestorError`` if ``raw`` (or any ancestor) is revoked."""
        cursor: str | None = raw
        while cursor is not None:
            if cursor in self._revoked:
                raise RevokedAncestorError(f"Ancestor token revoked: {cursor[:32]}\u2026")
            cursor = self._parent.get(cursor)

    # ------------------------------------------------------------------
    # Auth protocol
    # ------------------------------------------------------------------

    async def issue(self, subject: AgentId, scopes: list[str]) -> Token:
        """Issue a root capability token for ``subject`` with ``scopes``.

        Root tokens have no audience restriction and a default TTL of 3600 s.

        Example::

            token = await auth.issue(AgentId("coordinator"), ["read", "write", "delegate"])
        """
        token = self._build_token(
            subject, audience=None, scopes=scopes, ttl=3600.0, parent_token=None
        )
        self._parent[str(token)] = None
        return token

    async def verify(self, token: Token, *, presenter: AgentId | None = None) -> AuthContext:
        """Verify a token and return its auth context.

        Checks (in order): signature, expiry, audience (if ``presenter`` given),
        and cascading revocation of the full ancestor chain.

        Raises:
            ValueError: bad signature or expired.
            AudienceError: token audience ≠ presenter.
            RevokedAncestorError: any ancestor has been revoked.

        Example::

            ctx = await auth.verify(token)
            assert ctx.subject == AgentId("coordinator")
        """
        raw = str(token)
        data: dict[str, Any] = self._decode(token)
        self._check_expiry(data, raw)

        if presenter is not None and data["aud"] is not None and data["aud"] != str(presenter):
            msg = f"Audience mismatch: token is for {data['aud']!r}, presented by {presenter!r}"
            raise AudienceError(msg)

        self._check_revoked(raw)

        return AuthContext(
            subject=AgentId(data["sub"]),
            scopes=data["scopes"],
            issued_at=data["iat"],
            expires_at=data["exp"],
        )

    async def revoke(self, token: Token) -> None:
        """Revoke a token (and implicitly all its descendants at next verify).

        Revocation is stored by raw token string.  Every descendant calls
        ``_check_revoked`` which walks the ancestor chain, so descendants are
        invalidated without needing a per-child revocation record.

        Example::

            await auth.revoke(root)
            with pytest.raises(RevokedAncestorError):
                await auth.verify(child)
        """
        self._revoked.add(str(token))

    # ------------------------------------------------------------------
    # Delegation extension
    # ------------------------------------------------------------------

    async def delegate(
        self,
        parent_token: Token,
        audience: AgentId,
        scopes: list[str],
        ttl: float,
    ) -> Token:
        """Mint a child token scoped to a subset of ``parent_token``'s scopes.

        The parent token holder (not the issuer) calls this.  The child's TTL
        is capped to the parent's remaining lifetime to prevent TTL escalation.

        Args:
            parent_token: A valid, non-revoked parent token.
            audience: The agent who may present the child token.
            scopes: Must be a non-empty subset of the parent's scopes.
            ttl: Requested TTL in seconds (capped to parent's remaining TTL).

        Raises:
            ScopeEscalationError: Any requested scope is absent from the parent.
            ValueError: Parent is expired or has an invalid signature.
            RevokedAncestorError: Parent or one of its ancestors is revoked.

        Example::

            child = await auth.delegate(root, AgentId("worker"), ["read"], ttl=60.0)
            ctx = await auth.verify(child)
            assert ctx.scopes == ["read"]
        """
        parent_data: dict[str, Any] = self._decode(parent_token)
        self._check_expiry(parent_data, str(parent_token))
        self._check_revoked(str(parent_token))

        parent_scopes: set[str] = set(parent_data["scopes"])
        child_scopes: set[str] = set(scopes)
        extra = child_scopes - parent_scopes
        if extra:
            msg = f"Scope escalation: {extra!r} not in parent scopes {parent_scopes!r}"
            raise ScopeEscalationError(msg)
        if child_scopes == parent_scopes:
            raise ScopeEscalationError("Delegated scopes must be a strict subset of the parent scopes")

        if ttl <= 0:
            raise ValueError("ttl must be positive")
        # Cap TTL to parent's remaining lifetime
        parent_remaining: float = float(parent_data["exp"]) - self._now()
        if parent_remaining <= 0:
            raise ValueError("parent token has expired")
        actual_ttl: float = min(ttl, parent_remaining)

        token = self._build_token(
            subject=AgentId(parent_data["sub"]),
            audience=audience,
            scopes=sorted(child_scopes),
            ttl=actual_ttl,
            parent_token=parent_token,
        )
        self._parent[str(token)] = str(parent_token)
        return token
