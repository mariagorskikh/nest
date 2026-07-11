# SPDX-License-Identifier: Apache-2.0
"""Delegatable auth plugin -- capability tokens with cascading revocation.

The default auth plugin
(:class:`~nest_plugins_reference.auth.jwt_auth.JwtAuth`) issues flat,
single-level tokens: ``_revoked`` tracks exact token strings with no notion
of parent/child. That makes it impossible to model the most common
multi-agent pattern -- "agent A holds a long-lived root token, mints a
narrow, time-boxed sub-token for agent B without calling back to the
issuer, and revoking A's token should invalidate B's (and anything B in
turn delegated) at the next verify."

This plugin adds that on top of the existing ``issue``/``verify``/``revoke``
surface via a single new method, ``delegate``, plus an optional
``presented_by`` argument on ``verify``:

* **Delegation is capability-narrowing, not reissuance.** ``delegate()``
  checks the child's scopes are a subset of the parent's and the child's
  expiry does not outlive the parent's, *at mint time* -- the parent agent
  does this itself, in-process, without the root issuer's involvement.
* **The chain is self-authenticating.** Each link's ``mac`` is an
  HMAC-SHA256 keyed on the *previous* link's ``mac`` (the root link is keyed
  on the shared secret). A link can only be produced by someone who already
  holds the entire preceding chain -- scopes and expiry cannot be widened
  after the fact without invalidating the signature.
* **Revocation is cascading by construction.** Revoking a token records only
  *that token's own* id in a single in-memory set. Every descendant token
  carries its full ancestor-id chain as part of its (signed) claims, so
  ``verify`` rejects a descendant the moment any id in its chain -- not just
  its own -- turns up revoked. No per-descendant bookkeeping is needed.

Compatibility contract for ``verify``:

* Any HMAC mismatch anywhere in the chain -> ``ValueError`` ("Invalid token
  signature").
* The presented (leaf) token expired -> ``ValueError`` ("Token has
  expired"). Because ``delegate`` enforces child expiry <= parent expiry,
  an unexpired leaf implies no ancestor is naturally expired either.
* Any link's id (leaf or ancestor) was revoked -> :class:`RevokedAncestorError`.
* ``presented_by`` given and it does not match the leaf's declared
  audience -> :class:`AudienceMismatchError`.

Example::

    auth = DelegatableAuth(secret=b"root-secret", clock=1000.0)
    root = await auth.issue(AgentId("coordinator"), ["read", "write"])
    child = await auth.delegate(root, AgentId("worker"), ["read"], ttl=60)
    ctx = await auth.verify(child, presented_by=AgentId("worker"))
    assert ctx.scopes == ["read"]
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any, cast

from nest_core.types import AgentId, AuthContext, Token

#: Default lifetime, in seconds, of a root token minted by :meth:`issue`.
DEFAULT_TTL_SECONDS = 3600.0


class DelegationError(ValueError):
    """Base class for delegation-specific auth failures.

    Subclasses :class:`ValueError` so existing ``except ValueError`` guards
    (written against the plain :class:`~nest_plugins_reference.auth.jwt_auth.JwtAuth`)
    keep catching these unchanged.
    """


class ScopeEscalationError(DelegationError):
    """Raised when a delegated token would carry scopes its parent lacks.

    Example::

        with pytest.raises(ScopeEscalationError):
            await auth.delegate(parent, AgentId("b"), ["admin"], ttl=60)
    """

    def __init__(self, requested: list[str], allowed: list[str]) -> None:
        self.requested = requested
        self.allowed = allowed
        excess = sorted(set(requested) - set(allowed))
        super().__init__(f"delegated scopes {excess} exceed parent scopes {sorted(allowed)}")


class ExcessiveTtlError(DelegationError):
    """Raised when a delegated token's expiry would outlive its parent's.

    Example::

        with pytest.raises(ExcessiveTtlError):
            await auth.delegate(parent, AgentId("b"), ["read"], ttl=999_999)
    """

    def __init__(self, child_expires_at: float, parent_expires_at: float) -> None:
        self.child_expires_at = child_expires_at
        self.parent_expires_at = parent_expires_at
        super().__init__(
            f"child expiry {child_expires_at} exceeds parent expiry {parent_expires_at}"
        )


class RevokedAncestorError(DelegationError):
    """Raised when a token, or any ancestor in its delegation chain, was revoked.

    Example::

        await auth.revoke(root)
        with pytest.raises(RevokedAncestorError):
            await auth.verify(child)
    """

    def __init__(self, token_id: str) -> None:
        self.token_id = token_id
        super().__init__(f"token {token_id!r} was revoked (directly or via an ancestor)")


class AudienceMismatchError(DelegationError):
    """Raised when a token is presented by an agent other than its declared audience.

    Example::

        with pytest.raises(AudienceMismatchError):
            await auth.verify(child, presented_by=AgentId("mallory"))
    """

    def __init__(self, expected: AgentId, presented_by: AgentId) -> None:
        self.expected = expected
        self.presented_by = presented_by
        super().__init__(f"token issued to {expected!r} was presented by {presented_by!r}")


def _canonical(claims: dict[str, Any]) -> str:
    """Canonical JSON encoding of a claims dict, used as the HMAC message.

    Example::

        assert _canonical({"b": 1, "a": 2}) == '{"a": 2, "b": 1}'
    """
    return json.dumps(claims, sort_keys=True)


def describe_token(token: Token) -> tuple[str, str]:
    """Return ``(token_id, subject)`` of a token's leaf link, unverified.

    For diagnostics and scenario trace breadcrumbs only -- this does not
    check the HMAC chain or revocation state. Use :meth:`DelegatableAuth.verify`
    to actually authenticate a token.

    Example::

        token_id, subject = describe_token(token)
    """
    chain = cast("list[dict[str, Any]]", json.loads(str(token))["chain"])
    leaf = chain[-1]
    return str(leaf["token_id"]), str(leaf["subject"])


class DelegatableAuth:
    """Capability-token auth with delegation and cascading revocation.

    Drop-in alternative to ``jwt`` for scenarios that need a delegation
    tree: an orchestrator holding a root token can mint scoped, time-boxed
    sub-tokens for workers itself, and a single ``revoke`` call on any node
    invalidates that node and everything delegated beneath it.

    Example::

        auth = DelegatableAuth(secret=b"secret", clock=0.0)
        token = await auth.issue(AgentId("a1"), ["read", "write"])
    """

    def __init__(
        self,
        secret: bytes = b"nest-default-secret",
        clock: float | None = None,
    ) -> None:
        self._secret = secret
        self._clock = clock
        self._revoked: set[str] = set()

    def _now(self) -> float:
        if self._clock is not None:
            return self._clock
        return time.time()

    def _mac(self, key: bytes, claims: dict[str, Any]) -> str:
        return hmac.new(key, _canonical(claims).encode(), hashlib.sha256).hexdigest()

    def _token_id(self, claims: dict[str, Any]) -> str:
        return hashlib.sha256(_canonical(claims).encode()).hexdigest()

    async def issue(self, subject: AgentId, scopes: list[str]) -> Token:
        """Issue a root token for ``subject`` with ``scopes``.

        Example::

            token = await auth.issue(AgentId("coordinator"), ["read", "write"])
        """
        now = self._now()
        claims: dict[str, Any] = {
            "subject": str(subject),
            "scopes": list(scopes),
            "iat": now,
            "exp": now + DEFAULT_TTL_SECONDS,
            "parent_id": None,
        }
        claims["token_id"] = self._token_id(claims)
        claims["mac"] = self._mac(self._secret, claims)
        return Token(json.dumps({"chain": [claims]}, sort_keys=True))

    async def delegate(
        self,
        parent_token: Token,
        audience: AgentId,
        scopes_subset: list[str],
        ttl: float,
    ) -> Token:
        """Mint a child token narrower than ``parent_token``, without the issuer.

        The parent must currently verify (correct signature, not expired,
        no revoked ancestor). ``scopes_subset`` must be a subset of the
        parent's scopes and the child must expire no later than the parent.

        Example::

            child = await auth.delegate(root, AgentId("worker"), ["read"], ttl=60)
        """
        parent_chain = self._verify_chain(parent_token, presented_by=None)
        parent_leaf = parent_chain[-1]
        parent_scopes: list[str] = cast("list[str]", parent_leaf["scopes"])

        requested = set(scopes_subset)
        if not requested.issubset(parent_scopes):
            raise ScopeEscalationError(list(scopes_subset), parent_scopes)

        now = self._now()
        child_expires_at = now + ttl
        parent_expires_at = cast("float", parent_leaf["exp"])
        if child_expires_at > parent_expires_at:
            raise ExcessiveTtlError(child_expires_at, parent_expires_at)

        claims: dict[str, Any] = {
            "subject": str(audience),
            "scopes": list(scopes_subset),
            "iat": now,
            "exp": child_expires_at,
            "parent_id": parent_leaf["token_id"],
        }
        claims["token_id"] = self._token_id(claims)
        parent_key = bytes.fromhex(cast("str", parent_leaf["mac"]))
        claims["mac"] = self._mac(parent_key, claims)

        new_chain = [*parent_chain, claims]
        return Token(json.dumps({"chain": new_chain}, sort_keys=True))

    async def verify(self, token: Token, *, presented_by: AgentId | None = None) -> AuthContext:
        """Verify a (possibly delegated) token and return its context.

        Checks, in order: HMAC chain integrity from the root secret down to
        the presented token, expiry of the leaf, revocation of any link in
        the chain, and -- if ``presented_by`` is given -- that it matches
        the token's declared audience.

        Example::

            ctx = await auth.verify(child, presented_by=AgentId("worker"))
        """
        chain = self._verify_chain(token, presented_by=presented_by)
        leaf = chain[-1]
        return AuthContext(
            subject=AgentId(cast("str", leaf["subject"])),
            scopes=cast("list[str]", leaf["scopes"]),
            issued_at=cast("float", leaf["iat"]),
            expires_at=cast("float", leaf["exp"]),
        )

    async def revoke(self, token: Token) -> None:
        """Revoke a token, invalidating it and everything delegated from it.

        Revocation is recorded once, against the presented token's own id.
        Every descendant embeds this id in its own (signed) ancestor chain,
        so it stops verifying immediately -- no separate revocation entry
        per descendant is ever added.

        Example::

            await auth.revoke(root)  # root and every child/grandchild are now dead
        """
        chain = self._parse_chain(token)
        self._revoked.add(cast("str", chain[-1]["token_id"]))

    def _parse_chain(self, token: Token) -> list[dict[str, Any]]:
        """Parse the JSON delegation chain out of a token without verifying it."""
        try:
            loaded = json.loads(str(token))
        except (json.JSONDecodeError, ValueError) as exc:
            msg = "Invalid token format"
            raise ValueError(msg) from exc
        if not isinstance(loaded, dict):
            msg = "Invalid token format"
            raise ValueError(msg)
        data = cast("dict[str, Any]", loaded)
        chain = data.get("chain")
        if not isinstance(chain, list) or not chain:
            msg = "Invalid token format"
            raise ValueError(msg)
        return cast("list[dict[str, Any]]", chain)

    def _verify_chain(self, token: Token, *, presented_by: AgentId | None) -> list[dict[str, Any]]:
        """Verify HMAC integrity, expiry, and revocation across the whole chain."""
        chain = self._parse_chain(token)

        key = self._secret
        for link in chain:
            claims = {k: v for k, v in link.items() if k != "mac"}
            expected = self._mac(key, claims)
            actual = cast("str", link.get("mac", ""))
            if not hmac.compare_digest(expected, actual):
                msg = "Invalid token signature"
                raise ValueError(msg)
            token_id = cast("str", link["token_id"])
            if token_id in self._revoked:
                raise RevokedAncestorError(token_id)
            key = bytes.fromhex(actual)

        leaf = chain[-1]
        if cast("float", leaf["exp"]) < self._now():
            msg = "Token has expired"
            raise ValueError(msg)

        if presented_by is not None and str(presented_by) != leaf["subject"]:
            raise AudienceMismatchError(AgentId(cast("str", leaf["subject"])), presented_by)

        return chain
