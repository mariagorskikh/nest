# SPDX-License-Identifier: Apache-2.0
"""Delegatable capability tokens with cascading revocation (macaroon-style).

A holder of a token can mint a narrower child token for another agent
*without* contacting the issuer, by HMAC-chaining the child segment to the
parent signature (Birgisson et al., 2014).  Revoking any segment invalidates
every descendant at the next ``verify`` — no per-child revocation lists.

Attenuation invariants enforced at mint *and* re-checked at verify:

- child ``scopes`` must be a strict-or-equal subset of the parent's;
- child ``exp`` must not exceed the parent's;
- a child is bound to a single ``audience`` and only that agent may
  present it (checked via :meth:`DelegatableAuth.verify_presented`).

Example::

    auth = DelegatableAuth(secret=b"secret", clock=0.0)
    root = await auth.issue(AgentId("coordinator"), ["read", "write"])
    child = await auth.delegate(root, AgentId("worker"), ["read"], ttl=60.0)
    ctx = await auth.verify_presented(child, AgentId("worker"))
    await auth.revoke(root)          # cascades:
    await auth.verify(child)         # raises RevokedAncestorError
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any, cast

from nest_core.types import AgentId, AuthContext, Token

_DEFAULT_TTL: float = 3600.0


class DelegationError(ValueError):
    """Base class for delegation failures.

    Subclasses ``ValueError`` so callers written against the reference
    ``jwt`` plugin (which raises bare ``ValueError``) keep working.

    Example::

        try:
            await auth.verify(token)
        except DelegationError as err:
            print(f"rejected: {err}")
    """


class ScopeEscalationError(DelegationError):
    """A child requested scopes its parent does not hold.

    Example::

        raise ScopeEscalationError("scope 'admin' not held by parent")
    """


class RevokedAncestorError(DelegationError):
    """A token in the ancestry chain has been revoked.

    Example::

        raise RevokedAncestorError("ancestor tid=ab12 revoked")
    """


class ExpiredAncestorError(DelegationError):
    """A token in the ancestry chain has expired.

    Example::

        raise ExpiredAncestorError("ancestor tid=ab12 expired")
    """


class AudienceMismatchError(DelegationError):
    """A token was presented by an agent other than its audience.

    Example::

        raise AudienceMismatchError("presented by a2, bound to a1")
    """


def _canonical(segment: dict[str, Any]) -> bytes:
    """Serialize a segment deterministically for signing.

    Example::

        digest_input = _canonical({"tid": "ab", "aud": "a1"})
    """
    return json.dumps(segment, sort_keys=True, separators=(",", ":")).encode()


def _segment_tid(
    audience: str,
    scopes: list[str],
    issued_at: float,
    expires_at: float,
    parent_tid: str | None,
) -> str:
    """Derive a deterministic segment id from segment content.

    Example::

        tid = _segment_tid("a1", ["read"], 0.0, 60.0, None)
    """
    preimage = json.dumps(
        {
            "aud": audience,
            "scopes": sorted(scopes),
            "iat": issued_at,
            "exp": expires_at,
            "parent": parent_tid,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(preimage).hexdigest()[:16]


class DelegatableAuth:
    """Macaroon-style delegatable auth with cascading revocation.

    Satisfies the base ``Auth`` protocol (``issue`` / ``verify`` /
    ``revoke``) and adds ``delegate`` and ``verify_presented``.

    Example::

        auth = DelegatableAuth(secret=b"secret", clock=0.0)
        root = await auth.issue(AgentId("a1"), ["read", "write"])
        child = await auth.delegate(root, AgentId("a2"), ["read"], ttl=60.0)
    """

    def __init__(self, secret: bytes = b"nest-default-secret", clock: float | None = None) -> None:
        self._secret = secret
        self._clock = clock
        self._revoked: set[str] = set()

    def set_clock(self, now: float) -> None:
        """Pin the plugin's logical clock (deterministic scenarios).

        Example::

            auth.set_clock(ctx.time)
        """
        self._clock = now

    def _now(self) -> float:
        if self._clock is not None:
            return self._clock
        import time

        return time.time()

    def _chain_signature(self, chain: list[dict[str, Any]]) -> str:
        key = self._secret
        for segment in chain:
            key = hmac.new(key, _canonical(segment), hashlib.sha256).digest()
        return key.hex()

    def _encode(self, chain: list[dict[str, Any]]) -> Token:
        envelope = {"chain": chain, "sig": self._chain_signature(chain)}
        return Token(json.dumps(envelope, sort_keys=True, separators=(",", ":")))

    def _decode(self, token: Token) -> list[dict[str, Any]]:
        try:
            data: object = json.loads(str(token))
        except json.JSONDecodeError as err:
            msg = "Invalid token format"
            raise DelegationError(msg) from err
        if not isinstance(data, dict):
            msg = "Invalid token format"
            raise DelegationError(msg)
        envelope = cast("dict[str, Any]", data)
        chain_obj: object = envelope.get("chain")
        sig_obj: object = envelope.get("sig")
        if not isinstance(chain_obj, list) or not chain_obj or not isinstance(sig_obj, str):
            msg = "Invalid token format"
            raise DelegationError(msg)
        chain = cast("list[dict[str, Any]]", chain_obj)
        expected = self._chain_signature(chain)
        if not hmac.compare_digest(sig_obj, expected):
            msg = "Invalid token signature"
            raise DelegationError(msg)
        return chain

    def _check_chain(self, chain: list[dict[str, Any]], now: float) -> None:
        parent_scopes: set[str] | None = None
        parent_exp: float | None = None
        for segment in chain:
            tid = str(segment.get("tid", ""))
            scopes = {str(s) for s in cast("list[Any]", segment.get("scopes", []))}
            exp = float(cast("float", segment.get("exp", 0.0)))
            if tid in self._revoked:
                msg = f"ancestor tid={tid} revoked"
                raise RevokedAncestorError(msg)
            if exp < now:
                msg = f"ancestor tid={tid} expired"
                raise ExpiredAncestorError(msg)
            if parent_scopes is not None and not scopes.issubset(parent_scopes):
                escalated = sorted(scopes - parent_scopes)
                msg = f"scopes {escalated} not held by parent"
                raise ScopeEscalationError(msg)
            if parent_exp is not None and exp > parent_exp:
                msg = f"child exp {exp} exceeds parent exp {parent_exp}"
                raise ExpiredAncestorError(msg)
            parent_scopes = scopes
            parent_exp = exp

    async def issue(self, subject: AgentId, scopes: list[str]) -> Token:
        """Issue a root token for a subject with given scopes.

        Example::

            root = await auth.issue(AgentId("a1"), ["read", "write"])
        """
        now = self._now()
        exp = now + _DEFAULT_TTL
        segment: dict[str, Any] = {
            "tid": _segment_tid(str(subject), scopes, now, exp, None),
            "aud": str(subject),
            "scopes": sorted(scopes),
            "iat": now,
            "exp": exp,
            "parent": None,
        }
        return self._encode([segment])

    async def delegate(
        self,
        parent_token: Token,
        audience: AgentId,
        scopes_subset: list[str],
        ttl: float,
    ) -> Token:
        """Mint a child token from a parent, without contacting the issuer.

        The child's scopes must be a subset of the parent's, and its
        expiry is clamped to the parent's.  Raises
        :class:`ScopeEscalationError` on a broader request and any
        chain error (revoked / expired ancestor) eagerly.

        Example::

            child = await auth.delegate(root, AgentId("a2"), ["read"], ttl=60.0)
        """
        now = self._now()
        chain = self._decode(parent_token)
        self._check_chain(chain, now)
        parent = chain[-1]
        parent_scopes = {str(s) for s in cast("list[Any]", parent.get("scopes", []))}
        requested = {str(s) for s in scopes_subset}
        if not requested.issubset(parent_scopes):
            escalated = sorted(requested - parent_scopes)
            msg = f"scopes {escalated} not held by parent"
            raise ScopeEscalationError(msg)
        parent_exp = float(cast("float", parent.get("exp", now)))
        exp = min(now + ttl, parent_exp)
        parent_tid = str(parent.get("tid", ""))
        segment: dict[str, Any] = {
            "tid": _segment_tid(str(audience), sorted(requested), now, exp, parent_tid),
            "aud": str(audience),
            "scopes": sorted(requested),
            "iat": now,
            "exp": exp,
            "parent": parent_tid,
        }
        return self._encode([*chain, segment])

    async def verify(self, token: Token) -> AuthContext:
        """Verify a token, walking the full ancestry chain.

        Checks signature, per-segment revocation (cascading), expiry of
        every ancestor, and monotonic scope / expiry attenuation.

        Example::

            ctx = await auth.verify(child)
        """
        now = self._now()
        chain = self._decode(token)
        self._check_chain(chain, now)
        leaf = chain[-1]
        return AuthContext(
            subject=AgentId(str(leaf.get("aud", ""))),
            scopes=[str(s) for s in cast("list[Any]", leaf.get("scopes", []))],
            issued_at=float(cast("float", leaf.get("iat", now))),
            expires_at=float(cast("float", leaf.get("exp", now))),
        )

    async def verify_presented(self, token: Token, presenter: AgentId) -> AuthContext:
        """Verify a token *and* that the presenter is its bound audience.

        Example::

            ctx = await auth.verify_presented(child, AgentId("a2"))
        """
        ctx = await self.verify(token)
        if ctx.subject != presenter:
            msg = f"presented by {presenter}, bound to {ctx.subject}"
            raise AudienceMismatchError(msg)
        return ctx

    async def revoke(self, token: Token) -> None:
        """Revoke a token; every descendant fails verify from now on.

        Example::

            await auth.revoke(root)
        """
        chain = self._decode(token)
        leaf = chain[-1]
        self._revoked.add(str(leaf.get("tid", "")))
