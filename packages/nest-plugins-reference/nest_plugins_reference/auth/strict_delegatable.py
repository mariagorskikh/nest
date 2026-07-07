# SPDX-License-Identifier: Apache-2.0
"""Strict delegatable capability-token auth with cascading revocation.

The reference ``jwt`` auth plugin issues independent bearer tokens.  This
plugin models a common multi-agent pattern instead: an orchestrator holds a
root capability, attenuates it into a narrower child capability for a worker,
and can revoke the parent to invalidate the whole subtree.

Example::

    auth = StrictDelegatableAuth(secret=b"demo", clock=1000.0)
    root = await auth.issue(AgentId("coordinator"), ["read", "write"])
    child = await auth.delegate(root, AgentId("worker-1"), ["read"], ttl=60)
    ctx = await auth.verify_for(child, AgentId("worker-1"))
    assert ctx.scopes == ["read"]
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any, cast

from nest_core.types import AgentId, AuthContext, Token

_TOKEN_SIGN_DOMAIN = b"nest.delegatable-strict.token.v1|"
_CHILD_KEY_DOMAIN = b"nest.delegatable-strict.child-key.v1|"


class DelegationError(ValueError):
    """Base class for failures raised by ``StrictDelegatableAuth``.

    Example::

        raise DelegationError("invalid delegated token")
    """


class ScopeEscalationError(DelegationError):
    """Raised when a child token asks for scopes outside its parent.

    Example::

        raise ScopeEscalationError("child scopes must be a strict subset")
    """


class RevokedAncestorError(DelegationError):
    """Raised when a token verifies only because an ancestor was ignored.

    Example::

        raise RevokedAncestorError("ancestor token has been revoked")
    """


class ExpiredAncestorError(DelegationError):
    """Raised when a child token outlives an ancestor token.

    Example::

        raise ExpiredAncestorError("ancestor token has expired")
    """


class AudienceMismatchError(DelegationError):
    """Raised when a token is presented by an agent outside its audience.

    Example::

        raise AudienceMismatchError("token audience is worker-1, not worker-2")
    """


@dataclass(frozen=True)
class _Claims:
    token_id: str
    subject: AgentId
    audience: AgentId
    scopes: tuple[str, ...]
    issued_at: float
    expires_at: float
    parent_hash: str | None


@dataclass(frozen=True)
class _ParsedToken:
    raw: str
    payload_b64: str
    signature: str
    claims: _Claims


class StrictDelegatableAuth:
    """Auth plugin with strict child attenuation and revocation trees.

    Tokens remain opaque ``Token`` strings to satisfy the base ``Auth``
    protocol.  Delegation is the one extra API: ``delegate(parent, audience,
    scopes_subset, ttl)``.  Child signatures are derived from the parent
    token's signature and hash, so the child is attenuated from the parent
    capability rather than re-signed with the issuer root secret.  Verification
    walks the in-process ancestor chain, checks every signature, and rejects
    the child if any ancestor is revoked or expired.

    Example::

        auth = StrictDelegatableAuth(secret=b"secret", clock=10.0)
        parent = await auth.issue(AgentId("root"), ["orders:read", "orders:write"])
        child = await auth.delegate(parent, AgentId("worker"), ["orders:read"], ttl=5)
        assert (await auth.verify(child)).subject == AgentId("worker")
    """

    def __init__(
        self,
        secret: bytes = b"nest-delegatable-strict-secret",
        clock: float | Callable[[], float] | None = None,
    ) -> None:
        self._secret = secret
        self._clock = clock
        self._counter = 0
        self._issued_tokens: dict[str, Token] = {}
        self._revoked_hashes: set[str] = set()

    def _now(self) -> float:
        if callable(self._clock):
            return float(self._clock())
        if self._clock is not None:
            return float(self._clock)
        return time.time()

    def _next_token_id(
        self,
        subject: AgentId,
        audience: AgentId,
        scopes: Iterable[str],
        parent_hash: str | None,
        issued_at: float,
    ) -> str:
        self._counter += 1
        material = json.dumps(
            {
                "aud": str(audience),
                "counter": self._counter,
                "iat": issued_at,
                "parent": parent_hash,
                "scopes": list(scopes),
                "sub": str(subject),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(material.encode()).hexdigest()[:32]

    @staticmethod
    def _b64_json(data: dict[str, Any]) -> str:
        raw = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    @staticmethod
    def _json_from_b64(data: str) -> dict[str, Any]:
        try:
            padded = data + "=" * (-len(data) % 4)
            raw = base64.urlsafe_b64decode(padded.encode())
            decoded = json.loads(raw)
        except (binascii.Error, json.JSONDecodeError, UnicodeDecodeError) as exc:
            msg = "Invalid token payload"
            raise DelegationError(msg) from exc
        if not isinstance(decoded, dict):
            msg = "Invalid token payload"
            raise DelegationError(msg)
        return cast("dict[str, Any]", decoded)

    def _signing_key(self, parent_hash: str | None) -> bytes:
        if parent_hash is None:
            return self._secret
        parent_token = self._issued_tokens.get(parent_hash)
        if parent_token is None:
            msg = "Ancestor token is unknown"
            raise RevokedAncestorError(msg)
        _, parent_signature = str(parent_token).rsplit(".", 1)
        return hmac.new(
            parent_signature.encode(),
            _CHILD_KEY_DOMAIN + parent_hash.encode(),
            hashlib.sha256,
        ).digest()

    def _sign(self, payload_b64: str, parent_hash: str | None) -> str:
        key = self._signing_key(parent_hash)
        return hmac.new(
            key,
            _TOKEN_SIGN_DOMAIN + payload_b64.encode(),
            hashlib.sha256,
        ).hexdigest()

    @staticmethod
    def _token_hash(token: Token | str) -> str:
        return hashlib.sha256(str(token).encode()).hexdigest()

    def _make_token(
        self,
        *,
        subject: AgentId,
        audience: AgentId,
        scopes: list[str],
        ttl: float,
        parent_hash: str | None,
    ) -> Token:
        issued_at = self._now()
        expires_at = issued_at + ttl
        token_id = self._next_token_id(subject, audience, scopes, parent_hash, issued_at)
        payload = {
            "aud": str(audience),
            "exp": expires_at,
            "iat": issued_at,
            "jti": token_id,
            "parent": parent_hash,
            "scopes": scopes,
            "sub": str(subject),
        }
        payload_b64 = self._b64_json(payload)
        signature = self._sign(payload_b64, parent_hash)
        token = Token(f"{payload_b64}.{signature}")
        self._issued_tokens[self._token_hash(token)] = token
        return token

    def _parse(self, token: Token) -> _ParsedToken:
        raw = str(token)
        parts = raw.rsplit(".", 1)
        if len(parts) != 2:
            msg = "Invalid token format"
            raise DelegationError(msg)
        payload_b64, signature = parts
        data = self._json_from_b64(payload_b64)
        parent_hash = data.get("parent")
        if parent_hash is not None and not isinstance(parent_hash, str):
            msg = "Invalid parent hash"
            raise DelegationError(msg)
        expected = self._sign(payload_b64, parent_hash)
        try:
            signature_matches = hmac.compare_digest(signature, expected)
        except TypeError as exc:
            msg = "Invalid token signature"
            raise DelegationError(msg) from exc
        if not signature_matches:
            msg = "Invalid token signature"
            raise DelegationError(msg)

        scopes_obj = data.get("scopes")
        if not isinstance(scopes_obj, list):
            msg = "Invalid scope list"
            raise DelegationError(msg)
        scopes_raw = cast("list[object]", scopes_obj)
        if not all(isinstance(scope, str) for scope in scopes_raw):
            msg = "Invalid scope list"
            raise DelegationError(msg)
        scopes = cast("list[str]", scopes_raw)
        try:
            claims = _Claims(
                token_id=str(data["jti"]),
                subject=AgentId(str(data["sub"])),
                audience=AgentId(str(data["aud"])),
                scopes=tuple(scopes),
                issued_at=float(data["iat"]),
                expires_at=float(data["exp"]),
                parent_hash=parent_hash,
            )
        except (KeyError, TypeError, ValueError) as exc:
            msg = "Invalid token claims"
            raise DelegationError(msg) from exc
        return _ParsedToken(raw=raw, payload_b64=payload_b64, signature=signature, claims=claims)

    async def issue(self, subject: AgentId, scopes: list[str]) -> Token:
        """Issue a root token for ``subject``.

        Example::

            token = await auth.issue(AgentId("coordinator"), ["read", "write"])
        """
        return self._make_token(
            subject=subject,
            audience=subject,
            scopes=list(scopes),
            ttl=3600.0,
            parent_hash=None,
        )

    async def delegate(
        self,
        parent_token: Token,
        audience: AgentId,
        scopes_subset: list[str],
        ttl: float,
    ) -> Token:
        """Mint a child token from ``parent_token`` without central re-issuance.

        ``scopes_subset`` must be a strict subset of the parent's scopes and
        ``ttl`` must not outlive the parent.

        Example::

            child = await auth.delegate(parent, AgentId("worker"), ["read"], ttl=30)
        """
        parent_ctx = await self.verify(parent_token)
        parent_hash = self._token_hash(parent_token)
        self._issued_tokens.setdefault(parent_hash, parent_token)
        requested = list(scopes_subset)
        parent_scopes = set(parent_ctx.scopes)
        requested_scopes = set(requested)
        if not requested_scopes or not requested_scopes < parent_scopes:
            msg = "Child scopes must be a non-empty strict subset of parent scopes"
            raise ScopeEscalationError(msg)
        if parent_ctx.expires_at is None:
            msg = "Parent token has no expiry"
            raise DelegationError(msg)
        remaining = parent_ctx.expires_at - self._now()
        if ttl <= 0 or ttl > remaining:
            msg = "Child TTL must be positive and no longer than parent TTL"
            raise DelegationError(msg)
        return self._make_token(
            subject=parent_ctx.subject,
            audience=audience,
            scopes=requested,
            ttl=ttl,
            parent_hash=parent_hash,
        )

    async def verify(self, token: Token) -> AuthContext:
        """Verify ``token`` and reject stale delegated descendants.

        This base-protocol method treats a valid child as a bearer token.
        Call :meth:`verify_for` when the presenter must match its audience.

        Example::

            ctx = await auth.verify(child)
            assert ctx.subject == AgentId("worker")
        """
        parsed = self._parse(token)
        self._verify_ancestor_chain(parsed)
        claims = parsed.claims
        return AuthContext(
            # AuthContext.subject is the holder/audience. The ``sub`` claim
            # remains the original delegator for ancestry inspection.
            subject=claims.audience,
            scopes=list(claims.scopes),
            issued_at=claims.issued_at,
            expires_at=claims.expires_at,
        )

    async def verify_for(self, token: Token, presenter: AgentId) -> AuthContext:
        """Verify ``token`` as presented by ``presenter``.

        Example::

            await auth.verify_for(child, AgentId("worker-1"))
        """
        ctx = await self.verify(token)
        if ctx.subject != presenter:
            msg = f"Token audience is {ctx.subject}, not {presenter}"
            raise AudienceMismatchError(msg)
        return ctx

    async def revoke(self, token: Token) -> None:
        """Revoke ``token`` and therefore every delegated descendant.

        Example::

            await auth.revoke(parent)
        """
        self._revoked_hashes.add(self._token_hash(token))

    def _verify_ancestor_chain(self, parsed: _ParsedToken) -> None:
        now = self._now()
        current = parsed
        current_hash = self._token_hash(current.raw)
        first = True
        while True:
            if current_hash in self._revoked_hashes:
                if first:
                    msg = "Token has been revoked"
                    raise DelegationError(msg)
                msg = "Ancestor token has been revoked"
                raise RevokedAncestorError(msg)
            if current.claims.expires_at < now:
                if first:
                    msg = "Token has expired"
                    raise DelegationError(msg)
                msg = "Ancestor token has expired"
                raise ExpiredAncestorError(msg)
            parent_hash = current.claims.parent_hash
            if parent_hash is None:
                return
            parent_token = self._issued_tokens.get(parent_hash)
            if parent_token is None:
                msg = "Ancestor token is unknown"
                raise RevokedAncestorError(msg)
            parent = self._parse(parent_token)
            if not set(current.claims.scopes) < set(parent.claims.scopes):
                msg = "Child scopes are not a strict subset of parent scopes"
                raise ScopeEscalationError(msg)
            if current.claims.expires_at > parent.claims.expires_at:
                msg = "Child token outlives parent token"
                raise ExpiredAncestorError(msg)
            current = parent
            current_hash = parent_hash
            first = False
