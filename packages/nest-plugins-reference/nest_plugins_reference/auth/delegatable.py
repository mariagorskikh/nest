# SPDX-License-Identifier: Apache-2.0
"""Delegatable capability-token auth plugin.

This module implements the hackathon Problem 04 reference solution: agents can
mint bounded child tokens from parent capabilities, revoke a parent, and have
all descendants become invalid through cascading revocation.

Example::

    auth = DelegatableAuth()
    root = auth.issue_root(
        subject="alice",
        audience="nest",
        scopes={"read", "write", "delegate"},
        ttl_seconds=3600.0,
        max_depth=2,
    )
    child = auth.delegate(root, subject="bob", scopes={"read"})
    cap = auth.verify_capability(child, audience="nest")
    assert cap.scopes == frozenset({"read"})
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
from dataclasses import dataclass, field
from time import time
from typing import Any
from uuid import uuid4

from nest_core.layers.auth import Auth
from nest_core.types import AgentId, AuthContext, Token


class CapabilityError(ValueError):
    """Raised when a capability token cannot be minted or verified."""


@dataclass(frozen=True, slots=True)
class CapabilityToken:
    """A signed bearer token with delegation ancestry."""

    token_id: str
    subject: str
    audience: str
    scopes: frozenset[str]
    issued_at: float
    expires_at: float
    parent_id: str | None = None
    max_depth: int = 0
    depth: int = 0
    signature: str = ""

    def payload(self) -> dict[str, Any]:
        """Return the canonical payload covered by the signature."""

        return {
            "aud": self.audience,
            "depth": self.depth,
            "exp": self.expires_at,
            "iat": self.issued_at,
            "jti": self.token_id,
            "max_depth": self.max_depth,
            "parent": self.parent_id,
            "scopes": sorted(self.scopes),
            "sub": self.subject,
        }


@dataclass(slots=True)
class DelegatableAuth(Auth):
    """Capability-token auth with bounded delegation and cascading revocation."""

    issuer: str = "nandatown"
    secret: bytes = b"nandatown-dev-capability-secret"
    _tokens: dict[str, CapabilityToken] = field(default_factory=dict[str, CapabilityToken])
    _children: dict[str, set[str]] = field(default_factory=dict[str, set[str]])
    _revoked: set[str] = field(default_factory=set[str])

    async def verify(self, token: Token) -> AuthContext:
        """Verify a serialized capability token using the token's own audience.

        Example::

            ctx = await auth.verify(Token(cap_str))
            assert ctx.subject == AgentId("alice")
        """

        cap = self.verify_capability(str(token))
        return AuthContext(
            subject=AgentId(cap.subject),
            scopes=sorted(cap.scopes),
            issued_at=cap.issued_at,
            expires_at=cap.expires_at,
        )

    async def issue(self, subject: AgentId, scopes: list[str]) -> Token:
        """Issue a root token compatible with the core Auth protocol.

        For protocol compatibility the default audience is ``nest`` and the root
        token can delegate once. Use ``issue_root`` when a test or scenario needs
        explicit audience, TTL, or max-depth control.

        Example::

            token = await auth.issue(AgentId("alice"), ["read", "write"])
        """

        return Token(
            self.issue_root(
                subject=str(subject),
                audience="nest",
                scopes=frozenset(scopes),
                ttl_seconds=3600.0,
                max_depth=1,
            )
        )

    def issue_root(
        self,
        *,
        subject: str,
        audience: str,
        scopes: frozenset[str] | set[str],
        ttl_seconds: float,
        max_depth: int,
        now: float | None = None,
    ) -> str:
        """Mint a root capability token.

        Example::

            root = auth.issue_root(
                subject="alice",
                audience="nest",
                scopes={"read", "write"},
                ttl_seconds=3600.0,
                max_depth=2,
            )
        """

        self._require_positive_finite("ttl_seconds", ttl_seconds)
        if max_depth < 0:
            raise CapabilityError("max_depth must be non-negative")
        issued_at = self._checked_now(now)
        token = CapabilityToken(
            token_id=self._new_id(),
            subject=subject,
            audience=audience,
            scopes=frozenset(scopes),
            issued_at=issued_at,
            expires_at=issued_at + ttl_seconds,
            max_depth=max_depth,
        )
        return self._store(self._sign(token))

    def delegate(
        self,
        parent: str,
        *,
        subject: str,
        audience: str | None = None,
        scopes: frozenset[str] | set[str] | None = None,
        ttl_seconds: float | None = None,
        now: float | None = None,
    ) -> str:
        """Mint a child token bounded by its live parent.

        The child's scopes must be a subset of the parent's scopes and the
        child's TTL must not exceed the parent's remaining lifetime.

        Example::

            root = auth.issue_root(subject="alice", audience="svc",
                                   scopes={"read", "write"}, ttl_seconds=3600.0,
                                   max_depth=2)
            child = auth.delegate(root, subject="bob", scopes={"read"})
            assert auth.verify_capability(child, audience="svc")

        Raises ``CapabilityError`` if the parent is expired, revoked, at max
        depth, or if the requested child scopes exceed the parent's.
        """

        parent_token = self.verify_capability(parent, now=now)
        if parent_token.depth >= parent_token.max_depth:
            raise CapabilityError("delegation depth exceeded")

        child_scopes = frozenset(scopes if scopes is not None else parent_token.scopes)
        if not child_scopes.issubset(parent_token.scopes):
            raise CapabilityError("child scopes must be a subset of parent scopes")

        child_audience = parent_token.audience if audience is None else audience

        issued_at = self._checked_now(now)
        parent_ttl = parent_token.expires_at - issued_at
        requested_ttl = parent_ttl if ttl_seconds is None else ttl_seconds
        self._require_positive_finite("child token ttl", requested_ttl)
        expires_at = min(parent_token.expires_at, issued_at + requested_ttl)

        child = CapabilityToken(
            token_id=self._new_id(),
            subject=subject,
            audience=child_audience,
            scopes=child_scopes,
            issued_at=issued_at,
            expires_at=expires_at,
            parent_id=parent_token.token_id,
            max_depth=parent_token.max_depth,
            depth=parent_token.depth + 1,
        )
        return self._store(self._sign(child))

    async def revoke(self, token: Token) -> None:
        """Revoke a token and all descendants.

        Example::

            await auth.revoke(root_token)
            with pytest.raises(CapabilityError):
                auth.verify_capability(child, audience="nest")
        """

        self.revoke_tree(str(token))

    def revoke_tree(self, token: str | CapabilityToken) -> set[str]:
        """Revoke a token and all descendants, returning revoked token ids.

        Accepts a serialized token (string) — only signature and token
        existence are checked, not expiry/revocation state, so that expired
        parents can still be revoked to cascade-invalidate live children.

        Example::

            revoked = auth.revoke_tree(root_str)
            assert len(revoked) > 1  # root + children
        """

        if isinstance(token, CapabilityToken):
            token_id = token.token_id
        else:
            token_id = self._verify_signature(token).token_id
        revoked: set[str] = set()
        stack = [token_id]
        while stack:
            current = stack.pop()
            if current in revoked:
                continue
            revoked.add(current)
            stack.extend(self._children.get(current, set()))
        self._revoked.update(revoked)
        return revoked

    def inspect(self, token: str) -> CapabilityToken:
        """Decode a token for audit assertions without checking liveness.

        Example::

            cap = auth.inspect(token_str)
            assert cap.subject == "alice"
            assert "read" in cap.scopes
        """

        return self._decode(token)

    def verify_capability(
        self,
        token: str,
        *,
        audience: str | None = None,
        required_scopes: set[str] | frozenset[str] | None = None,
        now: float | None = None,
    ) -> CapabilityToken:
        """Verify signature, expiry, audience, scope, and revocation ancestry.

        Example::

            cap = auth.verify_capability(
                token_str,
                audience="nest",
                required_scopes={"read"},
            )
            assert cap.subject == "bob"
        """

        cap = self._decode(token)
        expected = self._sign(cap).signature
        if not hmac.compare_digest(cap.signature, expected):
            raise CapabilityError("invalid capability signature")
        if cap.token_id not in self._tokens:
            raise CapabilityError("unknown capability token")
        if self._is_revoked(cap.token_id):
            raise CapabilityError("capability token is revoked")
        checked_at = self._checked_now(now)
        if checked_at >= cap.expires_at:
            raise CapabilityError("capability token is expired")
        if audience is not None and cap.audience != audience:
            raise CapabilityError("capability audience mismatch")
        needed = frozenset(required_scopes or frozenset())
        if not needed.issubset(cap.scopes):
            raise CapabilityError("capability scope mismatch")
        if cap.parent_id is not None and cap.parent_id not in self._tokens:
            raise CapabilityError("missing parent capability")
        return cap

    def _verify_signature(self, token: str) -> CapabilityToken:
        """Decode and verify signature + token existence, skipping liveness checks.

        This is the lighter verification used by ``revoke_tree`` so that
        expired tokens can still be revoked to invalidate live descendants.
        """
        cap = self._decode(token)
        expected = self._sign(cap).signature
        if not hmac.compare_digest(cap.signature, expected):
            raise CapabilityError("invalid capability signature")
        if cap.token_id not in self._tokens:
            raise CapabilityError("unknown capability token")
        return cap

    def _is_revoked(self, token_id: str) -> bool:
        current: str | None = token_id
        while current is not None:
            if current in self._revoked:
                return True
            current = self._tokens[current].parent_id if current in self._tokens else None
        return False

    def _store(self, token: CapabilityToken) -> str:
        self._tokens[token.token_id] = token
        if token.parent_id is not None:
            self._children.setdefault(token.parent_id, set()).add(token.token_id)
        return self._encode(token)

    def _sign(self, token: CapabilityToken) -> CapabilityToken:
        payload = json.dumps(token.payload(), sort_keys=True, separators=(",", ":")).encode()
        signature = hmac.new(self.secret, payload, hashlib.sha256).hexdigest()
        return CapabilityToken(
            token_id=token.token_id,
            subject=token.subject,
            audience=token.audience,
            scopes=token.scopes,
            issued_at=token.issued_at,
            expires_at=token.expires_at,
            parent_id=token.parent_id,
            max_depth=token.max_depth,
            depth=token.depth,
            signature=signature,
        )

    def _encode(self, token: CapabilityToken) -> str:
        envelope = {**token.payload(), "iss": self.issuer, "sig": token.signature}
        return json.dumps(envelope, sort_keys=True, separators=(",", ":"))

    def _decode(self, token: str) -> CapabilityToken:
        try:
            raw = json.loads(token)
            if raw.get("iss") != self.issuer:
                raise CapabilityError("capability issuer mismatch")
            issued_at = self._require_finite("issued_at", float(raw["iat"]))
            expires_at = self._require_finite("expires_at", float(raw["exp"]))
            return CapabilityToken(
                token_id=str(raw["jti"]),
                subject=str(raw["sub"]),
                audience=str(raw["aud"]),
                scopes=frozenset(str(scope) for scope in raw["scopes"]),
                issued_at=issued_at,
                expires_at=expires_at,
                parent_id=None if raw.get("parent") is None else str(raw["parent"]),
                max_depth=int(raw["max_depth"]),
                depth=int(raw["depth"]),
                signature=str(raw["sig"]),
            )
        except CapabilityError:
            raise
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise CapabilityError("malformed capability token") from exc

    def _require_finite(self, label: str, value: float) -> float:
        if not math.isfinite(value):
            raise CapabilityError(f"{label} must be finite")
        return value

    def _require_positive_finite(self, label: str, value: float) -> float:
        self._require_finite(label, value)
        if value <= 0:
            raise CapabilityError(f"{label} must be positive")
        return value

    def _checked_now(self, now: float | None) -> float:
        current = time() if now is None else now
        self._require_finite("now", current)
        return current

    def _new_id(self) -> str:
        return uuid4().hex


# ── Declarative plugin handle ──────────────────────────────────────────────
# Reference implementation so the entry-point discovery path has a concrete
# instance to resolve.  The PluginRegistry hard‑codes DelegatableAuth for
# ("auth", "delegatable") as well; this handle lets `nest.plugins.auth`
# discovery work identically for third‑party consumers.
auth_plugin: type[DelegatableAuth] = DelegatableAuth
