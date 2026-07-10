# SPDX-License-Identifier: Apache-2.0
"""Delegatable auth plugin — HMAC-chained capability tokens with cascading revocation.

Example::

    auth = DelegatableAuth(secret=b"my-secret", clock=0.0)
    root = await auth.issue(AgentId("coordinator"), ["read", "write", "delegate"])
    child = await auth.delegate(root, AgentId("leaf-0"), ["read"], ttl=600)
    ctx = await auth.verify(child, presenter=AgentId("leaf-0"))
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

from nest_core.types import AgentId, AuthContext, Token


class AuthError(ValueError):
    """Base error for delegatable auth failures."""


class ScopeEscalationError(AuthError):
    """Child scopes are not a strict subset of the parent scopes."""


class TtlViolationError(AuthError):
    """Child TTL exceeds the parent token's remaining lifetime."""


class RevokedAncestorError(AuthError):
    """An ancestor token in the delegation chain has been revoked."""


class ExpiredParentError(AuthError):
    """An ancestor token in the delegation chain has expired."""


class AudienceMismatchError(AuthError):
    """The presenting agent does not match the token audience."""


class DelegatableAuth:
    """HMAC-chained delegatable capability tokens with transitive revocation.

    Root tokens are issued by the authority. Parent agents delegate strict
    subsets of their scopes to child audiences without contacting the issuer.
    Revoking any ancestor invalidates every descendant at verify time.

    Example::

        auth = DelegatableAuth(secret=b"secret", clock=0.0)
        root = await auth.issue(AgentId("a1"), ["read", "write"])
        child = await auth.delegate(root, AgentId("a2"), ["read"], ttl=300)
    """

    def __init__(
        self,
        secret: bytes = b"nest-delegatable-secret",
        clock: float | None = None,
        root_ttl: float = 3600.0,
    ) -> None:
        self._secret = secret
        self._clock = clock if clock is not None else 0.0
        self._root_ttl = root_ttl
        self._revoked_ids: set[str] = set()
        self._tokens: dict[str, str] = {}
        self._next_id = 0

    def _now(self) -> float:
        return self._clock

    def set_clock(self, value: float) -> None:
        """Advance the deterministic virtual clock used for issuance and expiry.

        Example::

            auth.set_clock(100.0)
        """
        self._clock = value

    def _new_tok_id(self) -> str:
        tok_id = f"t{self._next_id}"
        self._next_id += 1
        return tok_id

    def _sign(self, payload: str, parent_token: str | None = None) -> str:
        material = payload if parent_token is None else f"{payload}|{parent_token}"
        return hmac.new(self._secret, material.encode(), hashlib.sha256).hexdigest()

    def _parse_token(self, token: Token) -> tuple[dict[str, Any], str, str]:
        raw = str(token)
        parts = raw.rsplit("|", 1)
        if len(parts) != 2:
            msg = "Invalid token format"
            raise ValueError(msg)
        payload_str, sig = parts
        data = json.loads(payload_str)
        parent_raw = self._tokens.get(str(data.get("parent_id", "")))
        expected = self._sign(payload_str, parent_raw if data.get("kind") == "delegate" else None)
        if not hmac.compare_digest(sig, expected):
            msg = "Invalid token signature"
            raise ValueError(msg)
        return data, payload_str, raw

    def _register(self, tok_id: str, raw: str) -> None:
        self._tokens[tok_id] = raw

    async def issue(self, subject: AgentId, scopes: list[str]) -> Token:
        """Issue a root capability token for a subject.

        Example::

            token = await auth.issue(AgentId("coordinator"), ["read", "delegate"])
        """
        now = self._now()
        tok_id = self._new_tok_id()
        payload = json.dumps(
            {
                "kind": "root",
                "sub": str(subject),
                "scopes": sorted(scopes),
                "iat": now,
                "exp": now + self._root_ttl,
                "tok_id": tok_id,
            },
            sort_keys=True,
        )
        sig = self._sign(payload)
        raw = f"{payload}|{sig}"
        self._register(tok_id, raw)
        return Token(raw)

    async def delegate(
        self,
        parent_token: Token,
        audience: AgentId,
        scopes_subset: list[str],
        ttl: float,
    ) -> Token:
        """Delegate a strict subset of parent scopes to an audience agent.

        Example::

            child = await auth.delegate(root, AgentId("leaf-0"), ["read"], ttl=600)
        """
        parent_data, _, parent_raw = self._parse_token(parent_token)
        parent_id = str(parent_data["tok_id"])
        if parent_id in self._revoked_ids:
            msg = f"Parent token {parent_id} has been revoked"
            raise RevokedAncestorError(msg)
        if parent_data["exp"] < self._now():
            msg = f"Parent token {parent_id} has expired"
            raise ExpiredParentError(msg)

        parent_scopes = set(parent_data["scopes"])
        if "delegate" not in parent_scopes:
            msg = "Parent token lacks delegate scope required for delegation"
            raise ScopeEscalationError(msg)

        child_scopes = set(scopes_subset)
        if not child_scopes < parent_scopes:
            child_sorted = sorted(child_scopes)
            parent_sorted = sorted(parent_scopes)
            msg = f"Child scopes {child_sorted} are not a strict subset of {parent_sorted}"
            raise ScopeEscalationError(msg)

        now = self._now()
        parent_remaining = parent_data["exp"] - now
        if ttl > parent_remaining:
            msg = f"Child TTL {ttl} exceeds parent remaining TTL {parent_remaining}"
            raise TtlViolationError(msg)

        tok_id = self._new_tok_id()
        payload = json.dumps(
            {
                "kind": "delegate",
                "sub": str(parent_data["sub"]),
                "aud": str(audience),
                "scopes": sorted(scopes_subset),
                "iat": now,
                "exp": now + ttl,
                "parent_id": parent_id,
                "tok_id": tok_id,
            },
            sort_keys=True,
        )
        sig = self._sign(payload, parent_raw)
        raw = f"{payload}|{sig}"
        self._register(tok_id, raw)
        return Token(raw)

    def _walk_ancestors(self, data: dict[str, Any]) -> None:
        """Verify every ancestor is present, unrevoked, and unexpired."""
        now = self._now()
        parent_id = data.get("parent_id")
        while parent_id:
            if str(parent_id) in self._revoked_ids:
                msg = f"Ancestor token {parent_id} has been revoked"
                raise RevokedAncestorError(msg)
            parent_raw = self._tokens.get(str(parent_id))
            if parent_raw is None:
                msg = f"Unknown parent token {parent_id}"
                raise ValueError(msg)
            parent_data, _, _ = self._parse_token(Token(parent_raw))
            if parent_data["exp"] < now:
                msg = f"Ancestor token {parent_id} has expired"
                raise ExpiredParentError(msg)
            parent_id = parent_data.get("parent_id")

    async def verify(self, token: Token, presenter: AgentId | None = None) -> AuthContext:
        """Verify a token, walking the delegation chain and checking audience binding.

        Example::

            ctx = await auth.verify(child, presenter=AgentId("leaf-0"))
            assert "read" in ctx.scopes
        """
        data, _, _ = self._parse_token(token)
        tok_id = str(data["tok_id"])
        if tok_id in self._revoked_ids:
            msg = "Token has been revoked"
            raise RevokedAncestorError(msg)

        if data.get("kind") == "delegate":
            aud = str(data["aud"])
            if presenter is None:
                msg = "Delegated token requires a presenting audience agent"
                raise AudienceMismatchError(msg)
            if str(presenter) != aud:
                msg = f"Token audience {aud} does not match presenter {presenter}"
                raise AudienceMismatchError(msg)
            self._walk_ancestors(data)
            subject = AgentId(aud)
        else:
            self._walk_ancestors(data)
            subject = AgentId(data["sub"])

        if data["exp"] < self._now():
            msg = "Token has expired"
            raise ValueError(msg)

        return AuthContext(
            subject=subject,
            scopes=list(data["scopes"]),
            issued_at=data["iat"],
            expires_at=data["exp"],
        )

    async def revoke(self, token: Token) -> None:
        """Revoke a token; all descendants fail verification via ancestor walk.

        Example::

            await auth.revoke(root)
        """
        data, _, _ = self._parse_token(token)
        self._revoked_ids.add(str(data["tok_id"]))

    def tok_id(self, token: Token) -> str:
        """Return the stable token id embedded in a token payload.

        Example::

            tid = auth.tok_id(root)
        """
        data, _, _ = self._parse_token(token)
        return str(data["tok_id"])
