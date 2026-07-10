# SPDX-License-Identifier: Apache-2.0
"""Delegatable capability tokens with cascading revocation.

Allows offline delegation without contacting the central issuer and verifies
cascading revocation transitively down the parent chain.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any

from nest_core.types import AgentId, AuthContext, Token


class RevokedAncestorError(ValueError):
    """Raised when verification fails because a parent or ancestor token was revoked."""

    pass


class DelegatableAuth:
    """Delegatable capability tokens with cascading revocation.

    Example::

        auth = DelegatableAuth(secret=b"secret")
        root = await auth.issue(AgentId("a1"), ["read", "write"])
        child = await auth.delegate(root, AgentId("a2"), ["read"], ttl=60)
        ctx = await auth.verify(child)
    """

    def __init__(self, secret: bytes = b"nest-default-secret", clock: float | None = None) -> None:
        self._secret = secret
        self._clock = clock
        self._revoked: set[str] = set()

    def _now(self) -> float:
        clock_val: Any = self._clock
        if clock_val is not None:
            if callable(clock_val):
                res: Any = clock_val()
                return float(res)
            return float(clock_val)
        return time.time()

    def _sign(self, payload: str, key: bytes | None = None) -> str:
        sign_key = key if key is not None else self._secret
        return hmac.new(sign_key, payload.encode(), hashlib.sha256).hexdigest()

    async def issue(self, subject: AgentId, scopes: list[str]) -> Token:
        """Issue a root capability token.

        Example::

            token = await auth.issue(AgentId("a1"), ["read"])
        """
        now = self._now()
        jti = hashlib.sha256(f"root-{subject}-{scopes}-{now}".encode()).hexdigest()[:16]
        payload = json.dumps(
            {
                "jti": jti,
                "sub": str(subject),
                "scopes": scopes,
                "iat": now,
                "exp": now + 3600,
            },
            sort_keys=True,
        )
        sig = self._sign(payload)
        return Token(f"{payload}|{sig}")

    async def delegate(
        self,
        parent_token: Token,
        audience: AgentId,
        scopes_subset: list[str],
        ttl: float,
    ) -> Token:
        """Delegate a subset of capabilities to another agent offline.

        The child's signature is anchored to the parent's signature.

        Example::

            child = await auth.delegate(parent, AgentId("a2"), ["read"], ttl=60)
        """
        # First verify parent to check signatures, expiration, and revocation state
        parent_ctx = await self.verify(parent_token)

        # Enforce strict subset of scopes
        parent_scopes_set = set(parent_ctx.scopes)
        for scope in scopes_subset:
            if scope not in parent_scopes_set:
                raise ValueError("Escalated scopes: child scope not in parent scopes")

        # Enforce time bounds
        now = self._now()
        exp_child = now + ttl
        if parent_ctx.expires_at is not None and exp_child > parent_ctx.expires_at:
            raise ValueError("Child TTL exceeds parent expiration")

        # Extract parent signature (the last part of parent token)
        parent_parts = str(parent_token).split("|")
        parent_sig = parent_parts[-1]

        # Construct child payload
        jti_seed = f"delegate-{audience}-{scopes_subset}-{parent_token}".encode()
        child_jti = hashlib.sha256(jti_seed).hexdigest()[:16]
        child_payload = json.dumps(
            {
                "jti": child_jti,
                "aud": str(audience),
                "scopes": scopes_subset,
                "iat": now,
                "exp": exp_child,
            },
            sort_keys=True,
        )
        sig_child = self._sign(child_payload, key=parent_sig.encode())
        return Token(f"{parent_token}|{child_payload}|{sig_child}")

    async def verify(self, token: Token, presenter: AgentId | None = None) -> AuthContext:
        """Verify the signature chain, expiration, and transitive revocation of the token.

        Example::

            ctx = await auth.verify(token)
        """
        raw = str(token)
        parts = raw.split("|")
        if len(parts) % 2 != 0 or len(parts) < 2:
            raise ValueError("Invalid token format")

        now = self._now()

        # 1. Verify root token
        payload_0, sig_0 = parts[0], parts[1]
        expected_sig_0 = self._sign(payload_0)
        if not hmac.compare_digest(sig_0, expected_sig_0):
            raise ValueError("Invalid token signature")

        data_0 = json.loads(payload_0)
        if data_0["exp"] < now:
            raise ValueError("Token has expired")

        current_sig = sig_0
        current_sub = data_0["sub"]
        current_scopes = data_0["scopes"]
        current_jti = data_0["jti"]
        current_exp = data_0["exp"]

        jti_list = [current_jti]
        depth = len(parts) // 2 - 1

        # 2. Verify delegation chain
        for i in range(1, depth + 1):
            payload_i, sig_i = parts[2 * i], parts[2 * i + 1]
            expected_sig_i = self._sign(payload_i, key=current_sig.encode())
            if not hmac.compare_digest(sig_i, expected_sig_i):
                raise ValueError("Invalid token signature")

            data_i = json.loads(payload_i)
            # Enforce scopes subset of the parent block (current_scopes)
            for s in data_i["scopes"]:
                if s not in current_scopes:
                    raise ValueError("Escalated scopes")

            # Enforce expiration <= parent expiration
            if data_i["exp"] > current_exp:
                raise ValueError("Child expiration exceeds parent expiration")

            if data_i["exp"] < now:
                raise ValueError("Token has expired")

            current_sig = sig_i
            current_sub = data_i["aud"]
            current_scopes = data_i["scopes"]
            current_jti = data_i["jti"]
            current_exp = data_i["exp"]
            jti_list.append(current_jti)

        # 3. Check transitive revocation
        for idx, jti in enumerate(jti_list):
            if jti in self._revoked:
                if idx < depth:
                    raise RevokedAncestorError("Ancestor token was revoked")
                else:
                    raise ValueError("Token has been revoked")

        # 4. Check audience confusion (presenter must match token subject)
        if presenter is not None and str(presenter) != str(current_sub):
            raise ValueError("Audience confusion: presenter does not match token subject")

        return AuthContext(
            subject=AgentId(current_sub),
            scopes=current_scopes,
            issued_at=data_0["iat"],
            expires_at=current_exp,
        )

    async def revoke(self, token: Token) -> None:
        """Revoke a token.

        Example::

            await auth.revoke(token)
        """
        # We can pull out the JTI of the final block in the token
        raw = str(token)
        parts = raw.split("|")
        if len(parts) >= 2:
            try:
                data = json.loads(parts[-2])
                self._revoked.add(data["jti"])
            except Exception:
                # Fallback to the whole token string if parsing fails
                self._revoked.add(raw)
        else:
            self._revoked.add(raw)
