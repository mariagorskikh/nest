# SPDX-License-Identifier: Apache-2.0
"""JWT auth plugin — sign tokens with HMAC-SHA256 for simulation.

Example::

    auth = JwtAuth(secret=b"my-secret")
    token = await auth.issue(AgentId("a1"), ["read", "write"])
    ctx = await auth.verify(token)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time

from nest_core.types import AgentId, AuthContext, Token

from nest_plugins_reference._simulation_warning import warn_simulation_only


class JwtAuth:
    """Simplified JWT-style auth using HMAC-SHA256.

    Example::

        auth = JwtAuth(secret=b"secret")
        token = await auth.issue(AgentId("a1"), ["read"])
    """

    def __init__(self, secret: bytes = b"nest-default-secret", clock: float | None = None) -> None:
        warn_simulation_only(
            "JwtAuth",
            "HMAC pipe-delimited tokens, not RFC 7519 JWT",
        )
        self._secret = secret
        self._clock = clock
        self._revoked: set[str] = set()

    def _now(self) -> float:
        if self._clock is not None:
            return self._clock
        return time.time()

    def _sign(self, payload: str) -> str:
        return hmac.new(self._secret, payload.encode(), hashlib.sha256).hexdigest()

    async def issue(self, subject: AgentId, scopes: list[str]) -> Token:
        """Issue a token for a subject with given scopes.

        Example::

            token = await auth.issue(AgentId("a1"), ["read", "write"])
        """
        now = self._now()
        payload = json.dumps(
            {
                "sub": str(subject),
                "scopes": scopes,
                "iat": now,
                "exp": now + 3600,
            },
            sort_keys=True,
        )
        sig = self._sign(payload)
        return Token(f"{payload}|{sig}")

    async def verify(self, token: Token) -> AuthContext:
        """Verify a token and return its context.

        Example::

            ctx = await auth.verify(token)
            assert ctx.subject == AgentId("a1")
        """
        raw = str(token)
        if raw in self._revoked:
            msg = "Token has been revoked"
            raise ValueError(msg)

        parts = raw.rsplit("|", 1)
        if len(parts) != 2:
            msg = "Invalid token format"
            raise ValueError(msg)

        payload_str, sig = parts
        expected = self._sign(payload_str)
        if not hmac.compare_digest(sig, expected):
            msg = "Invalid token signature"
            raise ValueError(msg)

        data = json.loads(payload_str)
        if data["exp"] < self._now():
            msg = "Token has expired"
            raise ValueError(msg)
        return AuthContext(
            subject=AgentId(data["sub"]),
            scopes=data["scopes"],
            issued_at=data["iat"],
            expires_at=data["exp"],
        )

    async def revoke(self, token: Token) -> None:
        """Revoke a token.

        Example::

            await auth.revoke(token)
        """
        self._revoked.add(str(token))
