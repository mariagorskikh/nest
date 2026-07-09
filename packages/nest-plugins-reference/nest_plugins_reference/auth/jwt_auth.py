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
import warnings
from collections import OrderedDict
from collections.abc import Callable
from nest_core.types import AgentId, AuthContext, Token

# Publicly documented weak default — never use in production.
KNOWN_WEAK_SECRET = b"nest-default-secret"
ClockFn = Callable[[], float]


class JwtAuth:
    """Simplified JWT-style auth using HMAC-SHA256.
    Example::
        auth = JwtAuth(secret=b"secret")
        token = await auth.issue(AgentId("a1"), ["read"])
    """

    def __init__(
        self,
        *,
        secret: bytes,
        clock: ClockFn | float | None = None,
        max_revoked: int = 10_000,
    ) -> None:
        if secret == KNOWN_WEAK_SECRET:
            warnings.warn(
                "JwtAuth secret is the publicly known weak default "
                f"{KNOWN_WEAK_SECRET!r}; use a unique secret for any non-simulation "
                "deployment.",
                stacklevel=2,
                category=UserWarning,
            )
        self._secret = secret
        self._clock_fn = self._normalize_clock(clock)
        self._max_revoked = max(1, max_revoked)
        self._revoked: OrderedDict[str, None] = OrderedDict()

    @staticmethod
    def _normalize_clock(clock: ClockFn | float | None) -> ClockFn:
        if clock is None:
            return time.time
        if isinstance(clock, (int, float)):
            fixed = float(clock)
            return lambda: fixed
        return clock

    def set_clock(self, clock: ClockFn | float) -> None:
        """Replace the clock used for token issue/expiry checks."""
        self._clock_fn = self._normalize_clock(clock)

    def _now(self) -> float:
        return self._clock_fn()

    def _sign(self, payload: str) -> str:
        return hmac.new(self._secret, payload.encode(), hashlib.sha256).hexdigest()

    def _remember_revoked(self, token: str) -> None:
        self._revoked[token] = None
        while len(self._revoked) > self._max_revoked:
            self._revoked.popitem(last=False)

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
        self._remember_revoked(str(token))

    @property
    def revoked_count(self) -> int:
        return len(self._revoked)
