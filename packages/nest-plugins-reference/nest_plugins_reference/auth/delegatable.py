# SPDX-License-Identifier: Apache-2.0
"""Delegatable capability auth plugin with cascading revocation.

This plugin implements **delegatable capability tokens** inspired by the
macaroon construction (Birgisson et al., 2014).
"""

from __future__ import annotations

import hashlib
import hmac
import json

from nest_core.types import AgentId, AuthContext, Token

# ---------------------------------------------------------------------------
# Typed exceptions
# ---------------------------------------------------------------------------


class ScopeEscalationError(ValueError):
    pass


class RevokedAncestorError(ValueError):
    pass


class AudienceError(ValueError):
    pass


class RevocationViewStaleError(ValueError):
    pass


class ResourceGuardError(ValueError):
    pass


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_SEP = "|"


def _sign(key: bytes, payload: str) -> str:
    """HMAC-SHA256 of payload."""
    return hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()


def _chain_hash(prev_hash: str, payload: str, sig: str) -> str:
    """Derive chain hash from previous hash, payload, and signature."""
    material = f"{prev_hash}:{payload}:{sig}"
    return hashlib.sha256(material.encode()).hexdigest()


# ---------------------------------------------------------------------------
# DelegatableAuth
# ---------------------------------------------------------------------------


class DelegatableAuth:
    def __init__(
        self,
        secret: bytes = b"nest-delegatable-secret",
        clock: float | None = None,
        stale_after: float = 300.0,
    ) -> None:
        self._secret = secret
        self._clock_override = clock
        self._stale_after = stale_after
        # Maps chain_hash -> revocation epoch
        self._revoked: dict[str, int] = {}
        self._epoch = 0

    def advance_epoch(self) -> None:
        self._epoch += 1

    def _now(self) -> float:
        if self._clock_override is not None:
            return self._clock_override
        import time

        return time.time()

    async def issue(self, subject: AgentId, scopes: list[str]) -> Token:
        now = self._now()
        payload = json.dumps(
            {
                "sub": str(subject),
                "aud": None,
                "scopes": sorted(scopes),
                "iat": now,
                "exp": now + 3600.0,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        sig = _sign(self._secret, payload)
        raw = f"{payload}{_SEP}{sig}"
        return Token(raw)

    async def delegate(
        self,
        parent_token: Token,
        audience: AgentId,
        scopes: list[str],
        ttl: float,
    ) -> Token:
        if ttl <= 0:
            raise ValueError("ttl must be positive")

        raw = str(parent_token)
        parts = raw.split(_SEP)
        if len(parts) < 2:
            raise ValueError("Malformed token")

        payloads = parts[:-1]
        parent_sig = parts[-1]

        last_payload_str = payloads[-1]
        try:
            parent_data = json.loads(last_payload_str)
        except json.JSONDecodeError:
            raise ValueError("Malformed payload") from None

        if parent_data["exp"] < self._now():
            raise ValueError("parent token has expired")

        parent_scopes = set(parent_data["scopes"])
        child_scopes = set(scopes)
        extra = child_scopes - parent_scopes
        if extra:
            raise ScopeEscalationError(
                f"Scope escalation: {extra!r} not in parent scopes {parent_scopes!r}"
            )
        if child_scopes == parent_scopes:
            raise ScopeEscalationError(
                "Delegated scopes must be a strict subset of the parent scopes"
            )

        parent_remaining = float(parent_data["exp"]) - self._now()
        if parent_remaining <= 0:
            raise ValueError("parent token has expired")
        actual_ttl = min(ttl, parent_remaining)

        now = self._now()
        child_payload = json.dumps(
            {
                "sub": parent_data["sub"],
                "aud": str(audience),
                "scopes": sorted(child_scopes),
                "iat": now,
                "exp": now + actual_ttl,
            },
            sort_keys=True,
            separators=(",", ":"),
        )

        child_sig = _sign(parent_sig.encode(), child_payload)
        new_raw = _SEP.join(payloads + [child_payload, child_sig])
        return Token(new_raw)

    async def verify(
        self, token: Token, *, presenter: AgentId | None = None, visible_epoch: int | None = None
    ) -> AuthContext:
        parts = str(token).split(_SEP)
        if len(parts) < 2:
            raise ValueError("Malformed token")

        payloads = parts[:-1]
        final_sig = parts[-1]

        current_key = self._secret
        prev_hash = ""
        last_data = None

        now = self._now()
        if visible_epoch is None:
            visible_epoch = self._epoch

        # Check partition fence
        if self._epoch - visible_epoch > self._stale_after:
            raise RevocationViewStaleError(
                f"Revocation view stale: {visible_epoch} vs {self._epoch}"
            )

        for payload_str in payloads:
            try:
                data = json.loads(payload_str)
            except json.JSONDecodeError:
                raise ValueError("Malformed payload") from None

            sig = _sign(
                current_key if isinstance(current_key, bytes) else current_key.encode(), payload_str
            )
            current_key = sig

            chain_hash = _chain_hash(prev_hash, payload_str, sig)
            prev_hash = chain_hash

            if chain_hash in self._revoked:
                raise RevokedAncestorError(f"Ancestor token revoked: {chain_hash[:8]}")

            if data["exp"] < now:
                raise ValueError(f"Token expired at {data['exp']:.0f}")

            if last_data is not None:
                parent_scopes = set(last_data["scopes"])
                child_scopes = set(data["scopes"])
                if not child_scopes.issubset(parent_scopes):
                    raise ScopeEscalationError("Scope escalation detected in chain")
                if data["exp"] > last_data["exp"]:
                    raise ValueError("Child expiry exceeds parent expiry")

            last_data = data

        if current_key != final_sig:
            raise ValueError("Invalid token signature")

        assert last_data is not None, "Payloads must not be empty"

        if (
            presenter is not None
            and last_data["aud"] is not None
            and last_data["aud"] != str(presenter)
        ):
            raise AudienceError(
                f"Audience mismatch: token is for {last_data['aud']!r}, presented by {presenter!r}"
            )

        return AuthContext(
            subject=AgentId(last_data["sub"]),
            scopes=last_data["scopes"],
            issued_at=last_data["iat"],
            expires_at=last_data["exp"],
        )

    async def revoke(self, token: Token) -> None:
        parts = str(token).split(_SEP)
        if len(parts) < 2:
            raise ValueError("Malformed token")

        payloads = parts[:-1]

        current_key = self._secret
        prev_hash = ""

        for payload_str in payloads:
            sig = _sign(
                current_key if isinstance(current_key, bytes) else current_key.encode(), payload_str
            )
            current_key = sig
            chain_hash = _chain_hash(prev_hash, payload_str, sig)
            prev_hash = chain_hash

        self._revoked[prev_hash] = self._epoch
        self.advance_epoch()

    async def authorize(
        self,
        token: Token,
        presenter: AgentId,
        required_scope: str,
        visible_epoch: int | None = None,
    ) -> None:
        ctx = await self.verify(token, presenter=presenter, visible_epoch=visible_epoch)
        if required_scope not in ctx.scopes:
            raise ResourceGuardError(f"Token missing required scope: {required_scope}")
