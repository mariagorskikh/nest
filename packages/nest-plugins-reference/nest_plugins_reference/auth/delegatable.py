# SPDX-License-Identifier: Apache-2.0
"""Delegatable capability tokens with cascading revocation.

The default :class:`~nest_plugins_reference.auth.jwt_auth.JwtAuth` tracks
revocation in ``_revoked: set[str]`` keyed by the *exact token string*, with no
parent-child relationship at all. That makes it impossible to model the most
common real-world capability pattern: agent A holds a long-lived root token,
mints a narrow, short-lived sub-token for agent B without contacting the
issuer, and revoking A's token must invalidate every token B (or anyone B
further delegated to) derived from it, at the next verify.

This plugin builds a macaroon-style **chained MAC**: a token is a JSON list of
*hops*, one per delegation step from the root. Each hop's HMAC key is the
*previous* hop's MAC (the root hop's key is the plugin's secret), so:

* a party without the root secret cannot forge *any* hop, because every hop's
  MAC recursively depends on a value only the true issuer could have produced;
* **scope narrows monotonically** — :meth:`DelegatableAuth.delegate` refuses to
  mint a child whose scopes are not a strict subset of its parent's (and
  :meth:`~DelegatableAuth.verify` re-checks this structurally, so a tampered
  or malformed hop chain is rejected even if some future code path skipped the
  mint-time check);
* **cascading revocation is O(1) to issue and O(depth) to check**: revoking a
  token adds *one* MAC to :attr:`DelegatableAuth._revoked`; verifying any
  descendant walks its own embedded hop chain and fails the moment it finds a
  revoked MAC — no per-descendant bookkeeping is needed at revoke time.

Audience binding — "child token presented by an agent other than its declared
audience" — is not expressible through the base :class:`~nest_core.layers.auth.Auth`
protocol (``verify(token) -> AuthContext`` has no caller identity), so this
plugin exposes :meth:`~DelegatableAuth.verify_with_audience` as new API on top
of the protocol, exactly as the problem brief calls for with
:meth:`~DelegatableAuth.delegate`.

Example::

    auth = DelegatableAuth(secret=b"root-secret")
    root = await auth.issue(AgentId("orchestrator"), ["read", "write", "deploy"])
    child = await auth.delegate(root, AgentId("worker-1"), ["read"], ttl=60.0)
    ctx = await auth.verify(child)
    assert ctx.subject == AgentId("worker-1")
    assert ctx.scopes == ["read"]

    await auth.revoke(root)
    await auth.verify(child)  # raises RevokedAncestorError
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any, cast

from nest_core.types import AgentId, AuthContext, Token


class ScopeEscalationError(ValueError):
    """Raised when a delegated token would hold a scope its parent lacks.

    Example::

        try:
            await auth.delegate(parent, AgentId("worker-1"), ["admin"], ttl=60.0)
        except ScopeEscalationError as exc:
            assert "admin" in exc.requested_scopes
    """

    def __init__(self, requested_scopes: list[str], parent_scopes: list[str]) -> None:
        self.requested_scopes = requested_scopes
        self.parent_scopes = parent_scopes
        extra = sorted(set(requested_scopes) - set(parent_scopes))
        super().__init__(f"requested scopes {extra} exceed parent scopes {sorted(parent_scopes)}")


class RevokedAncestorError(ValueError):
    """Raised when a token's chain contains a revoked ancestor (or itself).

    Example::

        try:
            await auth.verify(child_of_revoked_parent)
        except RevokedAncestorError as exc:
            assert exc.revoked_mac
    """

    def __init__(self, revoked_mac: str, depth: int) -> None:
        self.revoked_mac = revoked_mac
        self.depth = depth
        super().__init__(f"chain hop {depth} (mac {revoked_mac[:12]}...) has been revoked")


class AudienceMismatchError(ValueError):
    """Raised when a token is presented by an agent other than its holder.

    Example::

        try:
            await auth.verify_with_audience(child, AgentId("attacker"))
        except AudienceMismatchError as exc:
            assert exc.presented_by == AgentId("attacker")
    """

    def __init__(self, presented_by: AgentId, declared_holder: AgentId) -> None:
        self.presented_by = presented_by
        self.declared_holder = declared_holder
        super().__init__(f"token held by {declared_holder!r} presented by {presented_by!r}")


class TokenChainMalformedError(ValueError):
    """Raised when a token's structure or MAC chain cannot be trusted.

    Covers empty hop lists, non-monotonic scopes/TTLs baked into the chain,
    and MAC mismatches (forged or corrupted tokens) in one place so callers
    verifying untrusted input only need one exception type to guard against
    "this token is not authentic," distinct from :class:`RevokedAncestorError`
    ("this token *was* authentic but its authority was withdrawn").

    Example::

        try:
            await auth.verify(Token("not-json"))
        except TokenChainMalformedError:
            pass
    """


def _canonical(hop: dict[str, Any]) -> bytes:
    """Return the deterministic byte encoding of one hop, used as the HMAC message.

    Example::

        mac = hmac.new(key, _canonical(hop), hashlib.sha256).digest()
    """
    return json.dumps(hop, sort_keys=True).encode("utf-8")


def _hop(holder: AgentId, scopes: list[str], issued_at: float, expires_at: float) -> dict[str, Any]:
    """Build one delegation hop's plain-data payload.

    Example::

        hop = _hop(AgentId("worker-1"), ["read"], issued_at=0.0, expires_at=60.0)
    """
    return {
        "holder": str(holder),
        "scopes": sorted(scopes),
        "issued_at": issued_at,
        "expires_at": expires_at,
    }


class DelegatableAuth:
    """Macaroon-style capability tokens: strict-subset delegation, cascading revocation.

    Drop-in replacement for ``jwt`` that adds :meth:`delegate` on top of the
    base :class:`~nest_core.layers.auth.Auth` protocol. Revocation state is
    held in-process for the plugin's lifetime (mirrors ``JwtAuth._revoked``).

    Example::

        auth = DelegatableAuth(secret=b"root-secret")
        root = await auth.issue(AgentId("orchestrator"), ["read", "write"])
    """

    def __init__(
        self,
        secret: bytes = b"nest-default-delegation-secret",
        clock: float | None = None,
    ) -> None:
        self._secret = secret
        self._clock = clock
        self._revoked: set[str] = set()

    def _now(self) -> float:
        if self._clock is not None:
            return self._clock
        return time.time()

    def set_clock(self, clock: float) -> None:
        """Advance the plugin's deterministic simulation clock.

        Mirrors the ``set_clock`` convention used by other rotating/timed
        reference plugins (see ``ed25519_rotating``) so scenario drivers can
        move time forward without reaching into private state.

        Example::

            auth.set_clock(3700.0)
        """
        self._clock = clock

    async def issue(self, subject: AgentId, scopes: list[str]) -> Token:
        """Issue a root capability token for a subject with given scopes.

        Satisfies the base :class:`~nest_core.layers.auth.Auth` protocol: a
        root token is a one-hop chain keyed directly by :attr:`_secret`.

        Example::

            token = await auth.issue(AgentId("orchestrator"), ["read", "write"])
        """
        now = self._now()
        hop = _hop(subject, scopes, issued_at=now, expires_at=now + 3600)
        mac = hmac.new(self._secret, _canonical(hop), hashlib.sha256).hexdigest()
        return Token(json.dumps({"hops": [hop], "mac": mac}, sort_keys=True))

    async def delegate(
        self,
        parent_token: Token,
        audience: AgentId,
        scopes_subset: list[str],
        ttl: float,
    ) -> Token:
        """Mint a child token narrowing ``parent_token``'s authority to ``audience``.

        ``scopes_subset`` must be a strict subset of the parent's current
        scopes (else :class:`ScopeEscalationError`) and ``ttl`` must not push
        the child's expiry past the parent's (else :class:`ValueError`). The
        parent is verified first, so delegating from an already-revoked or
        expired parent fails immediately rather than minting a child that
        would only fail later.

        Example::

            child = await auth.delegate(root, AgentId("worker-1"), ["read"], ttl=60.0)
        """
        parent_ctx = await self.verify(parent_token)
        if not set(scopes_subset) <= set(parent_ctx.scopes):
            raise ScopeEscalationError(scopes_subset, parent_ctx.scopes)

        now = self._now()
        expires_at = now + ttl
        if parent_ctx.expires_at is not None and expires_at > parent_ctx.expires_at:
            msg = (
                f"child ttl would expire at {expires_at}, "
                f"after parent expiry {parent_ctx.expires_at}"
            )
            raise ValueError(msg)

        parsed = _parse(parent_token)
        parent_mac_bytes = bytes.fromhex(parsed["mac"])
        hop = _hop(audience, scopes_subset, issued_at=now, expires_at=expires_at)
        mac = hmac.new(parent_mac_bytes, _canonical(hop), hashlib.sha256).hexdigest()
        hops = [*parsed["hops"], hop]
        return Token(json.dumps({"hops": hops, "mac": mac}, sort_keys=True))

    async def verify(self, token: Token) -> AuthContext:
        """Verify a token's full MAC chain, monotonicity, expiry, and revocation.

        Recomputes every hop's MAC from :attr:`_secret` forward — a token
        cannot verify unless every hop was genuinely produced by this plugin
        (directly or via a chain of :meth:`delegate` calls rooted in it).
        Also re-checks that scopes only narrow and expiry only tightens hop
        to hop, so a structurally tampered chain fails even if some MAC
        collided (defense in depth, not the primary authenticity check).

        Example::

            ctx = await auth.verify(child)
            assert ctx.subject == AgentId("worker-1")
        """
        parsed = _parse(token)
        hops = parsed["hops"]
        claimed_mac = parsed["mac"]

        key = self._secret
        computed_macs: list[str] = []
        for depth, hop in enumerate(hops):
            mac_bytes = hmac.new(key, _canonical(hop), hashlib.sha256).digest()
            mac_hex = mac_bytes.hex()
            computed_macs.append(mac_hex)
            if depth > 0:
                prev = hops[depth - 1]
                if not set(hop["scopes"]) <= set(prev["scopes"]):
                    msg = (
                        f"hop {depth} scopes {hop['scopes']} exceed "
                        f"hop {depth - 1} scopes {prev['scopes']}"
                    )
                    raise TokenChainMalformedError(msg)
                if hop["expires_at"] > prev["expires_at"]:
                    msg = (
                        f"hop {depth} expires_at {hop['expires_at']} exceeds "
                        f"hop {depth - 1} expires_at {prev['expires_at']}"
                    )
                    raise TokenChainMalformedError(msg)
            key = mac_bytes

        if not hmac.compare_digest(computed_macs[-1], claimed_mac):
            msg = "token MAC does not match its claimed hop chain"
            raise TokenChainMalformedError(msg)

        for depth, mac_hex in enumerate(computed_macs):
            if mac_hex in self._revoked:
                raise RevokedAncestorError(mac_hex, depth)

        last = hops[-1]
        expires_at = cast("float", last["expires_at"])
        if expires_at < self._now():
            msg = f"token expired at {expires_at}"
            raise ValueError(msg)

        return AuthContext(
            subject=AgentId(last["holder"]),
            scopes=list(last["scopes"]),
            issued_at=last["issued_at"],
            expires_at=expires_at,
        )

    async def verify_with_audience(self, token: Token, presented_by: AgentId) -> AuthContext:
        """Verify a token and additionally require it be presented by its own holder.

        New API beyond the base :class:`~nest_core.layers.auth.Auth` protocol
        (``verify`` alone has no caller identity to check against). Catches
        the "audience confusion" attack: an agent that intercepts or is
        forwarded a token that was never delegated to it.

        Example::

            ctx = await auth.verify_with_audience(child, AgentId("worker-1"))
        """
        ctx = await self.verify(token)
        if ctx.subject != presented_by:
            raise AudienceMismatchError(presented_by, ctx.subject)
        return ctx

    async def revoke(self, token: Token) -> None:
        """Revoke a token, cascading to every token delegated from it.

        Adds only the *revoked token's own* MAC to :attr:`_revoked` — O(1).
        Every descendant's chain embeds this MAC at the matching depth, so
        :meth:`verify` on any descendant fails without any per-descendant
        state being touched here.

        Example::

            await auth.revoke(root)
            await auth.verify(child)  # raises RevokedAncestorError
        """
        parsed = _parse(token)
        self._revoked.add(parsed["mac"])


def _parse(token: Token) -> dict[str, Any]:
    """Parse and structurally validate a token's JSON envelope.

    Example::

        parsed = _parse(token)
        assert parsed["hops"] and parsed["mac"]
    """
    try:
        loaded = json.loads(str(token))
    except json.JSONDecodeError as exc:
        raise TokenChainMalformedError(f"token is not valid JSON: {exc}") from exc
    if (
        not isinstance(loaded, dict)
        or "hops" not in loaded
        or "mac" not in loaded
        or not isinstance(loaded["hops"], list)
        or not loaded["hops"]
    ):
        raise TokenChainMalformedError(
            "token must be a JSON object with a non-empty 'hops' list and a 'mac' field"
        )
    return cast("dict[str, Any]", loaded)
