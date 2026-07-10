# SPDX-License-Identifier: Apache-2.0
"""Delegatable auth plugin — HMAC-chained capability tokens with cascading revocation.

Based on the Macaroon construction (Birgisson et al., 2014): each child
token's signing key is derived from its parent's HMAC, so revoking a
parent transitively invalidates every descendant without a per-child
revocation list.

Four attacks are blocked:

* **Scope escalation** — ``delegate()`` raises ``ScopeEscalationError``
  if the requested child scopes are not a strict subset of the parent's.
* **Stale-parent revocation** — ``verify()`` walks the ancestry chain and
  raises ``RevokedAncestorError`` if any ancestor token has been revoked.
* **Audience confusion at verify** — ``verify()`` raises
  ``AudienceConfusionError`` when the token has a declared audience and
  ``caller`` is absent OR does not match that audience.  The check is
  unconditional: omitting ``caller=`` on an audience-bound token is rejected
  just as firmly as passing the wrong identity.  Only root tokens (which carry
  no audience field) may be verified without a caller.  A gap where the
  no-``caller=`` path was silently accepted was found and closed during the
  same review cycle as the ``delegate()`` fix below.
* **Audience confusion at delegate** — ``delegate()`` raises
  ``AudienceConfusionError`` when the parent token has a declared audience and
  ``caller`` is absent OR does not match that audience.  This blocks the exploit
  unconditionally: a thief calling ``delegate(stolen, ...)`` with *no* ``caller=``
  kwarg is rejected just as firmly as one who passes a wrong ``caller=``.

The plugin satisfies the ``Auth`` protocol (``issue`` / ``verify`` /
``revoke``).  The extra ``delegate`` surface is additive; existing callers
that only call ``issue`` / ``verify`` / ``revoke`` are unaffected.

Example::

    auth = DelegatableAuth(secret=b"sim-secret")
    root = await auth.issue(AgentId("coordinator"), ["admin", "read", "write"])
    child = await auth.delegate(root, AgentId("worker"), ["read", "write"], ttl=1800.0)
    ctx = await auth.verify(child, caller=AgentId("worker"))
    assert ctx.scopes == ["read", "write"]
    # Only the worker can re-delegate the worker's token:
    grandchild = await auth.delegate(
        child, AgentId("leaf"), ["read"], ttl=60.0, caller=AgentId("worker")
    )
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Any, cast

from nest_core.types import AgentId, AuthContext, Token

# ---------------------------------------------------------------------------
# Typed exceptions
# ---------------------------------------------------------------------------


class ScopeEscalationError(ValueError):
    """Raised when a child token requests scopes not held by the parent.

    Example::

        try:
            await auth.delegate(parent, audience, ["admin"], ttl=60.0)
        except ScopeEscalationError:
            pass  # parent did not hold "admin"
    """


class RevokedAncestorError(ValueError):
    """Raised when a token's ancestry chain contains a revoked token.

    Example::

        await auth.revoke(parent_token)
        try:
            await auth.verify(child_token)
        except RevokedAncestorError:
            pass
    """


class AudienceConfusionError(ValueError):
    """Raised when a token is verified by an agent other than its audience.

    Example::

        child = await auth.delegate(root, AgentId("alice"), ["read"], ttl=60.0)
        try:
            await auth.verify(child, caller=AgentId("bob"))
        except AudienceConfusionError:
            pass
    """


# ---------------------------------------------------------------------------
# Internal record
# ---------------------------------------------------------------------------


@dataclass
class _TokenRecord:
    """Internal registry entry for a single issued or delegated token."""

    token_id: str
    parent_id: str | None  # None for root tokens
    subject: AgentId
    audience: AgentId | None  # None for root tokens
    scopes: list[str]
    exp: float
    sig_hex: str  # HMAC of this token's payload — used as child signing key


# ---------------------------------------------------------------------------
# Plugin
# ---------------------------------------------------------------------------


class DelegatableAuth:
    """HMAC-chained capability delegation with cascading revocation.

    A single instance is shared by all agents in a simulation (same as
    ``JwtAuth``).  Token state is kept in two in-process dicts:
    ``_registry`` maps token IDs to records, ``_revoked_ids`` holds the set
    of revoked token IDs.  Revoking a parent implicitly invalidates all
    descendants because ``verify`` walks the ``parent_id`` chain.

    Clock is injected for deterministic simulation (Tier 1).  Pass
    ``clock=ctx.time`` or a fixed float; the default falls back to
    ``time.time()`` so the plugin also works in ad-hoc scripts.

    Example::

        auth = DelegatableAuth(secret=b"sim-secret")
        root = await auth.issue(AgentId("coordinator"), ["admin", "read"])
        child = await auth.delegate(root, AgentId("worker"), ["read"], ttl=600.0)
        ctx = await auth.verify(child, caller=AgentId("worker"))
        assert "read" in ctx.scopes
    """

    def __init__(
        self,
        secret: bytes = b"nest-delegate-secret",
        clock: float | None = None,
    ) -> None:
        self._secret = secret
        self._clock = clock
        self._registry: dict[str, _TokenRecord] = {}
        self._revoked_ids: set[str] = set()
        self._counter: int = 0  # monotonic counter for deterministic token IDs

    # -- helpers -------------------------------------------------------------

    def _now(self) -> float:
        if self._clock is not None:
            return self._clock
        return time.time()

    def _sign(self, key: bytes, payload: str) -> str:
        return hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()

    def set_clock(self, t: float) -> None:
        """Override the injected clock value.

        Useful in tests to simulate token expiry without creating a new
        instance.

        Example::

            auth.set_clock(9999.0)
        """
        self._clock = t

    def _parse(self, token: Token) -> tuple[dict[str, Any], str]:
        """Split a token string into (payload_dict, sig_hex).

        Example::

            data, sig = auth._parse(token)
        """
        raw = str(token)
        parts = raw.rsplit("|", 1)
        if len(parts) != 2:
            msg = "malformed token: missing signature separator"
            raise ValueError(msg)
        return json.loads(parts[0]), parts[1]

    def _signing_key(self, parent_id: str | None) -> bytes:
        """Return the signing key for a token whose parent is ``parent_id``."""
        if parent_id is None:
            return self._secret
        rec = self._registry.get(parent_id)
        if rec is None:
            msg = f"parent token not found in registry: {parent_id}"
            raise ValueError(msg)
        return bytes.fromhex(rec.sig_hex)

    def _mint(
        self,
        parent_id: str | None,
        subject: AgentId,
        audience: AgentId | None,
        scopes: list[str],
        ttl: float,
    ) -> Token:
        """Build, sign, register, and return a new token."""
        now = self._now()
        self._counter += 1
        token_id = f"tok-{self._counter:04d}"
        payload = json.dumps(
            {
                "aud": str(audience) if audience is not None else None,
                "exp": now + ttl,
                "iat": now,
                "pid": parent_id,
                "scopes": sorted(scopes),
                "sub": str(subject),
                "tid": token_id,
            },
            sort_keys=True,
        )
        key = self._signing_key(parent_id)
        sig = self._sign(key, payload)
        self._registry[token_id] = _TokenRecord(
            token_id=token_id,
            parent_id=parent_id,
            subject=subject,
            audience=audience,
            scopes=scopes,
            exp=now + ttl,
            sig_hex=sig,
        )
        return Token(f"{payload}|{sig}")

    # -- Auth protocol -------------------------------------------------------

    async def issue(self, subject: AgentId, scopes: list[str], ttl: float = 3600.0) -> Token:
        """Issue a root capability token for *subject* with *scopes*.

        Example::

            root = await auth.issue(AgentId("coordinator"), ["admin", "read"], ttl=7200.0)
        """
        return self._mint(
            parent_id=None,
            subject=subject,
            audience=None,
            scopes=scopes,
            ttl=ttl,
        )

    async def verify(self, token: Token, *, caller: AgentId | None = None) -> AuthContext:
        """Verify *token* and return its auth context.

        Raises:
            ValueError: Malformed token, invalid signature, or expired.
            RevokedAncestorError: Any token in the ancestry chain is revoked.
            AudienceConfusionError: *caller* is provided and does not match
                the token's declared audience.

        Example::

            ctx = await auth.verify(child, caller=AgentId("worker"))
            assert "read" in ctx.scopes
        """
        data, sig = self._parse(token)
        token_id = str(data["tid"])
        parent_id = data["pid"]
        if isinstance(parent_id, str):
            parent_str: str | None = parent_id
        else:
            parent_str = None

        # Signature check
        payload = str(token).rsplit("|", 1)[0]
        key = self._signing_key(parent_str)
        if not hmac.compare_digest(sig, self._sign(key, payload)):
            msg = "invalid token signature"
            raise ValueError(msg)

        # Expiry check
        exp = float(str(data["exp"]))
        if exp < self._now():
            msg = "token has expired"
            raise ValueError(msg)

        # Ancestry revocation check (walk parent chain)
        current_id: str | None = token_id
        while current_id is not None:
            if current_id in self._revoked_ids:
                msg = f"token ancestry contains a revoked token: {current_id}"
                raise RevokedAncestorError(msg)
            rec = self._registry.get(current_id)
            current_id = rec.parent_id if rec is not None else None

        # Audience check — unconditional when the token has a declared audience.
        # Mirrors delegate()'s fix: omitting caller= is as wrong as supplying a wrong one.
        raw_aud = data.get("aud")
        audience: AgentId | None = AgentId(str(raw_aud)) if raw_aud is not None else None
        if audience is not None and (caller is None or caller != audience):
            msg = f"token issued for {audience!r}; presented by {caller!r}"
            raise AudienceConfusionError(msg)

        scopes_raw = data.get("scopes", [])
        if isinstance(scopes_raw, list):
            scopes = [str(s) for s in cast("list[Any]", scopes_raw)]
        else:
            scopes = []
        return AuthContext(
            subject=AgentId(str(data["sub"])),
            scopes=scopes,
            issued_at=float(str(data["iat"])),
            expires_at=exp,
        )

    async def revoke(self, token: Token) -> None:
        """Revoke *token* and (by cascade) all tokens derived from it.

        Example::

            await auth.revoke(parent_token)
            # all children of parent_token are now unverifiable
        """
        data, _ = self._parse(token)
        self._revoked_ids.add(str(data["tid"]))

    # -- Extension: delegation -----------------------------------------------

    async def delegate(
        self,
        parent_token: Token,
        audience: AgentId,
        scopes: list[str],
        ttl: float,
        *,
        caller: AgentId | None = None,
    ) -> Token:
        """Issue a child token derived from *parent_token*.

        The child's scopes must be a subset of the parent's scopes.  The
        child's effective TTL is capped at the parent's remaining lifetime.
        Revoking the parent (or any ancestor) later invalidates this child.

        Args:
            parent_token: The token to delegate from. Must be currently valid.
            audience: The agent the child token is issued to.
            scopes: Capability scopes for the child (must ⊆ parent scopes).
            ttl: Requested lifetime in seconds; capped at parent's remaining TTL.
            caller: Identity of the agent performing the delegation.  When the
                parent token has a declared audience (i.e. it is itself a
                delegated token, not a root token), ``caller`` is **required**
                and must exactly match that audience.  Omitting ``caller`` on
                an audience-bound parent raises ``AudienceConfusionError``
                immediately, blocking the exploit where a thief calls
                ``delegate(stolen, ...)`` with no ``caller=`` kwarg.

        Raises:
            ScopeEscalationError: *scopes* is not a subset of the parent's.
            RevokedAncestorError: The parent or one of its ancestors is revoked.
            AudienceConfusionError: The parent token has a declared audience and
                ``caller`` is absent or does not match it.
            ValueError: The parent token is malformed, has an invalid signature,
                or has expired.

        Example::

            root = await auth.issue(AgentId("coord"), ["read", "write"], ttl=3600.0)
            child = await auth.delegate(root, AgentId("worker"), ["read"], ttl=600.0)
            # Only the worker can re-delegate:
            grandchild = await auth.delegate(
                child, AgentId("leaf"), ["read"], ttl=60.0, caller=AgentId("worker")
            )
        """
        # Audience-binding check: must happen before verify() because verify()
        # only raises AudienceConfusionError when caller is not None.  An attacker
        # calling delegate(stolen) with no caller= would otherwise bypass the check.
        # Rule: if the parent token has a declared audience, caller must be supplied
        # and must match — omitting caller= is as wrong as supplying the wrong one.
        parent_data, _ = self._parse(parent_token)
        raw_aud = parent_data.get("aud")
        if raw_aud is not None and (caller is None or str(caller) != str(raw_aud)):
            msg = f"token issued for {raw_aud!r}; caller {caller!r} may not delegate it"
            raise AudienceConfusionError(msg)

        # Verify parent (also catches revocation, expiry, and signature)
        parent_ctx = await self.verify(parent_token, caller=caller)
        parent_tid = str(parent_data["tid"])
        parent_exp = float(str(parent_data["exp"]))

        # Scope subset check
        parent_scopes = set(parent_ctx.scopes)
        requested = set(scopes)
        if not requested <= parent_scopes:
            escalated = sorted(requested - parent_scopes)
            parent_sorted = sorted(parent_scopes)
            msg = f"child scopes {escalated!r} not held by parent (has {parent_sorted!r})"
            raise ScopeEscalationError(msg)

        # Cap TTL at parent's remaining lifetime
        remaining = parent_exp - self._now()
        effective_ttl = min(ttl, remaining)
        if effective_ttl <= 0:
            msg = "parent token has expired; cannot delegate"
            raise ValueError(msg)

        return self._mint(
            parent_id=parent_tid,
            subject=AgentId(str(parent_data["sub"])),
            audience=audience,
            scopes=scopes,
            ttl=effective_ttl,
        )
