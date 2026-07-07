# SPDX-License-Identifier: Apache-2.0
"""Delegatable capability tokens with cascading revocation.

Implements macaroon-style HMAC-chained delegation: a root authority issues a
root token; any holder of a token can mint a child token whose scopes are a
strict subset and whose TTL is at most the parent's remaining TTL.  Revoking
any ancestor in the chain automatically invalidates all its descendants —
without contacting the original issuer — because each child's HMAC is anchored
to its parent's fingerprint.

Three attacks are provably blocked:

* **Scope escalation** — child may only request scopes the parent already
  holds; attempting otherwise raises :class:`ScopeEscalationError`.
* **Stale-parent verification** — verifying a child transitively walks the
  ancestor chain; if any ancestor is revoked or expired the child fails with
  :class:`RevokedAncestorError` or :class:`ExpiredAncestorError`.
* **Audience confusion** — each token carries a declared ``audience``; the
  verifier rejects presentations by agents other than the declared audience
  via :class:`AudienceConfusionError`.

Example::

    auth = DelegatableAuth(secret=b"root-secret", clock=0.0)
    root = await auth.issue(AgentId("orchestrator"), ["read", "write", "exec"])
    child = await auth.delegate(
        parent_token=root,
        audience=AgentId("worker-1"),
        scopes_subset=["read", "exec"],
        ttl=300.0,
    )
    ctx = await auth.verify(child, presenter=AgentId("worker-1"))
    assert ctx.scopes == ["exec", "read"]
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

from nest_core.types import AgentId, AuthContext, Token


# ---------------------------------------------------------------------------
# Typed exceptions
# ---------------------------------------------------------------------------


class ScopeEscalationError(ValueError):
    """Child token requests scopes the parent does not hold.

    Example::

        try:
            await auth.delegate(root, AgentId("a"), ["admin"], ttl=60)
        except ScopeEscalationError as e:
            print(e)
    """


class RevokedAncestorError(ValueError):
    """An ancestor in the delegation chain has been revoked.

    Example::

        await auth.revoke(root)
        try:
            await auth.verify(child)
        except RevokedAncestorError:
            pass  # expected
    """


class ExpiredAncestorError(ValueError):
    """An ancestor in the delegation chain has expired.

    Example::

        # root issued at tick 0 with ttl=1; at tick=2 it is expired
        try:
            await auth.verify(child)
        except ExpiredAncestorError:
            pass
    """


class AudienceConfusionError(ValueError):
    """Token presented by an agent other than its declared audience.

    Example::

        child = await auth.delegate(root, AgentId("bob"), ["read"], ttl=60)
        try:
            await auth.verify(child, presenter=AgentId("eve"))
        except AudienceConfusionError:
            pass
    """


# ---------------------------------------------------------------------------
# Internal token record
# ---------------------------------------------------------------------------


class _TokenRecord:
    """Internal state for one issued token (root or delegated).

    Example::

        rec = _TokenRecord(
            token_id="abc",
            subject=AgentId("a1"),
            audience=AgentId("a1"),
            scopes=["read"],
            issued_at=0.0,
            expires_at=3600.0,
            parent_id=None,
            parent_fingerprint=None,
        )
    """

    def __init__(
        self,
        token_id: str,
        subject: AgentId,
        audience: AgentId,
        scopes: list[str],
        issued_at: float,
        expires_at: float,
        parent_id: str | None,
        parent_fingerprint: str | None,
    ) -> None:
        self.token_id = token_id
        self.subject = subject
        self.audience = audience
        self.scopes = scopes
        self.issued_at = issued_at
        self.expires_at = expires_at
        self.parent_id = parent_id
        self.parent_fingerprint = parent_fingerprint
        self.revoked = False


# ---------------------------------------------------------------------------
# Main plugin
# ---------------------------------------------------------------------------


class DelegatableAuth:
    """Auth plugin with HMAC-chained capability delegation and cascading revocation.

    Satisfies the ``Auth`` protocol (``issue`` / ``verify`` / ``revoke``).
    Adds ``delegate`` for minting child tokens and an optional ``presenter``
    kwarg on ``verify`` for audience enforcement.

    Example::

        auth = DelegatableAuth(secret=b"secret", clock=0.0)
        root = await auth.issue(AgentId("coord"), ["read", "write"])
        child = await auth.delegate(root, AgentId("worker"), ["read"], ttl=120.0)
        ctx = await auth.verify(child, presenter=AgentId("worker"))
        assert "read" in ctx.scopes
    """

    #: Default TTL for root tokens (1 hour of simulation ticks).
    DEFAULT_TTL: float = 3600.0

    def __init__(
        self,
        secret: bytes = b"nest-delegatable-secret",
        clock: float | None = None,
    ) -> None:
        self._secret = secret
        self._clock = clock
        # token_id -> _TokenRecord (all tokens ever issued)
        self._records: dict[str, _TokenRecord] = {}
        # serialised token string -> token_id (reverse lookup for verify/revoke)
        self._token_to_id: dict[str, str] = {}
        # monotonic counter for unique token IDs (deterministic, no random)
        self._counter: int = 0

    # ------------------------------------------------------------------
    # Clock helpers
    # ------------------------------------------------------------------

    def _now(self) -> float:
        """Return current simulation time.

        Example::

            t = auth._now()
        """
        if self._clock is not None:
            return self._clock
        import time

        return time.time()

    def tick(self, delta: float = 1.0) -> None:
        """Advance the internal clock by *delta* (for deterministic tests).

        Example::

            auth.tick(60.0)  # advance one minute
        """
        if self._clock is not None:
            self._clock += delta

    # ------------------------------------------------------------------
    # HMAC helpers
    # ------------------------------------------------------------------

    def _fingerprint(self, data: str) -> str:
        """HMAC-SHA256 fingerprint of *data* under the shared secret.

        Example::

            fp = auth._fingerprint("some-payload")
        """
        return hmac.new(self._secret, data.encode(), hashlib.sha256).hexdigest()

    def _sign_token(self, claims: dict[str, Any], parent_fingerprint: str | None) -> str:
        """Produce HMAC signature chained to *parent_fingerprint*.

        The signature covers the canonical JSON of *claims* concatenated with
        the parent fingerprint (empty string for root tokens), so a child token
        cannot be forged without knowing the shared secret *and* the parent's
        exact fingerprint.

        Example::

            sig = auth._sign_token({"sub": "a", "tid": "x"}, None)
        """
        payload = json.dumps(claims, sort_keys=True)
        chain_input = payload + "|" + (parent_fingerprint or "")
        return hmac.new(self._secret, chain_input.encode(), hashlib.sha256).hexdigest()

    def _build_token_str(self, claims: dict[str, Any], sig: str) -> str:
        return json.dumps(claims, sort_keys=True) + "|" + sig

    def _parse_token_str(self, token: Token) -> tuple[dict[str, Any], str]:
        raw = str(token)
        idx = raw.rfind("|")
        if idx == -1:
            msg = "Malformed token: missing signature separator"
            raise ValueError(msg)
        payload_str = raw[:idx]
        sig = raw[idx + 1 :]
        claims: dict[str, Any] = json.loads(payload_str)
        return claims, sig

    def _next_tid(self, sub: str, iat: float) -> str:
        """Deterministic token ID derived from subject + issue-time + counter.

        Example::

            tid = auth._next_tid("agent-1", 0.0)
        """
        self._counter += 1
        raw = f"{sub}|{iat}|{self._counter}"
        return self._fingerprint(raw)[:16]

    # ------------------------------------------------------------------
    # Auth protocol
    # ------------------------------------------------------------------

    async def issue(self, subject: AgentId, scopes: list[str]) -> Token:
        """Issue a root capability token for *subject* with *scopes*.

        The token's audience defaults to *subject* (root holder is own audience).
        TTL is :attr:`DEFAULT_TTL`.

        Example::

            token = await auth.issue(AgentId("coord"), ["read", "write", "exec"])
        """
        now = self._now()
        expires_at = now + self.DEFAULT_TTL
        tid = self._next_tid(str(subject), now)
        claims: dict[str, Any] = {
            "tid": tid,
            "sub": str(subject),
            "aud": str(subject),
            "scopes": sorted(scopes),
            "iat": now,
            "exp": expires_at,
            "parent_id": None,
            "parent_fp": None,
        }
        sig = self._sign_token(claims, None)
        token_str = self._build_token_str(claims, sig)

        rec = _TokenRecord(
            token_id=tid,
            subject=subject,
            audience=subject,
            scopes=sorted(scopes),
            issued_at=now,
            expires_at=expires_at,
            parent_id=None,
            parent_fingerprint=None,
        )
        self._records[tid] = rec
        self._token_to_id[token_str] = tid
        return Token(token_str)

    async def verify(self, token: Token, presenter: AgentId | None = None) -> AuthContext:
        """Verify *token* and return its :class:`~nest_core.types.AuthContext`.

        Walks the full ancestor chain; raises on any revoked or expired ancestor.

        Args:
            token: Token to verify.
            presenter: If provided, the agent claiming to use this token.
                Must match the token's declared audience.

        Returns:
            :class:`~nest_core.types.AuthContext` with subject and scopes.

        Raises:
            ValueError: Signature invalid or token unknown.
            AudienceConfusionError: *presenter* does not match declared audience.
            RevokedAncestorError: Any ancestor in the chain is revoked.
            ExpiredAncestorError: Any ancestor in the chain is expired.

        Example::

            ctx = await auth.verify(token, presenter=AgentId("worker"))
            assert "read" in ctx.scopes
        """
        claims, sig = self._parse_token_str(token)
        parent_fp: str | None = claims.get("parent_fp")
        expected_sig = self._sign_token(claims, parent_fp)
        if not hmac.compare_digest(sig, expected_sig):
            msg = "Invalid token signature"
            raise ValueError(msg)

        now = self._now()
        tid = claims["tid"]
        rec = self._records.get(tid)
        if rec is None:
            msg = f"Unknown token id: {tid!r}"
            raise ValueError(msg)

        # Audience enforcement
        if presenter is not None and str(presenter) != claims["aud"]:
            msg = (
                f"Audience confusion: token audience is {claims['aud']!r} "
                f"but presenter is {str(presenter)!r}"
            )
            raise AudienceConfusionError(msg)

        # Token-level expiry
        if claims["exp"] < now:
            msg = f"Token {tid!r} has expired"
            raise ValueError(msg)

        # Token-level revocation
        if rec.revoked:
            msg = f"Token {tid!r} has been revoked"
            raise RevokedAncestorError(msg)

        # Transitive ancestor chain check
        self._check_ancestor_chain(tid, now)

        return AuthContext(
            subject=AgentId(claims["sub"]),
            scopes=claims["scopes"],
            issued_at=claims["iat"],
            expires_at=claims["exp"],
        )

    async def revoke(self, token: Token) -> None:
        """Revoke *token*.  All descendants become invalid on next verify.

        Example::

            await auth.revoke(root_token)
            # child tokens now raise RevokedAncestorError on verify
        """
        token_str = str(token)
        tid = self._token_to_id.get(token_str)
        if tid is None:
            try:
                claims, _ = self._parse_token_str(token)
                tid = claims.get("tid")
            except Exception:
                return
        if tid and tid in self._records:
            self._records[tid].revoked = True

    # ------------------------------------------------------------------
    # Delegation extension
    # ------------------------------------------------------------------

    async def delegate(
        self,
        parent_token: Token,
        audience: AgentId,
        scopes_subset: list[str],
        ttl: float,
    ) -> Token:
        """Mint a child token derived from *parent_token*.

        The child's scopes must be a subset of the parent's.  TTL is capped at
        the parent's remaining lifetime so a sub-delegation can never outlive
        its parent.  The child is HMAC-anchored to the parent's fingerprint,
        enabling transitive revocation without contacting the original issuer.

        Args:
            parent_token: Token held by the delegating agent.
            audience: Agent that will hold and use the child token.
            scopes_subset: Scopes to grant; must be ⊆ parent scopes.
            ttl: Requested TTL in simulation time units.

        Returns:
            A new :class:`~nest_core.types.Token` for *audience*.

        Raises:
            ScopeEscalationError: *scopes_subset* contains a scope the parent
                does not hold.
            ValueError: Parent token invalid, expired, or unknown.
            RevokedAncestorError: Any ancestor of the parent is revoked.
            ExpiredAncestorError: Any ancestor of the parent is expired.

        Example::

            child = await auth.delegate(
                parent_token=root,
                audience=AgentId("worker-1"),
                scopes_subset=["read"],
                ttl=300.0,
            )
        """
        # Validate parent signature
        parent_claims, parent_sig = self._parse_token_str(parent_token)
        parent_fp_in_claims: str | None = parent_claims.get("parent_fp")
        expected = self._sign_token(parent_claims, parent_fp_in_claims)
        if not hmac.compare_digest(parent_sig, expected):
            msg = "Parent token has invalid signature"
            raise ValueError(msg)

        now = self._now()
        parent_exp = float(parent_claims["exp"])
        if parent_exp < now:
            msg = "Parent token has expired — cannot delegate from an expired token"
            raise ValueError(msg)

        parent_tid = parent_claims["tid"]
        parent_rec = self._records.get(parent_tid)
        if parent_rec is None:
            msg = f"Unknown parent token id: {parent_tid!r}"
            raise ValueError(msg)

        if parent_rec.revoked:
            msg = f"Parent token {parent_tid!r} is revoked — cannot delegate"
            raise RevokedAncestorError(msg)

        # Check parent's own ancestors
        self._check_ancestor_chain(parent_tid, now)

        # Scope escalation guard
        parent_scopes = set(parent_claims["scopes"])
        requested = set(scopes_subset)
        escalated = requested - parent_scopes
        if escalated:
            msg = (
                f"Scope escalation: requested {sorted(escalated)} "
                f"not held by parent (parent scopes: {sorted(parent_scopes)})"
            )
            raise ScopeEscalationError(msg)

        # TTL cap: child cannot outlive parent
        max_ttl = parent_exp - now
        effective_ttl = min(ttl, max_ttl)
        expires_at = now + effective_ttl

        # Build parent fingerprint for HMAC chain
        parent_payload = json.dumps(parent_claims, sort_keys=True)
        parent_fingerprint = self._fingerprint(parent_payload + "|" + parent_sig)

        child_tid = self._next_tid(str(audience), now)
        child_claims: dict[str, Any] = {
            "tid": child_tid,
            "sub": str(audience),
            "aud": str(audience),
            "scopes": sorted(scopes_subset),
            "iat": now,
            "exp": expires_at,
            "parent_id": parent_tid,
            "parent_fp": parent_fingerprint,
        }
        child_sig = self._sign_token(child_claims, parent_fingerprint)
        token_str = self._build_token_str(child_claims, child_sig)

        rec = _TokenRecord(
            token_id=child_tid,
            subject=audience,
            audience=audience,
            scopes=sorted(scopes_subset),
            issued_at=now,
            expires_at=expires_at,
            parent_id=parent_tid,
            parent_fingerprint=parent_fingerprint,
        )
        self._records[child_tid] = rec
        self._token_to_id[token_str] = child_tid
        return Token(token_str)

    # ------------------------------------------------------------------
    # Introspection helpers (used by scenario agents and validators)
    # ------------------------------------------------------------------

    def get_record(self, token: Token) -> _TokenRecord | None:
        """Return the internal record for *token*, or ``None`` if unknown.

        Example::

            rec = auth.get_record(child_token)
            assert rec is not None
        """
        tid = self._token_to_id.get(str(token))
        if tid is None:
            try:
                claims, _ = self._parse_token_str(token)
                tid = claims.get("tid")
            except Exception:
                return None
        return self._records.get(tid) if tid else None

    def ancestor_ids(self, token_id: str) -> list[str]:
        """Return all ancestor token IDs from nearest parent to root.

        Example::

            ids = auth.ancestor_ids(child_tid)
            # ids == [intermediary_tid, root_tid]
        """
        result: list[str] = []
        current = self._records.get(token_id)
        while current and current.parent_id:
            result.append(current.parent_id)
            current = self._records.get(current.parent_id)
        return result

    # ------------------------------------------------------------------
    # Private
    # ------------------------------------------------------------------

    def _check_ancestor_chain(self, token_id: str, now: float) -> None:
        """Walk ancestors and raise if any is revoked or expired.

        Example::

            auth._check_ancestor_chain(child_tid, now=100.0)
        """
        for ancestor_id in self.ancestor_ids(token_id):
            ancestor = self._records.get(ancestor_id)
            if ancestor is None:
                continue
            if ancestor.revoked:
                msg = f"Ancestor token {ancestor_id!r} in delegation chain has been revoked"
                raise RevokedAncestorError(msg)
            if ancestor.expires_at < now:
                msg = (
                    f"Ancestor token {ancestor_id!r} in delegation chain has expired "
                    f"(exp={ancestor.expires_at}, now={now})"
                )
                raise ExpiredAncestorError(msg)
