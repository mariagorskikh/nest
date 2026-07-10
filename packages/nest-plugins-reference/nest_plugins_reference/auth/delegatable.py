# SPDX-License-Identifier: Apache-2.0
"""Delegatable capability tokens with cascading revocation.

The default :class:`~nest_plugins_reference.auth.jwt_auth.JwtAuth` stores
revocation as a flat set of token strings with no parent-child relationship.
That means revoking a root token does **not** automatically invalidate tokens
the root-holder delegated to sub-agents — each must be revoked individually.
This plugin closes the gap.

Design: HMAC-chained token tree
--------------------------------
Every token is a JSON payload signed with HMAC-SHA256.  A *root* token is
signed directly by the plugin secret; a *delegated* child token carries a
``parent_sig`` field pointing to its parent's signature.  Revoking a token
adds its ``sig`` to the revoked set; :meth:`verify` walks the chain upward
and fails if any ancestor's ``sig`` is in the revoked set.

Three attack classes are thwarted (see adversarial validators):

* **Scope escalation** — ``delegate`` refuses to issue a child whose scopes
  are not a strict subset of the parent's.
* **Stale parent** — ``verify`` checks the full ancestor chain; a revoked or
  expired ancestor renders the child invalid even if the child token itself
  was not explicitly revoked.
* **Audience confusion** — the ``audience`` field is embedded in the signed
  payload; :meth:`verify` checks it against the caller's declared identity
  when the ``caller`` parameter is supplied.

Example::

    auth = DelegatableAuth(secret=b"sim-secret")
    root = await auth.issue(AgentId("coord"), ["read", "write"])
    child = await auth.delegate(root, audience=AgentId("worker"), scopes=["read"], ttl=60)
    ctx = await auth.verify(child, caller=AgentId("worker"))
    assert "read" in ctx.scopes
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any

from nest_core.types import AgentId, AuthContext, Token


class RevokedAncestorError(ValueError):
    """Raised when a token or one of its ancestors has been revoked.

    Carries the ``revoked_sig`` of the first revoked ancestor found so
    callers can log or branch on it without string-matching the message.

    Example::

        try:
            ctx = await auth.verify(child)
        except RevokedAncestorError as exc:
            print(exc.revoked_sig)
    """

    def __init__(self, revoked_sig: str) -> None:
        self.revoked_sig = revoked_sig
        super().__init__(f"token chain contains revoked ancestor (sig={revoked_sig!r})")


class ScopeEscalationError(ValueError):
    """Raised when a delegation requests scopes the parent does not hold.

    Example::

        try:
            child = await auth.delegate(root, audience=AgentId("a"), scopes=["admin"])
        except ScopeEscalationError as exc:
            print(exc.disallowed)
    """

    def __init__(self, disallowed: list[str]) -> None:
        self.disallowed = disallowed
        super().__init__(f"scope escalation: {disallowed} not in parent token")


class AudienceError(ValueError):
    """Raised when a token is presented by an agent other than its audience.

    Example::

        try:
            ctx = await auth.verify(child, caller=AgentId("impersonator"))
        except AudienceError as exc:
            print(exc.expected, exc.got)
    """

    def __init__(self, expected: str, got: str) -> None:
        self.expected = expected
        self.got = got
        super().__init__(f"audience mismatch: token is for {expected!r}, presented by {got!r}")


def _canonical(payload: dict[str, Any]) -> str:
    """Stable JSON serialisation for signing — sort_keys guarantees ordering.

    Example::

        assert _canonical({"b": 1, "a": 2}) == _canonical({"a": 2, "b": 1})
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _b64_encode(data: str) -> str:
    return base64.urlsafe_b64encode(data.encode()).decode().rstrip("=")


def _b64_decode(data: str) -> str:
    padding = "=" * (4 - (len(data) % 4))
    return base64.urlsafe_b64decode(data + padding).decode()


class DelegatableAuth:
    """Auth plugin supporting delegatable capability tokens with cascading revocation.

    A drop-in replacement for :class:`~nest_plugins_reference.auth.jwt_auth.JwtAuth`
    that adds :meth:`delegate` and multi-level ancestry checks in :meth:`verify`.

    Architecture: True Macaroon Cryptographic Chaining
    --------------------------------------------------
    Unlike standard JWTs, this plugin implements a True Macaroon token structure.
    The cryptographic lineage (parent tokens and their attenuating caveats) travels
    inside the token itself, enabling **stateless, offline verification**.

    Token Wire Format:
        `Base64(RootPayload) | Base64(Caveat_1) | ... | Base64(Caveat_N) | Signature`

    Signature Chaining (HMAC-SHA256):
        * ``Sig_0 = HMAC(Secret, RootPayload)``
        * ``Sig_1 = HMAC(Sig_0, Caveat_1)``
        * ``Sig_N = HMAC(Sig_{N-1}, Caveat_N)``

    Because each signature serves as the symmetric key for the next level's HMAC,
    any alteration to an ancestor payload invalidates all subsequent descendants.
    Revocation is performed by adding any ``Sig_i`` to the `_revoked` set, instantly
    poisoning the chain for all downstream tokens without needing to index them.
    """

    def __init__(
        self,
        secret: bytes = b"nest-delegatable-secret",
        clock: float | None = None,
    ) -> None:
        self._secret = secret
        self._clock = clock
        self._revoked: set[str] = set()

    # ------------------------------------------------------------------
    # Auth protocol (issue / verify / revoke)
    # ------------------------------------------------------------------

    def _now(self) -> float:
        if self._clock is not None:
            return self._clock
        return time.time()

    def _sign(self, payload_str: str, key: bytes) -> str:
        """HMAC-SHA256 over the canonical payload string."""
        return hmac.new(key, payload_str.encode(), hashlib.sha256).hexdigest()

    def _verify_chain(self, raw_token: str) -> tuple[list[dict[str, Any]], str, dict[str, Any]]:
        """Walks the macaroon caveat chain dynamically enforcing all boundaries.

        Returns:
            (payloads, final_sig, effective_payload)
        """
        parts = raw_token.split("|")
        if len(parts) < 2:  # noqa: PLR2004
            msg = "invalid token format"
            raise ValueError(msg)

        sig = parts[-1]
        payloads_b64 = parts[:-1]

        payloads: list[dict[str, Any]] = []
        for p in payloads_b64:
            try:
                payloads.append(json.loads(_b64_decode(p)))
            except Exception as e:
                msg = "invalid token payload encoding"
                raise ValueError(msg) from e

        # 1. Root verification
        root_payload = payloads[0]
        current_sig = self._sign(_canonical(root_payload), key=self._secret)
        if current_sig in self._revoked:
            raise RevokedAncestorError(current_sig)

        parent_scopes = set(root_payload.get("scopes", []))
        parent_exp = root_payload.get("exp")

        # 2. Caveat chain verification (enforces offline subsetting)
        for child_payload in payloads[1:]:
            child_scopes = set(child_payload.get("scopes", []))
            disallowed = sorted(child_scopes - parent_scopes)
            if disallowed:
                raise ScopeEscalationError(disallowed)
            parent_scopes = child_scopes

            child_exp = child_payload.get("exp")
            if parent_exp is not None and (child_exp is None or child_exp > parent_exp):
                msg = "child token expiration exceeds parent"
                raise ValueError(msg)
            parent_exp = child_exp

            # Next signature in the chain is keyed by the previous signature
            current_sig = self._sign(_canonical(child_payload), key=current_sig.encode())
            if current_sig in self._revoked:
                raise RevokedAncestorError(current_sig)

        if not hmac.compare_digest(current_sig, sig):
            msg = "invalid token signature"
            raise ValueError(msg)

        # 3. Check final temporal expiry
        now = self._now()
        final_payload = payloads[-1]
        exp = final_payload.get("exp")
        if exp is not None and exp < now:
            msg = "token or ancestor has expired"
            raise ValueError(msg)

        return payloads, current_sig, final_payload

    async def issue(self, subject: AgentId, scopes: list[str]) -> Token:
        now = self._now()
        payload: dict[str, Any] = {
            "sub": str(subject),
            "scopes": sorted(scopes),
            "iat": now,
            "exp": now + 3600,
        }
        payload_str = _canonical(payload)
        sig = self._sign(payload_str, key=self._secret)
        return Token(f"{_b64_encode(payload_str)}|{sig}")

    async def verify(self, token: Token, caller: AgentId | None = None) -> AuthContext:
        _payloads, _sig, final_payload = self._verify_chain(str(token))

        # Audience check
        audience = final_payload.get("audience")
        if caller is not None and audience is not None and str(caller) != audience:
            raise AudienceError(expected=audience, got=str(caller))

        return AuthContext(
            subject=AgentId(final_payload["sub"]),
            scopes=final_payload["scopes"],
            issued_at=final_payload.get("iat"),
            expires_at=final_payload.get("exp"),
        )

    async def revoke(self, token: Token) -> None:
        _payloads, sig, _final_payload = self._verify_chain(str(token))
        self._revoked.add(sig)

    # ------------------------------------------------------------------
    # Delegation extension
    # ------------------------------------------------------------------

    async def delegate(
        self,
        parent: Token,
        audience: AgentId,
        scopes: list[str],
        ttl: float = 300.0,
    ) -> Token:
        # 1. Parse and verify parent token exactly as it is (including chain)
        raw_parent = str(parent)
        parts = raw_parent.rsplit("|", 1)
        if len(parts) != 2:  # noqa: PLR2004
            msg = "invalid token format"
            raise ValueError(msg)
        chain_str, parent_sig = parts

        _payloads, _computed_sig, parent_payload = self._verify_chain(raw_parent)

        # 2. Scope subset enforcement
        parent_scopes = set(parent_payload.get("scopes", []))
        requested = set(scopes)
        disallowed = sorted(requested - parent_scopes)
        if disallowed:
            raise ScopeEscalationError(disallowed)

        # 3. TTL bounding
        now = self._now()
        parent_exp = parent_payload.get("exp")
        effective_exp = now + ttl
        if parent_exp is not None:
            effective_exp = min(effective_exp, parent_exp)

        # 4. Construct child caveat payload
        child_payload: dict[str, Any] = {
            "sub": parent_payload["sub"],  # carry originator subject
            "audience": str(audience),
            "scopes": sorted(scopes),
            "iat": now,
            "exp": effective_exp,
        }

        # 5. Cryptographic chaining: sign the child payload using parent signature as key
        child_str = _canonical(child_payload)
        child_sig = self._sign(child_str, key=parent_sig.encode())

        # 6. Append caveat to token string
        return Token(f"{chain_str}|{_b64_encode(child_str)}|{child_sig}")
