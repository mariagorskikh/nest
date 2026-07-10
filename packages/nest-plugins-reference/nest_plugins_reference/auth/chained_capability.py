# SPDX-License-Identifier: Apache-2.0
"""Delegatable capability tokens with cascading revocation.

Macaroon-style delegation on top of the ``Auth`` protocol: a token is a
chain of *links* from a root issuance down to the presented leaf. Link
*i*'s signature is an HMAC keyed by link *i-1*'s signature (the root link
is keyed by the plugin's shared secret). Verifying a leaf re-derives every
signature back to the root, so a forged or reordered ancestor is caught,
and revoking any ancestor's ``jti`` invalidates every token chained
beneath it by construction -- there is no separate revocation list to
maintain per descendant.

Presenting a *delegated* (non-root) token through :meth:`verify` without
an ``expected_audience`` is itself a rejection, not a silently-skipped
optional check -- the wrong-agent-presents-the-token attack has no code
path that lets a caller forget to ask for it.

Example::

    auth = ChainedCapabilityAuth(secret=b"town-secret")
    root = await auth.issue(AgentId("coordinator"), ["read", "write"])
    child = await auth.delegate(root, AgentId("intern"), ["read"], ttl=600)
    ctx = await auth.verify(child, expected_audience=AgentId("intern"))
    await auth.revoke(root)
    await auth.verify(child, expected_audience=AgentId("intern"))  # raises RevokedAncestorError
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any, cast

from nest_core.types import AgentId, AuthContext, Token


class TokenError(ValueError):
    """Base class for all chained-capability token failures.

    Example::

        try:
            await auth.verify(token, expected_audience=AgentId("intern"))
        except TokenError as e:
            print(e)
    """


class InvalidTokenError(TokenError):
    """Token is malformed, or a signature in its chain does not verify.

    Example::

        await auth.verify(Token("not-json"))  # raises InvalidTokenError
    """


class RevokedAncestorError(TokenError):
    """An ancestor in the token's delegation chain has been revoked.

    Example::

        await auth.revoke(root)
        await auth.verify(child, expected_audience=AgentId("intern"))  # raises RevokedAncestorError
    """


class ExpiredAncestorError(TokenError):
    """An ancestor in the token's delegation chain has expired.

    Example::

        auth.set_clock(parent_link_exp + 1)
        await auth.verify(child, expected_audience=AgentId("intern"))  # raises ExpiredAncestorError
    """


class ScopeEscalationError(TokenError):
    """A delegated token requests scopes its parent does not hold.

    Example::

        await auth.delegate(root, AgentId("intern"), ["admin"], ttl=60)
        # raises ScopeEscalationError if "admin" not in root's scopes
    """


class TtlExceededError(TokenError):
    """A delegated token's expiry would outlive its parent's.

    Example::

        await auth.delegate(root, AgentId("intern"), ["read"], ttl=10**9)
        # raises TtlExceededError
    """


class AudienceMismatchError(TokenError):
    """Token was presented by an agent other than its declared audience,
    or a delegated token was presented with no audience check requested
    at all.

    Example::

        await auth.verify(child, expected_audience=AgentId("someone-else"))
        # raises AudienceMismatchError

        await auth.verify(child)  # delegated token, no expected_audience
        # ALSO raises AudienceMismatchError -- the check cannot be skipped
    """


@dataclass(frozen=True)
class _Link:
    """One issuance in a delegation chain (root or a delegated child)."""

    jti: str
    sub: str
    aud: str
    scopes: tuple[str, ...]
    parent_jti: str | None
    iat: float
    exp: float

    def canonical(self) -> str:
        return json.dumps(
            {
                "jti": self.jti,
                "sub": self.sub,
                "aud": self.aud,
                "scopes": list(self.scopes),
                "parent_jti": self.parent_jti,
                "iat": self.iat,
                "exp": self.exp,
            },
            sort_keys=True,
        )


_ROOT_TTL = 3600.0


class ChainedCapabilityAuth:
    """Auth plugin supporting capability delegation and cascading revocation.

    Example::

        auth = ChainedCapabilityAuth(secret=b"town-secret")
        root = await auth.issue(AgentId("coordinator"), ["read", "write"])
        ctx = await auth.verify(root)
    """

    def __init__(self, secret: bytes = b"nest-default-secret", clock: float | None = None) -> None:
        self._secret = secret
        self._clock = 0.0 if clock is None else clock
        self._revoked: set[str] = set()
        self._jti_counter = 0

    def _next_jti(self) -> str:
        """Deterministic, monotonically increasing token id.

        Tier 1 requires byte-identical traces for a given seed; a random
        UUID would break that, so identity comes from call order on this
        instance instead.
        """
        jti = f"jti-{self._jti_counter}"
        self._jti_counter += 1
        return jti

    def set_clock(self, tick: float) -> None:
        """Advance the plugin's logical clock (monotonic, never rewinds).

        The simulator has no wall clock; agents call this with ``ctx.time``
        before issuing/delegating/verifying so expiry math stays
        deterministic across seeds. The clock starts at ``0.0`` and never
        reads real wall-clock time under any code path, so a forgotten
        ``set_clock`` call fails loud (wrong tick) instead of silently
        falling back to non-deterministic real time.

        Example::

            auth.set_clock(ctx.time)
        """
        if tick > self._clock:
            self._clock = tick

    def _now(self) -> float:
        return self._clock

    def _sign(self, key: bytes, payload: str) -> str:
        return hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()

    def _encode(self, chain: list[tuple[_Link, str]]) -> Token:
        return Token(
            json.dumps(
                [
                    {
                        "jti": link.jti,
                        "sub": link.sub,
                        "aud": link.aud,
                        "scopes": list(link.scopes),
                        "parent_jti": link.parent_jti,
                        "iat": link.iat,
                        "exp": link.exp,
                        "sig": sig,
                    }
                    for link, sig in chain
                ],
                sort_keys=True,
            )
        )

    def _decode(self, token: Token) -> list[tuple[_Link, str]]:
        try:
            raw: Any = json.loads(str(token))
        except (json.JSONDecodeError, TypeError) as exc:
            msg = "Malformed token: not valid JSON"
            raise InvalidTokenError(msg) from exc
        if not isinstance(raw, list) or not raw:
            msg = "Malformed token: expected a non-empty chain"
            raise InvalidTokenError(msg)
        items = cast("list[dict[str, Any]]", raw)
        chain: list[tuple[_Link, str]] = []
        for item in items:
            try:
                link = _Link(
                    jti=str(item["jti"]),
                    sub=str(item["sub"]),
                    aud=str(item["aud"]),
                    scopes=tuple(item["scopes"]),
                    parent_jti=item["parent_jti"],
                    iat=float(item["iat"]),
                    exp=float(item["exp"]),
                )
                sig = str(item["sig"])
            except (KeyError, TypeError) as exc:
                msg = "Malformed token: missing or malformed link fields"
                raise InvalidTokenError(msg) from exc
            chain.append((link, sig))
        return chain

    def _verify_chain(self, token: Token) -> list[tuple[_Link, str]]:
        """Recompute every signature root-to-leaf and enforce chain invariants."""
        chain = self._decode(token)
        key = self._secret
        prev: _Link | None = None
        now = self._now()
        for link, sig in chain:
            expected = self._sign(key, link.canonical())
            if not hmac.compare_digest(sig, expected):
                msg = f"Invalid signature at jti={link.jti}"
                raise InvalidTokenError(msg)
            if prev is not None:
                if link.parent_jti != prev.jti:
                    msg = f"Broken chain: jti={link.jti} does not point at {prev.jti}"
                    raise InvalidTokenError(msg)
                if not set(link.scopes) <= set(prev.scopes):
                    msg = f"jti={link.jti} escalates scopes beyond parent {prev.jti}"
                    raise ScopeEscalationError(msg)
                if link.exp > prev.exp:
                    msg = f"jti={link.jti} ttl exceeds parent {prev.jti}'s expiry"
                    raise TtlExceededError(msg)
            if link.jti in self._revoked:
                msg = f"Ancestor jti={link.jti} has been revoked"
                raise RevokedAncestorError(msg)
            if link.exp < now:
                msg = f"Ancestor jti={link.jti} has expired"
                raise ExpiredAncestorError(msg)
            key = sig.encode()
            prev = link
        return chain

    async def issue(self, subject: AgentId, scopes: list[str]) -> Token:
        """Issue a root token for a subject with given scopes.

        Example::

            token = await auth.issue(AgentId("coordinator"), ["read", "write"])
        """
        now = self._now()
        link = _Link(
            jti=self._next_jti(),
            sub=str(subject),
            aud=str(subject),
            scopes=tuple(scopes),
            parent_jti=None,
            iat=now,
            exp=now + _ROOT_TTL,
        )
        sig = self._sign(self._secret, link.canonical())
        return self._encode([(link, sig)])

    async def delegate(
        self,
        parent_token: Token,
        audience: AgentId,
        scopes_subset: list[str],
        ttl: float,
    ) -> Token:
        """Mint a child token scoped to a subset of the parent's capabilities.

        The parent is fully re-verified (signature chain, revocation,
        expiry) before delegation. ``scopes_subset`` must be a subset of
        the parent's scopes and the child's expiry must not outlive the
        parent's -- both are enforced here *and* re-checked at every
        future ``verify``, so a hand-crafted token cannot bypass either
        bound.

        Example::

            child = await auth.delegate(root, AgentId("intern"), ["read"], ttl=600)
        """
        chain = self._verify_chain(parent_token)
        parent_link, parent_sig = chain[-1]
        if not set(scopes_subset) <= set(parent_link.scopes):
            msg = (
                f"Requested scopes {scopes_subset} exceed parent scopes {list(parent_link.scopes)}"
            )
            raise ScopeEscalationError(msg)
        now = self._now()
        exp = now + ttl
        if exp > parent_link.exp:
            msg = f"Requested ttl={ttl} expires at {exp}, after parent expiry {parent_link.exp}"
            raise TtlExceededError(msg)
        child = _Link(
            jti=self._next_jti(),
            sub=str(audience),
            aud=str(audience),
            scopes=tuple(scopes_subset),
            parent_jti=parent_link.jti,
            iat=now,
            exp=exp,
        )
        sig = self._sign(parent_sig.encode(), child.canonical())
        return self._encode([*chain, (child, sig)])

    async def verify(self, token: Token, expected_audience: AgentId | None = None) -> AuthContext:
        """Verify a token's full delegation chain and return its context.

        For a **root** token, ``expected_audience`` is checked if given
        but optional -- a root token's own issuer presenting it is the
        common case and there is no delegation hop to confuse.

        For a **delegated** token (any link with a parent), omitting
        ``expected_audience`` is itself a rejection rather than a
        silently-skipped check: this is what catches a token delegated to
        one agent being handed off and presented by another (the same
        bearer-token confusion a real relying party guards against by
        always checking a JWT's ``aud`` claim against itself -- except
        here it cannot be forgotten).

        Example::

            ctx = await auth.verify(child, expected_audience=AgentId("intern"))
        """
        chain = self._verify_chain(token)
        leaf, _ = chain[-1]
        is_delegated = leaf.parent_jti is not None
        if expected_audience is None:
            if is_delegated:
                msg = (
                    f"jti={leaf.jti} is a delegated token; expected_audience is required "
                    "to verify who is presenting it"
                )
                raise AudienceMismatchError(msg)
        elif leaf.aud != str(expected_audience):
            msg = (
                f"Token audience {leaf.aud!r} does not match presenting agent {expected_audience!r}"
            )
            raise AudienceMismatchError(msg)
        return AuthContext(
            subject=AgentId(leaf.sub),
            scopes=list(leaf.scopes),
            issued_at=leaf.iat,
            expires_at=leaf.exp,
        )

    async def revoke(self, token: Token) -> None:
        """Revoke a token. Cascades: every token delegated beneath it stops
        verifying, since each descendant's chain re-checks this ``jti``.

        Example::

            await auth.revoke(root)
        """
        chain = self._decode(token)
        leaf, _ = chain[-1]
        self._revoked.add(leaf.jti)
