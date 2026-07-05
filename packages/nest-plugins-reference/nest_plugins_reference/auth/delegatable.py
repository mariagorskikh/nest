# SPDX-License-Identifier: Apache-2.0
"""Delegatable capability tokens with cascading revocation (macaroon-style).

The default ``jwt`` plugin can only mint and revoke flat tokens: revocation is
tracked per exact token string and there is no parent-child relationship at
all. This plugin adds the missing capability-delegation shape:

* **Offline attenuation.** A token holder mints a narrower child token for
  another agent *without the issuer's help* — the child's HMAC is chained to
  the parent's HMAC (Birgisson et al., "Macaroons", NDSS 2014), so only the
  verifier's root secret can validate the chain, but anyone holding a valid
  token can extend it.
* **Cascading revocation.** ``revoke(parent)`` records the hash of the
  parent's chain prefix. Every descendant token embeds that prefix, so all of
  them fail ``verify`` with :class:`RevokedAncestorError` from the next call
  on — no per-child bookkeeping.
* **Scope attenuation.** A child's scopes must be a strict subset of its
  parent's, enforced both at mint time and (independently) at verify time —
  the HMAC chain alone cannot stop a malicious holder from *writing* broader
  scopes into a link, so the verifier re-walks the chain.
* **Audience binding.** Each delegation names an audience; ``verify`` rejects
  a token presented by any agent other than the final audience
  (:class:`AudienceMismatchError`).
* **Nested TTLs.** A child's expiry may not exceed its parent's
  (:class:`TtlViolationError` at mint; :class:`ExpiredTokenError` at verify).

Determinism: the plugin never reads wall-clock time. The logical clock is
injected via the constructor or :meth:`DelegatableAuth.set_clock`, exactly
like the rotating-identity reference plugin.

Example::

    auth = DelegatableAuth(secret=b"root-secret")
    root = await auth.issue(AgentId("orchestrator"), ["read", "invoke"])
    child = await auth.delegate(
        root, audience=AgentId("worker-1"), scopes=["read"], ttl=600
    )
    ctx = await auth.verify(child, presenter=AgentId("worker-1"))
    await auth.revoke(root)          # cascades:
    await auth.verify(child)         # raises RevokedAncestorError
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any, cast

from nest_core.types import AgentId, AuthContext, Token

_DEFAULT_TTL = 3600.0


class DelegationError(ValueError):
    """Base class for delegation failures (a ``ValueError`` for jwt parity).

    Example::

        try:
            await auth.verify(token)
        except DelegationError as exc:
            print(f"rejected: {exc}")
    """


class InvalidTokenError(DelegationError):
    """Raised when a token is malformed or its HMAC chain does not verify.

    Example::

        raise InvalidTokenError("chain signature mismatch")
    """


class ScopeEscalationError(DelegationError):
    """Raised when a child link claims scopes its parent does not hold.

    Example::

        raise ScopeEscalationError("child scope 'write' not in parent scopes")
    """


class RevokedAncestorError(DelegationError):
    """Raised when the token itself or any ancestor in its chain is revoked.

    Example::

        raise RevokedAncestorError("ancestor at depth 0 is revoked")
    """


class AudienceMismatchError(DelegationError):
    """Raised when a token is presented by an agent other than its audience.

    Example::

        raise AudienceMismatchError("presented by 'eve', bound to 'worker-1'")
    """


class ExpiredTokenError(DelegationError):
    """Raised when a token (or any ancestor link) has expired.

    Example::

        raise ExpiredTokenError("link 2 expired at t=600.0, now=601.0")
    """


class TtlViolationError(DelegationError):
    """Raised at mint time when a child's TTL would outlive its parent.

    Example::

        raise TtlViolationError("child exp 900.0 > parent exp 600.0")
    """


def _canon(obj: Any) -> str:
    """Canonical JSON encoding used for signing and hashing.

    Example::

        assert _canon({"b": 1, "a": 2}) == '{"a":2,"b":1}'
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _chain_sig(secret: bytes, links: list[dict[str, Any]]) -> str:
    """Recompute the HMAC chain over *links* anchored at *secret*.

    ``sig_0 = HMAC(secret, canon(link_0))``;
    ``sig_i = HMAC(sig_{i-1}, canon(link_i))``.

    Example::

        sig = _chain_sig(b"secret", [{"sub": "a", "scopes": ["read"]}])
    """
    sig = hmac.new(secret, _canon(links[0]).encode(), hashlib.sha256).hexdigest()
    for link in links[1:]:
        sig = hmac.new(sig.encode(), _canon(link).encode(), hashlib.sha256).hexdigest()
    return sig


def _prefix_hash(links: list[dict[str, Any]]) -> str:
    """Content hash of a chain prefix, used as the revocation key.

    Example::

        h = _prefix_hash(chain[:2])   # identifies the depth-1 ancestor
    """
    return hashlib.sha256(_canon(links).encode()).hexdigest()


def _parse(token: Token) -> tuple[list[dict[str, Any]], str]:
    """Split a token into its (chain, signature) parts.

    Example::

        links, sig = _parse(token)
    """
    try:
        data = json.loads(str(token))
        links = data["chain"]
        sig = data["sig"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        msg = "Invalid token format"
        raise InvalidTokenError(msg) from exc
    if not isinstance(links, list) or not links or not isinstance(sig, str):
        msg = "Invalid token format"
        raise InvalidTokenError(msg)
    return cast("list[dict[str, Any]]", links), sig


def attenuate(
    parent_token: Token,
    audience: AgentId,
    scopes: list[str],
    ttl: float,
) -> Token:
    """Mint a narrower child token from *parent_token* — offline, no secret.

    This is the macaroon property: the child's signature is
    ``HMAC(parent_sig, canon(child_link))``, computable by anyone *holding*
    the parent token, while only the verifier's root secret can validate the
    resulting chain. Scope-subset and TTL-nesting are enforced here from the
    parent's *claimed* link (defense in depth: ``verify`` re-checks them
    against the whole chain, so a tampered parent link still fails).

    Example::

        child = attenuate(root, AgentId("worker-1"), ["read"], ttl=600)

    Args:
        parent_token: The token being attenuated.
        audience: Agent the child token is bound to.
        scopes: Child scopes; must be a subset of the parent link's scopes.
        ttl: Child lifetime in logical-clock units from the parent's ``iat``.

    Returns:
        The child token.

    Raises:
        InvalidTokenError: If the parent token is malformed.
        ScopeEscalationError: If *scopes* is not a subset of the parent's.
        TtlViolationError: If the child would outlive the parent.
    """
    links, parent_sig = _parse(parent_token)
    parent_link = links[-1]

    parent_scopes = set(parent_link["scopes"])
    if not set(scopes) <= parent_scopes:
        extra = sorted(set(scopes) - parent_scopes)
        msg = f"child scopes {extra} not held by parent"
        raise ScopeEscalationError(msg)

    child_exp = float(parent_link["iat"]) + float(ttl)
    if child_exp > float(parent_link["exp"]):
        msg = f"child exp {child_exp} > parent exp {parent_link['exp']}"
        raise TtlViolationError(msg)

    child_link = {
        "aud": str(audience),
        "exp": child_exp,
        "iat": float(parent_link["iat"]),
        "scopes": sorted(scopes),
        "sub": parent_link.get("aud") or parent_link["sub"],
    }
    child_sig = hmac.new(
        parent_sig.encode(), _canon(child_link).encode(), hashlib.sha256
    ).hexdigest()
    return Token(_canon({"chain": [*links, child_link], "sig": child_sig}))


class DelegatableAuth:
    """Macaroon-style delegatable capability tokens with cascading revocation.

    Satisfies the ``Auth`` protocol (``issue`` / ``verify`` / ``revoke``) and
    adds ``delegate`` on top. Revocation state lives in the verifier: a set of
    chain-prefix hashes. Revoking any prefix invalidates every token whose
    chain extends it — cascading revocation by construction.

    Example::

        auth = DelegatableAuth(secret=b"root")
        root = await auth.issue(AgentId("coord"), ["read", "write"])
        child = await auth.delegate(root, AgentId("leaf"), ["read"], ttl=60)
        grandchild = attenuate(child, AgentId("leaf-2"), ["read"], ttl=30)
        await auth.revoke(child)
        # grandchild now fails verify with RevokedAncestorError
    """

    def __init__(self, secret: bytes = b"nest-default-secret", clock: float | None = None) -> None:
        self._secret = secret
        self._clock = clock
        self._revoked: set[str] = set()

    def set_clock(self, now: float) -> None:
        """Advance the plugin's logical clock (scenario agents call this).

        Example::

            auth.set_clock(ctx.time)
        """
        self._clock = now

    def _now(self) -> float:
        if self._clock is not None:
            return self._clock
        return 0.0

    async def issue(self, subject: AgentId, scopes: list[str]) -> Token:
        """Issue a root capability token for *subject* with *scopes*.

        Example::

            root = await auth.issue(AgentId("coord"), ["read", "invoke"])
        """
        now = self._now()
        root_link = {
            "aud": None,
            "exp": now + _DEFAULT_TTL,
            "iat": now,
            "scopes": sorted(scopes),
            "sub": str(subject),
        }
        sig = hmac.new(self._secret, _canon(root_link).encode(), hashlib.sha256).hexdigest()
        return Token(_canon({"chain": [root_link], "sig": sig}))

    async def delegate(
        self,
        parent_token: Token,
        audience: AgentId,
        scopes: list[str],
        ttl: float,
    ) -> Token:
        """Verify the parent, then mint a narrower child token for *audience*.

        Unlike :func:`attenuate`, this checks the parent's revocation state
        first, so a revoked or expired parent cannot mint children through
        the verifier's own API. (An offline holder can still call
        :func:`attenuate` — and the resulting child will fail ``verify``,
        which is the property that matters.)

        Example::

            child = await auth.delegate(root, AgentId("worker"), ["read"], 600)

        Raises:
            RevokedAncestorError: If the parent chain is already revoked.
            ScopeEscalationError: If *scopes* exceed the parent's.
            TtlViolationError: If the child would outlive the parent.
        """
        await self.verify(parent_token)
        return attenuate(parent_token, audience, scopes, ttl)

    async def verify(self, token: Token, presenter: AgentId | None = None) -> AuthContext:
        """Verify a token: chain HMAC, subsets, TTLs, revocation, audience.

        The checks run in this order, each with a typed error:

        1. structure and HMAC chain (:class:`InvalidTokenError`),
        2. per-link scope subset — re-checked independently of the HMAC
           (:class:`ScopeEscalationError`),
        3. per-link nested expiry against the logical clock
           (:class:`ExpiredTokenError`),
        4. transitive revocation over every chain prefix
           (:class:`RevokedAncestorError`),
        5. audience binding when *presenter* is given
           (:class:`AudienceMismatchError`).

        Example::

            ctx = await auth.verify(child, presenter=AgentId("worker-1"))
            assert "read" in ctx.scopes
        """
        links, sig = _parse(token)

        expected = _chain_sig(self._secret, links)
        if not hmac.compare_digest(sig, expected):
            msg = "chain signature mismatch"
            raise InvalidTokenError(msg)

        now = self._now()
        for i, link in enumerate(links):
            if i > 0:
                parent = links[i - 1]
                if not set(link["scopes"]) <= set(parent["scopes"]):
                    msg = f"link {i} escalates scopes beyond its parent"
                    raise ScopeEscalationError(msg)
                if float(link["exp"]) > float(parent["exp"]):
                    msg = f"link {i} outlives its parent"
                    raise TtlViolationError(msg)
                if link["sub"] != (parent.get("aud") or parent["sub"]):
                    msg = f"link {i} delegator is not the parent's audience"
                    raise InvalidTokenError(msg)
            if float(link["exp"]) < now:
                msg = f"link {i} expired at {link['exp']}, now={now}"
                raise ExpiredTokenError(msg)

        for i in range(len(links)):
            if _prefix_hash(links[: i + 1]) in self._revoked:
                msg = f"ancestor at depth {i} is revoked"
                raise RevokedAncestorError(msg)

        leaf = links[-1]
        holder = leaf.get("aud") or leaf["sub"]
        if presenter is not None and str(presenter) != holder:
            msg = f"presented by {presenter!r}, bound to {holder!r}"
            raise AudienceMismatchError(msg)

        return AuthContext(
            subject=AgentId(holder),
            scopes=list(leaf["scopes"]),
            issued_at=float(leaf["iat"]),
            expires_at=float(leaf["exp"]),
        )

    async def revoke(self, token: Token) -> None:
        """Revoke a token and, transitively, every descendant minted from it.

        Records the hash of the token's full chain prefix; any token whose
        chain extends that prefix fails verification from the next call on.

        Example::

            await auth.revoke(intermediary_token)
            # every leaf delegated from intermediary_token is now invalid
        """
        links, _sig = _parse(token)
        self._revoked.add(_prefix_hash(links))
