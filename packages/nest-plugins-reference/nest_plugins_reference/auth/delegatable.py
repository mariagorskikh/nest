# SPDX-License-Identifier: Apache-2.0
"""Delegatable capability tokens — macaroon-style HMAC chains with cascading revocation.

The default :class:`~nest_plugins_reference.auth.jwt_auth.JwtAuth` plugin issues
flat HMAC tokens and revokes by exact token string. It cannot model the most
common multi-agent authorization pattern: an orchestrator hands out
narrowly-scoped, time-bounded sub-capabilities to workers *without going back to
the issuer*, and withdrawing the orchestrator's own token silently withdraws
every sub-capability underneath it.

This plugin implements that pattern with the macaroon construction
(Birgisson et al., 2014). A token is not a flat blob: it carries its **entire
delegation chain** (root → leaf) plus a single running HMAC signature where each
link is keyed on its parent's signature::

    s0  = HMAC(secret, link0)
    s1  = HMAC(s0,     link1)      # the previous signature is the next key
    ...
    sig = s_n

Two properties fall out of that construction, and they are the whole point:

* **Tamper-evidence.** Changing any byte of any link (a widened scope, a
  stretched expiry, a swapped audience) breaks the recomputed ``sig``.
* **Cascading revocation by construction.** Every descendant token embeds its
  ancestors' links, so :meth:`DelegatableAuth.verify` can walk the whole
  ancestry offline. Revoking a parent link's id invalidates every descendant at
  the next verify — no per-child revocation list.

Delegation only ever **attenuates**: a child's scopes must be a subset of its
parent's, its expiry must be no later than its parent's, and any first-party
caveats are additive constraints. Issuing a child that broadens either raises a
typed :class:`DelegationError`.

Determinism: like ``JwtAuth`` the plugin takes a fixed ``clock`` so simulated
traces are byte-identical across replays; there is no wall-clock or unseeded
randomness on any code path.

Example::

    auth = DelegatableAuth(secret=b"secret", clock=0.0)
    root = await auth.issue(AgentId("coordinator"), ["read", "write", "exec"])
    sub = await auth.delegate(root, AgentId("worker-1"), ["read"], ttl=600)
    ctx = await auth.verify(sub, presenter=AgentId("worker-1"))
    assert ctx.scopes == ["read"]
    await auth.revoke(root)              # cascades: sub now fails to verify
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any, TypedDict, cast

from nest_core.types import AgentId, AuthContext, Token

_DEFAULT_TTL = 3600.0


class DelegationError(ValueError):
    """Base class for every delegation/authorization failure.

    Catching :class:`DelegationError` catches all of the specific subclasses
    below in one ``except``.

    Example::

        try:
            await auth.delegate(parent, AgentId("b"), ["admin"], ttl=60)
        except DelegationError as exc:
            print(exc)
    """


class InvalidTokenError(DelegationError):
    """The token is malformed or its chain signature does not verify.

    Example::

        raise InvalidTokenError("chain signature mismatch")
    """


class ScopeEscalationError(DelegationError):
    """A child requested a scope its parent does not hold.

    Example::

        raise ScopeEscalationError("child scope 'admin' not in parent scopes")
    """


class TtlExpansionError(DelegationError):
    """A child's expiry would outlive its parent's expiry.

    Example::

        raise TtlExpansionError("child exp 200 > parent exp 100")
    """


class ExpiredTokenError(DelegationError):
    """A link in the chain (leaf or ancestor) has passed its expiry.

    Example::

        raise ExpiredTokenError("link for 'worker-1' expired at 50.0")
    """


class RevokedAncestorError(DelegationError):
    """A link in the chain has been revoked, so the whole token is invalid.

    Raised for both a directly-revoked leaf and any revoked ancestor — the
    cascading-revocation guarantee.

    Example::

        raise RevokedAncestorError("ancestor link 'coordinator' revoked")
    """


class AudienceMismatchError(DelegationError):
    """The presenter is not the audience the leaf token was minted for.

    Blocks a confused-deputy replay where agent C presents a token issued to
    agent B.

    Example::

        raise AudienceMismatchError("presented by 'c' but audience is 'b'")
    """


class CaveatUnsatisfiedError(DelegationError):
    """A first-party caveat attached to a link is not satisfied at verify time.

    Example::

        raise CaveatUnsatisfiedError("caveat 'resource=jobs' not satisfied")
    """


class _Link(TypedDict):
    """One rung of a delegation chain (serialized inside the token).

    ``sub`` delegated to ``aud`` the given ``scopes`` from ``iat`` until ``exp``,
    subject to ``caveats``. The link ``id`` is derived (not stored) so it cannot
    be forged independently of the link's content.
    """

    sub: str
    aud: str
    scopes: list[str]
    iat: float
    exp: float
    caveats: list[str]


def _canonical(link: _Link) -> bytes:
    """Serialize a link to canonical bytes for hashing/signing.

    Sorted keys + tight separators make the encoding reproducible, so link ids
    and chain signatures are byte-stable across runs.
    """
    return json.dumps(link, sort_keys=True, separators=(",", ":")).encode()


def _link_id(link: _Link) -> str:
    """Return the stable, content-derived id of a link.

    The id is a hash of the link's canonical bytes, so it is impossible to keep
    a link's id while altering its content. Revocation targets this id.

    Example::

        rid = _link_id(link)
    """
    return hashlib.sha256(_canonical(link)).hexdigest()[:16]


class DelegatableAuth:
    """Macaroon-style delegatable auth with attenuation and cascading revocation.

    Satisfies the :class:`~nest_core.layers.auth.Auth` protocol
    (``issue`` / ``verify`` / ``revoke``) and adds :meth:`delegate`. ``verify``
    keeps the base signature but accepts two optional keyword arguments
    (``presenter`` and ``context``), so it remains protocol-compatible.

    All instances that must recognise the same tokens and revocations should
    share one ``secret`` and one ``revoked`` set — pass the same instance to
    every agent (see the ``delegated_auth`` scenario factory).

    Example::

        auth = DelegatableAuth(secret=b"secret", clock=0.0)
        root = await auth.issue(AgentId("a"), ["read", "write"])
        child = await auth.delegate(root, AgentId("b"), ["read"], ttl=60)
    """

    def __init__(
        self,
        secret: bytes = b"nest-delegatable-secret",
        clock: float | None = None,
        default_ttl: float = _DEFAULT_TTL,
        revoked: set[str] | None = None,
    ) -> None:
        self._secret = secret
        self._clock = clock
        self._default_ttl = default_ttl
        self._revoked: set[str] = revoked if revoked is not None else set()

    def _now(self) -> float:
        if self._clock is not None:
            return self._clock
        return time.time()

    def _chain_sig(self, links: list[_Link]) -> str:
        """Compute the running macaroon signature over a chain of links.

        Each link is HMAC'd with the *previous* link's signature as the key,
        anchoring the whole chain to ``self._secret``.
        """
        running = self._secret
        for link in links:
            running = hmac.new(running, _canonical(link), hashlib.sha256).digest()
        return running.hex()

    def _encode(self, links: list[_Link]) -> Token:
        """Serialize a signed chain into an opaque token string."""
        envelope = {"links": links, "sig": self._chain_sig(links)}
        return Token(json.dumps(envelope, sort_keys=True))

    def _decode(self, token: Token) -> tuple[list[_Link], str]:
        """Parse a token into its links and signature (no verification yet).

        Raises :class:`InvalidTokenError` if the envelope is not well-formed.
        """
        try:
            data: Any = json.loads(str(token))
            links_raw = data["links"]
            sig = data["sig"]
        except (ValueError, KeyError, TypeError) as exc:
            msg = f"malformed delegatable token: {exc}"
            raise InvalidTokenError(msg) from exc
        if not isinstance(links_raw, list) or not links_raw or not isinstance(sig, str):
            msg = "token carries no delegation links"
            raise InvalidTokenError(msg)
        return cast("list[_Link]", links_raw), sig

    async def issue(self, subject: AgentId, scopes: list[str]) -> Token:
        """Issue a root capability token held by ``subject`` itself.

        The root link's audience equals its subject: the issuer is the first
        holder and may delegate onward from here.

        Example::

            root = await auth.issue(AgentId("coordinator"), ["read", "write"])
        """
        now = self._now()
        link: _Link = {
            "sub": str(subject),
            "aud": str(subject),
            "scopes": list(scopes),
            "iat": now,
            "exp": now + self._default_ttl,
            "caveats": [],
        }
        return self._encode([link])

    async def delegate(
        self,
        parent_token: Token,
        audience: AgentId,
        scopes_subset: list[str],
        ttl: float,
        caveats: list[str] | None = None,
    ) -> Token:
        """Mint a narrowed child token for ``audience`` — no issuer involved.

        The child is appended to the parent's chain by the current holder. It
        must **attenuate**:

        * ``scopes_subset`` must be a subset of the parent leaf's scopes, else
          :class:`ScopeEscalationError`.
        * ``now + ttl`` must not exceed the parent leaf's expiry, else
          :class:`TtlExpansionError`.
        * ``caveats`` are additive first-party constraints re-checked at verify.

        The parent is verified first, so you cannot delegate from an expired or
        revoked token.

        Example::

            child = await auth.delegate(root, AgentId("worker-1"), ["read"], ttl=600)
        """
        await self.verify(parent_token)
        links, _ = self._decode(parent_token)
        parent_leaf = links[-1]
        parent_scopes = set(parent_leaf["scopes"])
        requested = list(scopes_subset)
        extra = set(requested) - parent_scopes
        if extra:
            msg = f"child scopes {sorted(extra)} not held by parent {sorted(parent_scopes)}"
            raise ScopeEscalationError(msg)
        now = self._now()
        child_exp = now + ttl
        if child_exp > parent_leaf["exp"]:
            msg = f"child exp {child_exp} exceeds parent exp {parent_leaf['exp']}"
            raise TtlExpansionError(msg)
        child: _Link = {
            "sub": parent_leaf["aud"],
            "aud": str(audience),
            "scopes": requested,
            "iat": now,
            "exp": child_exp,
            "caveats": list(caveats or []),
        }
        return self._encode([*links, child])

    def _check_caveat(self, caveat: str, chain_depth: int, context: dict[str, str]) -> bool:
        """Return whether a single first-party caveat holds.

        Supported vocabulary (deterministic, self-contained):

        * ``max_depth=<int>`` — satisfied iff the total chain length is within
          the bound (an intrinsic check needing no external context).
        * ``<key>=<value>`` — satisfied iff ``context[key] == value``. A missing
          key fails closed.
        """
        key, sep, value = caveat.partition("=")
        if not sep:
            return False
        if key == "max_depth":
            try:
                return chain_depth <= int(value)
            except ValueError:
                return False
        return context.get(key) == value

    async def verify(
        self,
        token: Token,
        presenter: AgentId | None = None,
        context: dict[str, str] | None = None,
    ) -> AuthContext:
        """Verify a token end-to-end and return the leaf holder's auth context.

        Checks, in order: the chain signature; then for every link (root → leaf)
        revocation, expiry, scope monotonicity, expiry monotonicity, and
        caveats; then — if ``presenter`` is given — that it matches the leaf
        audience. Any failure raises the matching :class:`DelegationError`.

        Because ancestors are embedded in the token, a revoked *parent* fails a
        *child*'s verify: that is the cascading-revocation guarantee.

        Example::

            ctx = await auth.verify(child, presenter=AgentId("worker-1"))
        """
        links, sig = self._decode(token)
        if not hmac.compare_digest(sig, self._chain_sig(links)):
            msg = "chain signature mismatch — token tampered or wrong secret"
            raise InvalidTokenError(msg)

        now = self._now()
        ctx = context or {}
        prev_scopes: set[str] | None = None
        prev_exp: float | None = None
        for link in links:
            lid = _link_id(link)
            if lid in self._revoked:
                msg = f"link {lid} for {link['aud']!r} has been revoked"
                raise RevokedAncestorError(msg)
            if link["exp"] < now:
                msg = f"link for {link['aud']!r} expired at {link['exp']} (now={now})"
                raise ExpiredTokenError(msg)
            scopes = set(link["scopes"])
            if prev_scopes is not None and not scopes <= prev_scopes:
                widened = sorted(scopes - prev_scopes)
                msg = f"link for {link['aud']!r} widened scopes {widened} mid-chain"
                raise ScopeEscalationError(msg)
            if prev_exp is not None and link["exp"] > prev_exp:
                msg = f"link for {link['aud']!r} extended expiry {link['exp']} > {prev_exp}"
                raise TtlExpansionError(msg)
            for caveat in link["caveats"]:
                if not self._check_caveat(caveat, len(links), ctx):
                    msg = f"caveat {caveat!r} not satisfied"
                    raise CaveatUnsatisfiedError(msg)
            prev_scopes = scopes
            prev_exp = link["exp"]

        leaf = links[-1]
        if presenter is not None and str(presenter) != leaf["aud"]:
            msg = f"presented by {presenter!r} but leaf audience is {leaf['aud']!r}"
            raise AudienceMismatchError(msg)
        return AuthContext(
            subject=AgentId(leaf["aud"]),
            scopes=list(leaf["scopes"]),
            issued_at=leaf["iat"],
            expires_at=leaf["exp"],
        )

    async def revoke(self, token: Token) -> None:
        """Revoke a token by adding its leaf link id to the shared revoked set.

        Because every descendant embeds this link, revoking a token here
        invalidates the token and everything delegated from it at the next
        verify — one O(1) call collapses an entire subtree.

        Example::

            await auth.revoke(root)   # every child of root now fails verify
        """
        links, _ = self._decode(token)
        self._revoked.add(_link_id(links[-1]))
