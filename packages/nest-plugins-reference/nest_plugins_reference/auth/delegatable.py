# SPDX-License-Identifier: Apache-2.0
"""Delegatable capability tokens with cascading revocation (macaroon-style).

The default :class:`~nest_plugins_reference.auth.jwt_auth.JwtAuth` can only
*issue* and *revoke by exact string*. It cannot model the most common
multi-agent pattern: an orchestrator holds a long-lived root token, mints a
narrowly-scoped, short-lived sub-token for a worker **without going back to the
issuer**, and later revokes the root so every descendant token dies at once.

``DelegatableAuth`` adds exactly that. It borrows the HMAC chaining from
macaroons (Birgisson et al., 2014): each token carries the full chain of *links*
from root to leaf, and each link's signature is keyed by the previous link's
signature::

    s_0 = HMAC(secret,   link_0)
    s_1 = HMAC(s_0,       link_1)
    ...
    s_n = HMAC(s_{n-1},   link_n)          # the token's outer signature

Two properties fall straight out of this construction:

* **Transitive revocation for free.** ``s_k`` depends only on ``secret`` and
  ``link_0..link_k``, so the intermediate signature at step *k* of a long chain
  is *byte-identical* to the outer signature of the length-*k* ancestor token.
  Revoking an ancestor records its outer signature; verifying any descendant
  recomputes the same value mid-chain and rejects it — no per-child revocation
  list, and siblings/cousins are untouched.
* **Tamper-evidence.** Broadening a child's scopes or extending its expiry after
  the fact breaks the signature chain, so :meth:`verify` re-checks scope
  narrowing and TTL monotonicity as a belt-and-braces guard even though a forged
  chain would already fail the signature check.

The base :class:`~nest_core.layers.auth.Auth` surface (``issue`` / ``verify`` /
``revoke``) is preserved; delegation adds :meth:`delegate` and an *optional*
keyword-only ``presenter`` argument to :meth:`verify` for audience binding.
``verify(token)`` — the base contract — still works unchanged.

Example::

    auth = DelegatableAuth(secret=b"orchestrator-secret")
    root = await auth.issue(AgentId("coordinator"), ["read", "write", "pay"])
    child = await auth.delegate(root, AgentId("worker"), ["read"], ttl=600)
    ctx = await auth.verify(child, presenter=AgentId("worker"))
    assert ctx.scopes == ["read"]
    await auth.revoke(root)              # cascades
    await auth.verify(child)             # raises RevokedAncestorError
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any, cast

from nest_core.types import AgentId, AuthContext, Token

ROOT_TTL = 3600.0
"""Default lifetime (seconds) of a freshly issued root token."""


class DelegationError(ValueError):
    """Base class for delegation/verification failures.

    Subclasses :class:`ValueError` so callers written against the ``jwt``
    plugin's ``ValueError`` contract keep working while gaining typed granularity.

    Example::

        try:
            await auth.verify(tok)
        except DelegationError as exc:
            log.warning("token rejected: %s", exc)
    """


class MalformedTokenError(DelegationError):
    """The token string is not a well-formed delegatable token.

    Example::

        raise MalformedTokenError("token has no signature delimiter")
    """


class InvalidSignatureError(DelegationError):
    """The recomputed chain signature does not match the token's outer signature.

    Example::

        raise InvalidSignatureError("chain signature mismatch")
    """


class RevokedAncestorError(DelegationError):
    """Some link in the chain (this token or an ancestor) has been revoked.

    Example::

        raise RevokedAncestorError("ancestor at depth 1 is revoked")
    """


class ExpiredTokenError(DelegationError):
    """A link in the chain (this token or an ancestor) has expired.

    Example::

        raise ExpiredTokenError("token expired at t=600.0")
    """


class ScopeEscalationError(DelegationError):
    """A child link claims a scope its parent does not hold.

    Raised by :meth:`delegate` when the requested subset is not a subset, and by
    :meth:`verify` if a forged chain widens scopes mid-way.

    Example::

        raise ScopeEscalationError("child requested {'write'} beyond parent")
    """


class AudienceMismatchError(DelegationError):
    """The presenter is not the audience the leaf token was minted for.

    Example::

        raise AudienceMismatchError("token minted for 'bob', presented by 'mallory'")
    """


def _link_bytes(link: dict[str, Any]) -> bytes:
    """Serialize one chain link canonically so signatures are byte-deterministic."""
    return json.dumps(link, sort_keys=True, separators=(",", ":")).encode()


def _chain_sigs(secret: bytes, links: list[dict[str, Any]]) -> list[str]:
    """Return the running HMAC signatures ``s_0..s_n`` for a chain of links.

    ``s_i`` is ``HMAC(key_i, link_i)`` where ``key_0`` is *secret* and each
    subsequent key is the previous signature. The last element is the token's
    outer signature; every earlier element equals the outer signature of the
    corresponding ancestor token, which is what makes revocation transitive.

    Example::

        sigs = _chain_sigs(b"secret", [root_link, child_link])
    """
    sigs: list[str] = []
    key = secret
    for link in links:
        sig = hmac.new(key, _link_bytes(link), hashlib.sha256).hexdigest()
        sigs.append(sig)
        key = sig.encode()
    return sigs


class DelegatableAuth:
    """Macaroon-style auth: delegatable capability tokens, cascading revocation.

    Example::

        auth = DelegatableAuth(secret=b"secret")
        root = await auth.issue(AgentId("a1"), ["read", "write"])
        child = await auth.delegate(root, AgentId("a2"), ["read"], ttl=300)
    """

    def __init__(
        self, secret: bytes = b"nest-delegatable-secret", clock: float | None = None
    ) -> None:
        self._secret = secret
        self._clock = clock
        self._revoked: set[str] = set()

    def _now(self) -> float:
        if self._clock is not None:
            return self._clock
        return time.time()

    def _parse(self, token: Token) -> tuple[list[dict[str, Any]], str]:
        """Split a token into its ``(links, outer_signature)`` without validating."""
        raw = str(token)
        parts = raw.rsplit("|", 1)
        if len(parts) != 2:
            msg = "Token has no signature delimiter"
            raise MalformedTokenError(msg)
        payload_str, sig = parts
        try:
            data: Any = json.loads(payload_str)
        except (ValueError, TypeError) as exc:
            msg = "Token payload is not valid JSON"
            raise MalformedTokenError(msg) from exc
        if not isinstance(data, dict):
            msg = "Token payload has no chain"
            raise MalformedTokenError(msg)
        chain = cast("dict[str, Any]", data).get("chain")
        if not isinstance(chain, list) or not chain:
            msg = "Token chain is empty"
            raise MalformedTokenError(msg)
        return list(cast("list[dict[str, Any]]", chain)), sig

    def _encode(self, links: list[dict[str, Any]]) -> Token:
        """Sign *links* and serialize them into a wire token string."""
        sigs = _chain_sigs(self._secret, links)
        payload = json.dumps({"chain": links}, sort_keys=True)
        return Token(f"{payload}|{sigs[-1]}")

    async def issue(self, subject: AgentId, scopes: list[str]) -> Token:
        """Issue a root token granting *scopes* to *subject*.

        The root's audience is the subject itself, so only the subject can
        present it (once audience binding is checked).

        Example::

            root = await auth.issue(AgentId("coordinator"), ["read", "write"])
        """
        now = self._now()
        link = {
            "sub": str(subject),
            "aud": str(subject),
            "scopes": sorted(set(scopes)),
            "iat": now,
            "exp": now + ROOT_TTL,
        }
        return self._encode([link])

    async def delegate(
        self,
        parent_token: Token,
        audience: AgentId,
        scopes_subset: list[str],
        ttl: float,
    ) -> Token:
        """Mint a child token for *audience* with a strict subset of parent scopes.

        No round trip to the issuer: the holder of *parent_token* signs the child
        with the parent's own signature as the HMAC key. The child's scopes must
        be a subset of the parent's leaf scopes (else
        :class:`ScopeEscalationError`) and its expiry is clamped to ``≤`` the
        parent's (TTL never widens down the chain). The parent is verified first,
        so delegating from a revoked or expired parent fails.

        Example::

            child = await auth.delegate(root, AgentId("worker"), ["read"], ttl=600)
        """
        # Verify the parent (rejects revoked/expired/forged parents up front).
        await self.verify(parent_token)
        parent_links, _ = self._parse(parent_token)
        parent_leaf = parent_links[-1]
        parent_scopes = set(parent_leaf["scopes"])
        requested = set(scopes_subset)
        if not requested.issubset(parent_scopes):
            extra = requested - parent_scopes
            msg = f"child requested {sorted(extra)} beyond parent scopes {sorted(parent_scopes)}"
            raise ScopeEscalationError(msg)
        now = self._now()
        child_exp = min(now + ttl, float(parent_leaf["exp"]))
        child_link = {
            "sub": str(audience),
            "aud": str(audience),
            "scopes": sorted(requested),
            "iat": now,
            "exp": child_exp,
        }
        return self._encode([*parent_links, child_link])

    async def verify(self, token: Token, *, presenter: AgentId | None = None) -> AuthContext:
        """Verify a token end-to-end and return the leaf's :class:`AuthContext`.

        Checks, in order: the outer signature; that no link in the chain is
        revoked (transitive — a revoked ancestor sinks the whole subtree); that
        no link has expired; that scopes narrow monotonically and TTLs never
        widen down the chain (tamper guard); and, when *presenter* is supplied,
        that it matches the leaf's audience.

        Passing *presenter* is optional so the base ``verify(token)`` contract is
        preserved; omit it to skip audience binding (e.g. when the holder
        delegates onward rather than presents).

        Example::

            ctx = await auth.verify(child, presenter=AgentId("worker"))
        """
        links, sig = self._parse(token)
        sigs = _chain_sigs(self._secret, links)
        if not hmac.compare_digest(sigs[-1], sig):
            msg = "chain signature mismatch"
            raise InvalidSignatureError(msg)

        for depth, link_sig in enumerate(sigs):
            if link_sig in self._revoked:
                msg = f"ancestor at depth {depth} is revoked"
                raise RevokedAncestorError(msg)

        now = self._now()
        prev_scopes: set[str] | None = None
        prev_exp: float | None = None
        for depth, link in enumerate(links):
            exp = float(link["exp"])
            if exp < now:
                msg = f"link at depth {depth} expired at t={exp}"
                raise ExpiredTokenError(msg)
            scopes = set(link["scopes"])
            if prev_scopes is not None and not scopes.issubset(prev_scopes):
                widened = scopes - prev_scopes
                msg = f"link at depth {depth} widened scopes by {sorted(widened)}"
                raise ScopeEscalationError(msg)
            if prev_exp is not None and exp > prev_exp:
                msg = f"link at depth {depth} extends TTL beyond its parent"
                raise DelegationError(msg)
            prev_scopes = scopes
            prev_exp = exp

        leaf = links[-1]
        if presenter is not None and str(presenter) != leaf["aud"]:
            msg = f"token minted for {leaf['aud']!r}, presented by {str(presenter)!r}"
            raise AudienceMismatchError(msg)

        return AuthContext(
            subject=AgentId(leaf["sub"]),
            scopes=list(leaf["scopes"]),
            issued_at=leaf["iat"],
            expires_at=leaf["exp"],
        )

    async def revoke(self, token: Token) -> None:
        """Revoke *token*; every descendant delegated from it dies too.

        Records the token's outer signature. Because that value reappears as an
        intermediate signature in every descendant's chain, the next
        :meth:`verify` of any descendant raises :class:`RevokedAncestorError`.
        Siblings and ancestors are unaffected.

        Example::

            await auth.revoke(root)
        """
        _, sig = self._parse(token)
        self._revoked.add(sig)
