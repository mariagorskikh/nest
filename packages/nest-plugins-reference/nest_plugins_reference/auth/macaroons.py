# SPDX-License-Identifier: Apache-2.0
"""Macaroon-style auth plugin: delegatable capability tokens with cascading revocation.

An agent holding a token can mint a narrower token for another agent on its own,
without going back to the issuer. Each delegation appends a caveat and re-chains the
HMAC so the signature covers the whole ancestry. Because a child's signature is
anchored to its parent's, revoking any ancestor's id makes every descendant fail to
verify by construction, with no per-child revocation list.

The design follows the macaroon paper (Birgisson et al., 2014): a token is a chain of
caveats, each strictly attenuating the last (scopes can only shrink, expiry can only
move earlier), and the chained signature makes tampering or scope escalation
detectable at verify time.

Example::

    auth = MacaroonAuth(secret=b"root-secret")
    root = await auth.issue(AgentId("a1"), ["read", "write", "admin"])
    child = await auth.delegate(root, audience=AgentId("b"), scopes_subset=["read"], ttl=600)
    ctx = await auth.verify(child)          # ctx.scopes == ["read"]
    await auth.revoke(root)                 # revoking the parent...
    await auth.verify(child)                # ...raises RevokedAncestorError
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Any

from nest_core.types import AgentId, AuthContext, Token

_WIRE_VERSION = 1


class DelegationError(Exception):
    """Base class for every macaroon delegation or verification failure."""


class InvalidTokenError(DelegationError):
    """The token is malformed or its chained signature does not match."""


class ScopeEscalationError(DelegationError):
    """A child token requested a scope its parent does not hold."""


class TtlExtensionError(DelegationError):
    """A child token asked to outlive its parent."""


class RevokedAncestorError(DelegationError):
    """The token, or one of its ancestors, has been revoked."""


class ExpiredTokenError(DelegationError):
    """The token, or one of its ancestors, has expired."""


class AudienceMismatchError(DelegationError):
    """The token was presented by an agent other than its declared audience."""


@dataclass(frozen=True)
class Caveat:
    """One link in a macaroon chain: who may act, with which scopes, until when.

    Example::

        cav = Caveat(tid="ab12", subject="a1", audience="b",
                     scopes=("read",), issued_at=0.0, expires_at=600.0, parent="root9")
    """

    tid: str
    subject: str
    audience: str
    scopes: tuple[str, ...]
    issued_at: float
    expires_at: float
    parent: str | None


def _canonical(data: dict[str, Any]) -> bytes:
    """Return a stable byte encoding so signatures are deterministic.

    Example::

        raw = _canonical({"b": 2, "a": 1})
    """
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _content(
    subject: str,
    audience: str,
    scopes: tuple[str, ...],
    issued_at: float,
    expires_at: float,
    parent: str | None,
) -> dict[str, Any]:
    """Build the signed content of a caveat (everything except its own id).

    Example::

        c = _content("a1", "b", ("read",), 0.0, 600.0, None)
    """
    return {
        "subject": subject,
        "audience": audience,
        "scopes": list(scopes),
        "issued_at": issued_at,
        "expires_at": expires_at,
        "parent": parent,
    }


def _compute_tid(content: dict[str, Any]) -> str:
    """Content-address a caveat: its id is a hash of its signed content.

    Example::

        tid = _compute_tid(_content("a1", "a1", ("read",), 0.0, 1.0, None))
    """
    return hashlib.sha256(_canonical(content)).hexdigest()[:32]


class MacaroonAuth:
    """Delegatable capability tokens with cascading revocation.

    Example::

        auth = MacaroonAuth(secret=b"secret")
        root = await auth.issue(AgentId("a1"), ["read", "write"])
        child = await auth.delegate(root, AgentId("b"), ["read"], ttl=60)
    """

    def __init__(
        self,
        secret: bytes = b"nest-macaroon-secret",
        clock: float | None = None,
        default_ttl: float = 3600.0,
    ) -> None:
        self._secret = secret
        self._clock = clock
        self._default_ttl = default_ttl
        self._revoked: set[str] = set()

    def set_clock(self, now: float) -> None:
        """Pin the clock to a fixed value for deterministic issuance and expiry.

        Example::

            auth.set_clock(100.0)
        """
        self._clock = now

    def _now(self) -> float:
        if self._clock is not None:
            return self._clock
        return time.time()

    def _chain_signature(self, caveats: list[Caveat]) -> str:
        """Fold the caveat chain into one HMAC, each link keyed by the previous.

        Example::

            sig = auth._chain_signature([root_caveat, child_caveat])
        """
        key = self._secret
        sig = ""
        for cav in caveats:
            content = _content(
                cav.subject, cav.audience, cav.scopes, cav.issued_at, cav.expires_at, cav.parent
            )
            payload = _canonical({"tid": cav.tid, **content})
            sig = hmac.new(key, payload, hashlib.sha256).hexdigest()
            key = sig.encode("ascii")
        return sig

    def _encode(self, caveats: list[Caveat]) -> Token:
        """Serialize a caveat chain plus its signature into an opaque token string.

        Example::

            token = auth._encode([root_caveat])
        """
        chain = [
            {
                "tid": c.tid,
                "subject": c.subject,
                "audience": c.audience,
                "scopes": list(c.scopes),
                "issued_at": c.issued_at,
                "expires_at": c.expires_at,
                "parent": c.parent,
            }
            for c in caveats
        ]
        body = {"v": _WIRE_VERSION, "chain": chain, "sig": self._chain_signature(caveats)}
        return Token(json.dumps(body, sort_keys=True, separators=(",", ":")))

    def _decode(self, token: Token) -> list[Caveat]:
        """Parse a token into its caveat chain (structure only, no signature check).

        Example::

            caveats = auth._decode(token)
        """
        try:
            body = json.loads(str(token))
            raw_chain = body["chain"]
            caveats: list[Caveat] = []
            for item in raw_chain:
                caveats.append(
                    Caveat(
                        tid=str(item["tid"]),
                        subject=str(item["subject"]),
                        audience=str(item["audience"]),
                        scopes=tuple(str(s) for s in item["scopes"]),
                        issued_at=float(item["issued_at"]),
                        expires_at=float(item["expires_at"]),
                        parent=(None if item["parent"] is None else str(item["parent"])),
                    )
                )
        except (ValueError, KeyError, TypeError) as exc:
            msg = "Token is malformed"
            raise InvalidTokenError(msg) from exc
        if not caveats:
            msg = "Token has an empty caveat chain"
            raise InvalidTokenError(msg)
        return caveats

    def _check_chain(self, token: Token) -> list[Caveat]:
        """Validate structure, signature, attenuation, revocation, and expiry.

        Example::

            caveats = auth._check_chain(token)
            leaf = caveats[-1]
        """
        caveats = self._decode(token)
        body = json.loads(str(token))

        # 1. Signature must match a re-chain from the root secret. This catches
        #    tampering and any attempt to forge a caveat the issuer never signed.
        if not hmac.compare_digest(str(body["sig"]), self._chain_signature(caveats)):
            msg = "Token signature does not verify"
            raise InvalidTokenError(msg)

        now = self._now()
        prev: Caveat | None = None
        for cav in caveats:
            # 2. The id must content-address the caveat (integrity of the id itself).
            expected_tid = _compute_tid(
                _content(
                    cav.subject, cav.audience, cav.scopes, cav.issued_at, cav.expires_at, cav.parent
                )
            )
            if not hmac.compare_digest(cav.tid, expected_tid):
                msg = "Caveat id does not match its content"
                raise InvalidTokenError(msg)

            # 3. Cascading revocation: any revoked ancestor kills the whole chain.
            if cav.tid in self._revoked:
                msg = f"Ancestor {cav.tid} has been revoked"
                raise RevokedAncestorError(msg)

            # 4. Expiry, checked for every link so a stale ancestor is caught too.
            if cav.expires_at < now:
                msg = "Token or an ancestor has expired"
                raise ExpiredTokenError(msg)

            # 5. Attenuation, re-checked at verify as defense in depth.
            if prev is not None:
                if cav.parent != prev.tid:
                    msg = "Broken parent link in delegation chain"
                    raise InvalidTokenError(msg)
                if not set(cav.scopes).issubset(set(prev.scopes)):
                    msg = "Child scopes are not a subset of the parent"
                    raise ScopeEscalationError(msg)
                if cav.expires_at > prev.expires_at:
                    msg = "Child expiry is later than the parent"
                    raise TtlExtensionError(msg)
            prev = cav
        return caveats

    async def issue(self, subject: AgentId, scopes: list[str]) -> Token:
        """Issue a fresh root token for a subject with the given scopes.

        Example::

            root = await auth.issue(AgentId("a1"), ["read", "write"])
        """
        now = self._now()
        exp = now + self._default_ttl
        content = _content(str(subject), str(subject), tuple(scopes), now, exp, None)
        tid = _compute_tid(content)
        caveat = Caveat(tid, str(subject), str(subject), tuple(scopes), now, exp, None)
        return self._encode([caveat])

    async def delegate(
        self,
        parent_token: Token,
        audience: AgentId,
        scopes_subset: list[str],
        ttl: float,
    ) -> Token:
        """Mint a narrower child token for another agent, without the issuer.

        Example::

            child = await auth.delegate(root, AgentId("b"), ["read"], ttl=60)
        """
        caveats = self._check_chain(parent_token)
        parent = caveats[-1]

        if not set(scopes_subset).issubset(set(parent.scopes)):
            msg = "Delegated scopes must be a subset of the parent's scopes"
            raise ScopeEscalationError(msg)

        now = self._now()
        child_exp = now + ttl
        if child_exp > parent.expires_at:
            msg = "Delegated token cannot outlive its parent"
            raise TtlExtensionError(msg)

        content = _content(
            str(audience), str(audience), tuple(scopes_subset), now, child_exp, parent.tid
        )
        tid = _compute_tid(content)
        child = Caveat(
            tid, str(audience), str(audience), tuple(scopes_subset), now, child_exp, parent.tid
        )
        return self._encode([*caveats, child])

    async def verify(self, token: Token) -> AuthContext:
        """Verify a token end to end and return the leaf's auth context.

        Example::

            ctx = await auth.verify(child)
            assert ctx.subject == AgentId("b")
        """
        caveats = self._check_chain(token)
        leaf = caveats[-1]
        return AuthContext(
            subject=AgentId(leaf.audience),
            scopes=list(leaf.scopes),
            issued_at=leaf.issued_at,
            expires_at=leaf.expires_at,
        )

    async def verify_for(self, token: Token, presenter: AgentId) -> AuthContext:
        """Verify a token and confirm the presenter is its declared audience.

        Example::

            ctx = await auth.verify_for(child, AgentId("b"))
        """
        caveats = self._check_chain(token)
        leaf = caveats[-1]
        if leaf.audience != str(presenter):
            msg = f"Token audience {leaf.audience!r} was presented by {str(presenter)!r}"
            raise AudienceMismatchError(msg)
        return AuthContext(
            subject=AgentId(leaf.audience),
            scopes=list(leaf.scopes),
            issued_at=leaf.issued_at,
            expires_at=leaf.expires_at,
        )

    async def revoke(self, token: Token) -> None:
        """Revoke a token by its leaf id, which also invalidates its descendants.

        Example::

            await auth.revoke(root)
        """
        caveats = self._decode(token)
        self._revoked.add(caveats[-1].tid)
