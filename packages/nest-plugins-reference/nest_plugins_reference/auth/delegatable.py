# SPDX-License-Identifier: Apache-2.0
"""Delegatable capability tokens with cascading revocation (macaroon-style).

The default auth plugin
(:class:`~nest_plugins_reference.auth.jwt_auth.JwtAuth`) issues flat,
HMAC-signed tokens and tracks revocation by *exact token string*
(``JwtAuth._revoked: set[str]``).  That shape cannot express the most common
real-world authorization pattern:

* **Delegation without the issuer.**  Agent *A* holds a root capability and
  wants to mint a *narrower*, time-bounded sub-capability for agent *B* — and
  it must be able to do so **without going back to the issuer** for a fresh
  signature.
* **Cascading revocation.**  Revoking *A*'s capability must invalidate *B*'s
  (and every further descendant's) at the next ``verify`` — automatically,
  with no per-child revocation list.

This plugin implements the macaroon construction (Birgisson et al., 2014).
A token carries its whole *chain* of links from root to tip; the tip's HMAC
is keyed on the **previous link's signature**, so extending a token requires
only the parent token — never the root secret:

    s0  = HMAC(root_secret,   canonical(link0))
    s1  = HMAC(s0,            canonical(link1))     # delegation: no secret needed
    ...
    tip = HMAC(s_{n-1},       canonical(link_n))

Three attacks the reference ``jwt`` plugin silently allows, and how this
plugin stops each **at verify time** (an attacker who holds a token can always
*append* a link — the signature alone never proves restriction, so every
restriction is re-checked on the way in):

* **Scope escalation** — a child asking for a scope its parent never held.
  :meth:`delegate` refuses it, and :meth:`verify` independently rejects any
  chain whose scopes are not monotonically narrowing, so a hand-forged token
  cannot slip an escalation past a valid signature.
* **Stale ancestor** — presenting a child after an ancestor was revoked or
  expired.  Because every descendant embeds its ancestors' ``jti`` values,
  :meth:`verify` fails the whole chain if *any* ancestor id is in the revoked
  set (:class:`RevokedAncestorError`) or any link has lapsed
  (:class:`ExpiredTokenError`).
* **Audience confusion** — a token minted for *B* being presented by *C*.
  Each link binds an audience (``sub``); :meth:`verify_presented` rejects a
  presenter that is not the tip's declared audience
  (:class:`AudienceConfusionError`).

Determinism (Tier 1): token ids are content hashes, signatures are HMAC-SHA256
over canonical JSON, and expiry is measured against an injected **logical
tick** clock — never ``time.time()`` — so the same operations replay
byte-identically under a fixed seed.

Example::

    auth = DelegatableAuth(secret=b"authority-secret")
    root = await auth.issue(AgentId("coordinator-0"), ["read", "write", "admin"])
    child = await auth.delegate(root, AgentId("worker-3"), ["read"], ttl=100)
    ctx = await auth.verify_presented(child, AgentId("worker-3"))
    assert ctx.scopes == ["read"]
    await auth.revoke(root)                       # revoke the ancestor...
    # ...and every descendant fails at the next verify, by construction:
    # await auth.verify(child)  -> RevokedAncestorError
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, TypedDict, cast

from nest_core.types import AgentId, AuthContext, Token

if TYPE_CHECKING:
    from collections.abc import Sequence

DEFAULT_ROOT_TTL = 1_000_000
"""Default lifetime (in logical ticks) of a root token minted by :meth:`issue`.

Large by design: root capabilities are long-lived and narrowed by delegation,
not by a short root expiry.  Override per instance via the constructor.
"""


class DelegationError(ValueError):
    """Base class for every delegation/verification failure.

    Subclassing :class:`ValueError` keeps drop-in compatibility with the
    reference ``jwt`` plugin, whose failures are all ``ValueError``.

    Example::

        try:
            await auth.verify(tampered)
        except DelegationError as exc:
            print("rejected:", exc)
    """


class InvalidTokenError(DelegationError):
    """Token is malformed, or its HMAC chain does not verify.

    Example::

        raise InvalidTokenError("signature mismatch at link 2")
    """


class ScopeEscalationError(DelegationError):
    """A child link requests a scope its parent never held.

    Example::

        raise ScopeEscalationError("child asked for 'admin' not in parent scopes")
    """


class TokenTtlError(DelegationError):
    """A child's lifetime is non-positive or exceeds its parent's.

    Example::

        raise TokenTtlError("child exp 200 > parent exp 150")
    """


class ExpiredTokenError(DelegationError):
    """The token (or an ancestor) has lapsed against the logical clock.

    Example::

        raise ExpiredTokenError("token expired at tick 100 (now 137)")
    """


class RevokedAncestorError(DelegationError):
    """Some ancestor in the chain has been revoked — the child fails too.

    Example::

        raise RevokedAncestorError("ancestor 9f3a... is revoked")
    """


class AudienceConfusionError(DelegationError):
    """The presenter is not the audience the tip was minted for.

    Example::

        raise AudienceConfusionError("token for worker-3 presented by mallory-0")
    """


class _Link(TypedDict):
    """One capability link in a delegation chain (wire representation)."""

    jti: str
    sub: str
    scopes: list[str]
    iat: int
    exp: int
    parent: str | None


class _TokenBody(TypedDict):
    """The full decoded token: an ordered chain plus its tip signature."""

    chain: list[_Link]
    sig: str


@dataclass(frozen=True)
class CapabilityLink:
    """Public, read-only view of a single link — for traces and validators.

    Example::

        links = auth.describe(child)
        assert links[-1].sub == "worker-3"
        assert links[0].parent is None            # the root
    """

    jti: str
    sub: str
    scopes: tuple[str, ...]
    iat: int
    exp: int
    parent: str | None


def _canonical(link: _Link) -> bytes:
    """Serialize a link to canonical bytes (sorted keys, no whitespace).

    Determinism hinges on this being stable, so scopes are sorted upstream and
    the encoding pins key order and separators.

    Example::

        blob = _canonical({"jti": "x", "sub": "a", "scopes": [], "iat": 0, "exp": 1})
    """
    return json.dumps(link, sort_keys=True, separators=(",", ":")).encode()


def _mint_jti(sub: str, scopes: list[str], iat: int, exp: int, parent: str | None) -> str:
    """Derive a deterministic token id from a link's content-bearing fields.

    Content addressing means two links with identical content share an id and
    a tampered link gets a *different* id (so a forged ``parent`` pointer is
    detectable at verify time).

    Example::

        jti = _mint_jti("a1", ["read"], 0, 100, None)
    """
    material = json.dumps(
        {"sub": sub, "scopes": scopes, "iat": iat, "exp": exp, "parent": parent},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(material).hexdigest()[:16]


class DelegatableAuth:
    """Macaroon-style auth: delegatable capabilities with cascading revocation.

    The instance is the authority: it holds the root ``secret`` used to anchor
    (and verify) every chain, the shared revocation set, and a logical clock.
    Delegation, by contrast, needs only the parent token — see :meth:`delegate`.

    Example::

        auth = DelegatableAuth(secret=b"secret", clock=0)
        root = await auth.issue(AgentId("a1"), ["read", "write"])
        ctx = await auth.verify(root)
    """

    def __init__(
        self,
        secret: bytes = b"nest-delegatable-secret",
        clock: int = 0,
        root_ttl: int = DEFAULT_ROOT_TTL,
    ) -> None:
        self._secret = secret
        self._clock = clock
        self._root_ttl = root_ttl
        self._revoked: set[str] = set()

    @property
    def now(self) -> int:
        """Current logical tick used for issuance and expiry checks.

        Example::

            assert auth.now == 0
        """
        return self._clock

    def advance(self, ticks: int = 1) -> int:
        """Advance the logical clock and return the new tick (for tests/drivers).

        Example::

            auth.advance(50)
        """
        if ticks < 0:
            msg = "cannot rewind the logical clock"
            raise ValueError(msg)
        self._clock += ticks
        return self._clock

    # -- encoding -----------------------------------------------------------

    @staticmethod
    def _encode(chain: list[_Link], sig: str) -> Token:
        body: _TokenBody = {"chain": chain, "sig": sig}
        return Token(json.dumps(body, sort_keys=True, separators=(",", ":")))

    @staticmethod
    def _decode(token: Token) -> _TokenBody:
        try:
            raw = json.loads(str(token))
        except json.JSONDecodeError as exc:
            msg = f"token is not valid JSON: {exc}"
            raise InvalidTokenError(msg) from exc
        if not isinstance(raw, dict):
            msg = "token is not a JSON object"
            raise InvalidTokenError(msg)
        data = cast("dict[str, object]", raw)
        if "chain" not in data or "sig" not in data:
            msg = "token missing 'chain' or 'sig'"
            raise InvalidTokenError(msg)
        chain = data["chain"]
        if not isinstance(chain, list) or not chain:
            msg = "token chain is empty or malformed"
            raise InvalidTokenError(msg)
        return cast("_TokenBody", data)

    def _tip_signature(self, chain: Sequence[_Link]) -> str:
        """Recompute the chain's tip signature from the root secret."""
        sig = hmac.new(self._secret, _canonical(chain[0]), hashlib.sha256).hexdigest()
        for link in chain[1:]:
            sig = hmac.new(sig.encode(), _canonical(link), hashlib.sha256).hexdigest()
        return sig

    # -- Auth protocol ------------------------------------------------------

    async def issue(self, subject: AgentId, scopes: list[str]) -> Token:
        """Mint a root capability token for ``subject`` with ``scopes``.

        Example::

            root = await auth.issue(AgentId("coordinator-0"), ["read", "write"])
        """
        norm = sorted(set(scopes))
        iat = self._clock
        exp = self._clock + self._root_ttl
        jti = _mint_jti(str(subject), norm, iat, exp, None)
        link: _Link = {
            "jti": jti,
            "sub": str(subject),
            "scopes": norm,
            "iat": iat,
            "exp": exp,
            "parent": None,
        }
        return self._encode([link], self._tip_signature([link]))

    async def delegate(
        self,
        parent_token: Token,
        audience: AgentId,
        scopes_subset: list[str],
        ttl: int,
    ) -> Token:
        """Mint a narrower child capability for ``audience`` — no issuer needed.

        The child's scopes must be a subset of the parent's (a request for any
        scope the parent lacks raises :class:`ScopeEscalationError`) and its
        expiry is clamped to never outlive the parent.  Only the parent token
        is consumed; the root ``secret`` is untouched, which is what makes this
        real delegation rather than re-issuance.

        Example::

            child = await auth.delegate(root, AgentId("worker-3"), ["read"], ttl=100)
        """
        body = self._decode(parent_token)
        parent = body["chain"][-1]
        parent_scopes = set(parent["scopes"])
        requested = sorted(set(scopes_subset))
        extra = set(requested) - parent_scopes
        if extra:
            msg = f"scope escalation: {sorted(extra)} not held by parent {parent['jti']}"
            raise ScopeEscalationError(msg)
        if ttl <= 0:
            msg = f"child ttl must be positive, got {ttl}"
            raise TokenTtlError(msg)
        iat = self._clock
        exp = min(self._clock + ttl, parent["exp"])
        if exp <= iat:
            msg = f"child already expired: exp {exp} <= iat {iat}"
            raise TokenTtlError(msg)
        jti = _mint_jti(str(audience), requested, iat, exp, parent["jti"])
        child: _Link = {
            "jti": jti,
            "sub": str(audience),
            "scopes": requested,
            "iat": iat,
            "exp": exp,
            "parent": parent["jti"],
        }
        new_chain = [*body["chain"], child]
        # Extend the parent's *tip* signature by one HMAC — never the root
        # secret.  This is the macaroon property: any holder of the parent
        # token can delegate without contacting the issuer.
        child_sig = hmac.new(body["sig"].encode(), _canonical(child), hashlib.sha256).hexdigest()
        return self._encode(new_chain, child_sig)

    async def verify(self, token: Token) -> AuthContext:
        """Verify a token end-to-end and return the tip's :class:`AuthContext`.

        Checks, in order: HMAC chain integrity and content-addressed ids,
        monotonic scope narrowing, monotonic (non-increasing) expiry, tip
        expiry against the logical clock, and transitive revocation of every
        ancestor.  Any failure raises a :class:`DelegationError` subclass.

        Example::

            ctx = await auth.verify(child)
            assert ctx.subject == AgentId("worker-3")
        """
        body = self._decode(token)
        chain = body["chain"]

        if chain[0]["parent"] is not None:
            msg = "root link must have no parent"
            raise InvalidTokenError(msg)
        for depth, link in enumerate(chain):
            expected_jti = _mint_jti(
                link["sub"], link["scopes"], link["iat"], link["exp"], link["parent"]
            )
            if not hmac.compare_digest(expected_jti, link["jti"]):
                msg = f"tampered link at depth {depth}: id does not match content"
                raise InvalidTokenError(msg)
            if depth > 0 and link["parent"] != chain[depth - 1]["jti"]:
                msg = f"broken chain at depth {depth}: parent pointer mismatch"
                raise InvalidTokenError(msg)

        if not hmac.compare_digest(self._tip_signature(chain), body["sig"]):
            msg = "token signature does not verify"
            raise InvalidTokenError(msg)

        for depth in range(1, len(chain)):
            if not set(chain[depth]["scopes"]) <= set(chain[depth - 1]["scopes"]):
                widened = sorted(set(chain[depth]["scopes"]) - set(chain[depth - 1]["scopes"]))
                msg = f"scope escalation at depth {depth}: gained {widened}"
                raise ScopeEscalationError(msg)
            if chain[depth]["exp"] > chain[depth - 1]["exp"]:
                msg = f"ttl escalation at depth {depth}: child outlives parent"
                raise TokenTtlError(msg)

        tip = chain[-1]
        if tip["exp"] < self._clock:
            msg = f"token expired at tick {tip['exp']} (now {self._clock})"
            raise ExpiredTokenError(msg)

        for link in chain:
            if link["jti"] in self._revoked:
                msg = f"ancestor {link['jti']} is revoked"
                raise RevokedAncestorError(msg)

        return AuthContext(
            subject=AgentId(tip["sub"]),
            scopes=list(tip["scopes"]),
            issued_at=float(tip["iat"]),
            expires_at=float(tip["exp"]),
        )

    async def verify_presented(self, token: Token, presenter: AgentId) -> AuthContext:
        """Verify ``token`` **and** bind it to ``presenter`` (audience check).

        Everything :meth:`verify` checks, plus: the tip's audience must equal
        the agent actually presenting the token, closing the audience-confusion
        hole the flat ``jwt`` plugin cannot express.

        Example::

            ctx = await auth.verify_presented(child, AgentId("worker-3"))
        """
        ctx = await self.verify(token)
        if ctx.subject != presenter:
            msg = f"token for {ctx.subject} presented by {presenter}"
            raise AudienceConfusionError(msg)
        return ctx

    async def revoke(self, token: Token) -> None:
        """Revoke a token by its tip id — cascades to every descendant.

        Because each descendant embeds this id among its ancestors, revoking
        here makes them all fail their next :meth:`verify` with
        :class:`RevokedAncestorError`.

        Example::

            await auth.revoke(root)   # every child/grandchild now fails to verify
        """
        body = self._decode(token)
        self._revoked.add(body["chain"][-1]["jti"])

    # -- observability ------------------------------------------------------

    def describe(self, token: Token) -> tuple[CapabilityLink, ...]:
        """Return the chain as read-only :class:`CapabilityLink` records.

        Useful for emitting delegation evidence into a trace or feeding an
        adversarial validator without exposing the mutable wire dicts.

        Example::

            root_link, *rest = auth.describe(child)
            assert root_link.parent is None
        """
        body = self._decode(token)
        return tuple(
            CapabilityLink(
                jti=link["jti"],
                sub=link["sub"],
                scopes=tuple(link["scopes"]),
                iat=link["iat"],
                exp=link["exp"],
                parent=link["parent"],
            )
            for link in body["chain"]
        )

    def is_revoked(self, jti: str) -> bool:
        """Return whether a specific link id has been revoked.

        Example::

            assert auth.is_revoked(root_jti) is False
        """
        return jti in self._revoked
