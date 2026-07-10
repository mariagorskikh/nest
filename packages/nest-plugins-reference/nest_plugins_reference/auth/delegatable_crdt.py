# SPDX-License-Identifier: Apache-2.0
"""Delegatable capability tokens with cascading, partition-tolerant revocation.

Where the default :mod:`nest_plugins_reference.auth.jwt_auth` plugin issues a
flat HMAC-signed token and tracks revocation as an exact-string ``set``, this
plugin adds three capabilities:

* **Offline delegation** — an agent holding a token can mint a strictly
  narrower sub-token for another agent *without* contacting the issuer. This
  is the macaroon construction (Birgisson et al., 2014): each child seal is
  ``HMAC(parent_seal, caveat)``, so a holder can only ever *add* restrictions,
  never widen them. Recovering a parent seal from a child seal is infeasible.

* **Cascading revocation by construction** — revocation is keyed on a seal,
  not a token string. Because every descendant's seal is derived from its
  ancestor's seal, recomputing a descendant's chain during
  :meth:`~CrdtDelegatableAuth.verify` necessarily reproduces each ancestor seal.
  Revoking an ancestor therefore invalidates the whole subtree with *no
  per-child bookkeeping* (contrast ``jwt_auth`` which revokes one string).

* **Partition-tolerant revocation state** — in a swarm the revocation set is
  replicated per verifier and spread by gossip. It is a :class:`RevocationSet`,
  a grow-only set (G-Set CRDT): merges are the set union, so they are
  commutative, associative and idempotent, and replicas converge to the same
  view after a partition heals. The safety property is monotone: once a verifier
  has observed a revocation it never again accepts that token. A verifier that
  has not yet received a revocation still accepts until it merges one.

Determinism
-----------
Nanda Town Tier 1 requires byte-identical traces under a fixed seed. This
plugin uses **no** wall-clock time and **no** RNG: token identity is the seal
(a pure function of content and secret), and all time comes from an injected
:class:`Clock`. There is no ``time.time()`` fallback and no ``uuid`` — two
common ways a plugin silently becomes non-reproducible.

Example::

    clock = LogicalClock()
    auth = CrdtDelegatableAuth(secret=b"secret", clock=clock)
    root = await auth.issue(AgentId("orchestrator"), ["read", "write"])
    child = await auth.delegate(root, AgentId("worker"), ["read"], ttl=60.0)
    ctx = await auth.verify(child, presenter=AgentId("worker"))
    assert ctx.scopes == ["read"]
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Protocol, TypedDict, cast, runtime_checkable

from nest_core.types import AgentId, AuthContext, Token

# ---------------------------------------------------------------------------
# Typed errors — each maps to a distinct verification failure the adversarial
# validator asserts on, so a caller can distinguish a scope request that is too
# broad from a grant whose ancestor has been revoked.
# ---------------------------------------------------------------------------


class DelegationError(ValueError):
    """Base class for every delegatable-auth failure.

    Example::

        try:
            await auth.verify(bad_token)
        except DelegationError:
            ...
    """


class MalformedTokenError(DelegationError):
    """Raised when a token is not well-formed or its seal does not match.

    Example::

        raise MalformedTokenError("seal mismatch")
    """


class ScopeEscalationError(DelegationError):
    """Raised when a delegation requests scopes the parent does not hold.

    Example::

        raise ScopeEscalationError("child scopes exceed parent")
    """


class ExpiredTokenError(DelegationError):
    """Raised when a token (or any ancestor) has passed its expiry tick.

    Example::

        raise ExpiredTokenError("token expired at tick 20")
    """


class RevokedAncestorError(DelegationError):
    """Raised when a token or any ancestor seal is in the revocation set.

    Example::

        raise RevokedAncestorError("ancestor seal revoked")
    """


class AudienceMismatchError(DelegationError):
    """Raised when a token is presented by an agent other than its audience.

    Example::

        raise AudienceMismatchError("presenter is not the audience")
    """


# ---------------------------------------------------------------------------
# Clock — structural, so the plugin accepts both this module's LogicalClock
# (standalone / tests) and the simulator's VirtualClock (Tier 1 runs) without
# importing nest_core.sim. Both expose a read-only ``now``.
# ---------------------------------------------------------------------------


@runtime_checkable
class Clock(Protocol):
    """Anything exposing a monotonically advancing ``now`` tick.

    Example::

        def uptime(clock: Clock) -> float:
            return clock.now
    """

    @property
    def now(self) -> float:
        """Current tick.

        Example::

            t = clock.now
        """
        ...


class LogicalClock:
    """Deterministic in-process clock for standalone use and tests.

    Structurally compatible with the simulator's ``VirtualClock`` so a
    :class:`CrdtDelegatableAuth` can be exercised identically in both settings.

    Example::

        clock = LogicalClock()
        clock.advance_to(30.0)
        assert clock.now == 30.0
    """

    __slots__ = ("_now",)

    def __init__(self, start: float = 0.0) -> None:
        self._now = start

    @property
    def now(self) -> float:
        """Current tick.

        Example::

            t = clock.now
        """
        return self._now

    def advance_to(self, tick: float) -> None:
        """Advance the clock to *tick*; must not move backwards.

        Example::

            clock.advance_to(42.0)
        """
        if tick < self._now:
            msg = f"clock cannot move backwards: {tick} < {self._now}"
            raise ValueError(msg)
        self._now = tick


# ---------------------------------------------------------------------------
# Revocation set — a grow-only set (G-Set CRDT) of revoked seals. This is the
# distributed-systems core: each verifier owns a replica; merges are unions.
# ---------------------------------------------------------------------------


class RevocationSet:
    """A grow-only set of revoked seals — a G-Set CRDT.

    Elements are hex seal digests. The set only ever grows, so its merge is the
    set union: commutative, associative and idempotent. Replicas converge to the
    same membership regardless of the order or number of times revocations are
    exchanged, and that membership is monotone (a seal, once revoked and
    observed, is never un-revoked).

    Example::

        a, b = RevocationSet(), RevocationSet()
        a.revoke("deadbeef")
        b.merge(a)
        assert "deadbeef" in b
    """

    __slots__ = ("_seals",)

    def __init__(self, seals: frozenset[str] | None = None) -> None:
        self._seals: set[str] = set(seals) if seals is not None else set()

    def revoke(self, seal: str) -> None:
        """Add a seal to the revocation set.

        Example::

            revocations.revoke("a1b2c3")
        """
        self._seals.add(seal)

    def merge(self, other: RevocationSet) -> None:
        """Merge another replica in place (set union — the CRDT join).

        Example::

            local.merge(remote)
        """
        self._seals |= other._seals

    def snapshot(self) -> frozenset[str]:
        """Return an immutable copy of the current membership.

        Example::

            seen = revocations.snapshot()
        """
        return frozenset(self._seals)

    def __contains__(self, seal: str) -> bool:
        """Return whether *seal* has been revoked.

        Example::

            assert "a1b2c3" in revocations
        """
        return seal in self._seals

    def __len__(self) -> int:
        """Number of revoked seals.

        Example::

            n = len(revocations)
        """
        return len(self._seals)


# ---------------------------------------------------------------------------
# Wire shapes. Tokens serialize to canonical JSON; these TypedDicts let pyright
# check the decode path instead of leaning on Any/cast.
# ---------------------------------------------------------------------------


class _Root(TypedDict):
    subject: str
    scopes: list[str]
    issued_at: float
    expires_at: float


class _Caveat(TypedDict):
    audience: str
    scopes: list[str]
    expires_at: float


class _Body(TypedDict):
    root: _Root
    caveats: list[_Caveat]
    sig: str


@dataclass(frozen=True)
class TokenView:
    """Read-only summary of a token's chain, for validators and tests.

    ``depth`` is 0 for a root token and increments per delegation. ``seals``
    lists every seal from root to leaf, so a validator can assert exactly which
    ancestor a revocation targets.

    Example::

        view = auth.describe(child)
        assert view.depth == 1
        assert view.audience == AgentId("worker")
    """

    subject: AgentId
    audience: AgentId
    scopes: tuple[str, ...]
    issued_at: float
    expires_at: float
    depth: int
    seals: tuple[str, ...]


def _canonical(obj: _Root | _Caveat) -> bytes:
    """Serialize a payload to canonical JSON bytes (sorted keys, no spaces).

    Example::

        raw = _canonical({"audience": "b", "scopes": ["read"], "expires_at": 1.0})
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _require_str_list(value: object, field: str) -> list[str]:
    """Validate that *value* is a ``list[str]`` or raise ``MalformedTokenError``."""
    if not isinstance(value, list):
        msg = f"malformed token: {field} must be a list of strings"
        raise MalformedTokenError(msg)
    items = cast("list[object]", value)
    if not all(isinstance(item, str) for item in items):
        msg = f"malformed token: {field} must be a list of strings"
        raise MalformedTokenError(msg)
    # Narrowed by the check above; rebuild to give pyright a concrete list[str].
    return [item for item in items if isinstance(item, str)]


def _require_number(value: object, field: str) -> float:
    """Validate that *value* is a real number or raise ``MalformedTokenError``."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        msg = f"malformed token: {field} must be a number"
        raise MalformedTokenError(msg)
    return float(value)


def _require_str(value: object, field: str) -> str:
    """Validate that *value* is a ``str`` or raise ``MalformedTokenError``."""
    if not isinstance(value, str):
        msg = f"malformed token: {field} must be a string"
        raise MalformedTokenError(msg)
    return value


def _require_obj(value: object, field: str) -> dict[str, object]:
    """Validate that *value* is a JSON object or raise ``MalformedTokenError``.

    This is the single trust boundary where untyped decoded JSON becomes a
    typed mapping; downstream code reads it through the ``_require_*`` helpers.
    """
    if not isinstance(value, dict):
        msg = f"malformed token: {field} must be an object"
        raise MalformedTokenError(msg)
    # JSON object keys are always strings; values stay ``object`` until checked.
    return cast("dict[str, object]", value)


class CrdtDelegatableAuth:
    """Macaroon-style auth with cascading, partition-tolerant revocation.

    Implements the :class:`nest_core.layers.auth.Auth` protocol
    (:meth:`issue`, :meth:`verify`, :meth:`revoke`) and adds :meth:`delegate`
    for offline sub-token minting and :meth:`merge` for CRDT revocation gossip.

    Example::

        auth = CrdtDelegatableAuth(secret=b"secret", clock=LogicalClock())
        token = await auth.issue(AgentId("a1"), ["read", "write"])
        ctx = await auth.verify(token)
        assert ctx.subject == AgentId("a1")
    """

    #: Default lifetime (in ticks) granted to a freshly issued root token.
    DEFAULT_ROOT_TTL: float = 3600.0

    def __init__(
        self,
        secret: bytes = b"nest-default-secret",
        clock: Clock | None = None,
        revocations: RevocationSet | None = None,
    ) -> None:
        """Create an auth instance.

        *clock* defaults to a fresh :class:`LogicalClock` at tick 0 so the
        plugin is deterministic out of the box; in a Tier 1 run the simulator's
        ``VirtualClock`` is injected instead. *revocations* lets several agents
        share (or later merge) a replica.

        Example::

            auth = CrdtDelegatableAuth(secret=b"s3cr3t", clock=LogicalClock())
        """
        self._secret = secret
        self._clock: Clock = clock if clock is not None else LogicalClock()
        self.revocations: RevocationSet = (
            revocations if revocations is not None else RevocationSet()
        )

    # -- helpers ------------------------------------------------------------

    def _now(self) -> float:
        """Current tick from the injected clock (never wall-clock)."""
        return self._clock.now

    def set_now(self, tick: float) -> None:
        """Point the plugin at the current simulator tick.

        Tier 1 agents hold a plain ``ctx.time`` float rather than the clock
        object, so they call this before each operation to keep expiry checks
        anchored to simulation time (never wall-clock). Deterministic: the tick
        comes from the seeded virtual clock.

        Note: this replaces the clock with a fresh :class:`LogicalClock`, so a
        live clock object (e.g. the simulator's ``VirtualClock``) injected at
        construction does not survive a ``set_now`` call. That is fine for the
        Tier 1 agents here, which push ``ctx.time`` in before every operation;
        hold a reference to a live clock and skip ``set_now`` if you need it to
        keep advancing on its own.

        Example::

            auth.set_now(ctx.time)
        """
        self._clock = LogicalClock(tick)

    def _root_seal(self, root: _Root) -> bytes:
        """Seal for a root token: ``HMAC(secret, canonical(root))``."""
        return hmac.new(self._secret, _canonical(root), hashlib.sha256).digest()

    def _chain_seals(self, body: _Body) -> list[bytes]:
        """Recompute every seal from root to leaf for *body*.

        The returned list has length ``len(caveats) + 1``: index 0 is the root
        seal, index ``i+1`` folds caveat ``i`` under the previous seal. This is
        the single source of truth for both signature checking and cascading
        revocation.
        """
        seal = self._root_seal(body["root"])
        seals = [seal]
        for caveat in body["caveats"]:
            seal = hmac.new(seal, _canonical(caveat), hashlib.sha256).digest()
            seals.append(seal)
        return seals

    def _decode(self, token: Token) -> _Body:
        """Parse and structurally validate a token string into a ``_Body``."""
        try:
            parsed: object = json.loads(str(token))
        except json.JSONDecodeError as exc:
            msg = "malformed token: not valid JSON"
            raise MalformedTokenError(msg) from exc

        top = _require_obj(parsed, "token")
        root_obj = _require_obj(top.get("root"), "root")
        caveats_obj = top.get("caveats")
        if not isinstance(caveats_obj, list):
            msg = "malformed token: caveats must be a list"
            raise MalformedTokenError(msg)

        root: _Root = {
            "subject": _require_str(root_obj.get("subject"), "root.subject"),
            "scopes": _require_str_list(root_obj.get("scopes"), "root.scopes"),
            "issued_at": _require_number(root_obj.get("issued_at"), "root.issued_at"),
            "expires_at": _require_number(root_obj.get("expires_at"), "root.expires_at"),
        }
        caveats: list[_Caveat] = []
        for i, cav in enumerate(cast("list[object]", caveats_obj)):
            cav_obj = _require_obj(cav, f"caveat[{i}]")
            caveats.append(
                {
                    "audience": _require_str(cav_obj.get("audience"), f"caveat[{i}].audience"),
                    "scopes": _require_str_list(cav_obj.get("scopes"), f"caveat[{i}].scopes"),
                    "expires_at": _require_number(
                        cav_obj.get("expires_at"), f"caveat[{i}].expires_at"
                    ),
                }
            )
        return {"root": root, "caveats": caveats, "sig": _require_str(top.get("sig"), "sig")}

    def _effective_scopes(self, body: _Body) -> list[str]:
        """Scopes granted: the leaf caveat's, else the root's."""
        return body["caveats"][-1]["scopes"] if body["caveats"] else body["root"]["scopes"]

    def _effective_audience(self, body: _Body) -> str:
        """Audience bound: the leaf caveat's, else the root subject."""
        return body["caveats"][-1]["audience"] if body["caveats"] else body["root"]["subject"]

    def _effective_expiry(self, body: _Body) -> float:
        """Expiry in force: the leaf caveat's, else the root's."""
        return body["caveats"][-1]["expires_at"] if body["caveats"] else body["root"]["expires_at"]

    def _check_live(self, body: _Body, seals: list[bytes]) -> None:
        """Assert *body* is neither expired at any level nor revoked at any seal."""
        now = self._now()
        if now > body["root"]["expires_at"] or any(
            now > cav["expires_at"] for cav in body["caveats"]
        ):
            msg = "token or an ancestor has expired"
            raise ExpiredTokenError(msg)
        for seal in seals:
            if seal.hex() in self.revocations:
                msg = "token or an ancestor seal has been revoked"
                raise RevokedAncestorError(msg)

    # -- Auth protocol ------------------------------------------------------

    async def issue(self, subject: AgentId, scopes: list[str]) -> Token:
        """Issue a root token for *subject* granting *scopes*.

        Example::

            token = await auth.issue(AgentId("a1"), ["read", "write"])
        """
        now = self._now()
        root: _Root = {
            "subject": str(subject),
            "scopes": list(scopes),
            "issued_at": now,
            "expires_at": now + self.DEFAULT_ROOT_TTL,
        }
        sig = self._root_seal(root).hex()
        body: _Body = {"root": root, "caveats": [], "sig": sig}
        return Token(json.dumps(body, sort_keys=True, separators=(",", ":")))

    async def delegate(
        self,
        parent_token: Token,
        audience: AgentId,
        scopes_subset: list[str],
        ttl: float,
    ) -> Token:
        """Mint a narrower child token for *audience*, offline.

        The child grants a strict subset of the parent's scopes, is bound to
        *audience*, and expires at ``now + ttl`` — clamped so it can never
        outlive its parent. Raises :class:`ScopeEscalationError` on widening,
        and refuses to delegate from a dead (expired/revoked) parent.

        Example::

            child = await auth.delegate(root, AgentId("b"), ["read"], ttl=60.0)
        """
        if ttl <= 0:
            msg = "ttl must be positive"
            raise DelegationError(msg)

        body = self._decode(parent_token)
        seals = self._chain_seals(body)
        if seals[-1].hex() != body["sig"]:
            msg = "malformed token: seal mismatch"
            raise MalformedTokenError(msg)
        self._check_live(body, seals)

        parent_scopes = set(self._effective_scopes(body))
        if not set(scopes_subset).issubset(parent_scopes):
            extra = sorted(set(scopes_subset) - parent_scopes)
            msg = f"scope escalation: parent does not hold {extra}"
            raise ScopeEscalationError(msg)

        child_expiry = min(self._now() + ttl, self._effective_expiry(body))
        caveat: _Caveat = {
            "audience": str(audience),
            "scopes": list(scopes_subset),
            "expires_at": child_expiry,
        }
        child_sig = hmac.new(seals[-1], _canonical(caveat), hashlib.sha256).hexdigest()
        child: _Body = {
            "root": body["root"],
            "caveats": [*body["caveats"], caveat],
            "sig": child_sig,
        }
        return Token(json.dumps(child, sort_keys=True, separators=(",", ":")))

    async def verify(self, token: Token, presenter: AgentId | None = None) -> AuthContext:
        """Verify *token* and return its :class:`AuthContext`.

        Checks, in order: seal integrity (tamper), expiry at every level,
        revocation of any ancestor seal, and — when *presenter* is supplied —
        that the presenter is the token's bound audience. ``presenter`` is
        optional so the call stays drop-in compatible with the base ``Auth``
        protocol's ``verify(token)``.

        Example::

            ctx = await auth.verify(child, presenter=AgentId("worker"))
        """
        body = self._decode(token)
        seals = self._chain_seals(body)
        if seals[-1].hex() != body["sig"]:
            msg = "malformed token: seal mismatch"
            raise MalformedTokenError(msg)
        self._check_live(body, seals)

        audience = self._effective_audience(body)
        if presenter is not None and str(presenter) != audience:
            msg = f"audience mismatch: token is for {audience!r}, presented by {str(presenter)!r}"
            raise AudienceMismatchError(msg)

        return AuthContext(
            subject=AgentId(audience),
            scopes=self._effective_scopes(body),
            issued_at=body["root"]["issued_at"],
            expires_at=self._effective_expiry(body),
        )

    async def revoke(self, token: Token) -> None:
        """Revoke *token* (and, by construction, its entire subtree).

        Revocation records the token's own seal. Because every descendant's
        seal is derived from this one, a later :meth:`verify` of any descendant
        recomputes this seal as an ancestor and rejects it — no per-descendant
        state is stored.

        Example::

            await auth.revoke(root)  # kills root and everything delegated from it
        """
        body = self._decode(token)
        seals = self._chain_seals(body)
        if seals[-1].hex() != body["sig"]:
            msg = "malformed token: seal mismatch"
            raise MalformedTokenError(msg)
        self.revocations.revoke(body["sig"])

    # -- distributed helpers ------------------------------------------------

    def merge(self, other: CrdtDelegatableAuth) -> None:
        """Merge another agent's revocation replica into this one (CRDT join).

        Example::

            verifier.merge(issuer)  # gossip: pull in issuer's revocations
        """
        self.revocations.merge(other.revocations)

    def describe(self, token: Token) -> TokenView:
        """Return a :class:`TokenView` of *token* for validators and tests.

        Example::

            view = auth.describe(child)
            assert view.depth == 1
        """
        body = self._decode(token)
        seals = self._chain_seals(body)
        return TokenView(
            subject=AgentId(body["root"]["subject"]),
            audience=AgentId(self._effective_audience(body)),
            scopes=tuple(self._effective_scopes(body)),
            issued_at=body["root"]["issued_at"],
            expires_at=self._effective_expiry(body),
            depth=len(body["caveats"]),
            seals=tuple(seal.hex() for seal in seals),
        )
