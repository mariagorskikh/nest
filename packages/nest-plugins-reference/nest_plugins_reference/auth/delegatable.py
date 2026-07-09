# SPDX-License-Identifier: Apache-2.0
"""Macaroon-style delegatable capability tokens with cascading revocation.

``JwtAuth`` (``nest_plugins_reference.auth.jwt_auth``) signs a flat claim set
with one HMAC and tracks revocation in ``_revoked: set[str]`` keyed by the
*exact* token string. There is no parent-child relationship between tokens at
all, so it cannot model the most common real-world capability pattern: agent
A holds a long-lived token, mints a narrower, shorter-lived token for agent B
*without contacting the issuer*, and revoking A's token must invalidate B's
at the next verification -- automatically, transitively, and without anyone
having to remember to revoke B too.

This plugin borrows the caveat-chaining trick from macaroons (Birgisson et
al., 2014): a token is not one HMAC over one payload, it is an ordered chain
of *caveats*, each signed with the *previous caveat's own signature* as the
HMAC key rather than the root secret::

    sig_0 = HMAC(root_secret,      caveat_0)              # issue()
    sig_1 = HMAC(sig_0,            caveat_1)               # delegate()
    sig_2 = HMAC(sig_1,            caveat_2)               # delegate() again
    ...

Two properties fall out of that construction for free:

1. **Delegation needs no issuer round-trip.** :meth:`DelegatableAuth.delegate`
   never reads ``self._secret``. It only needs the parent token's own
   trailing signature (which travels with the token, in plain sight) to key
   the next caveat. Any agent holding a valid token can attenuate it into a
   narrower child; the anti-pattern this avoids is re-issuance-by-authority
   dressed up as "delegation".
2. **Revocation is transitive by construction.** Every token is
   self-contained -- it carries its *entire* ancestor chain, not just a
   pointer to one. :meth:`DelegatableAuth.verify` replays the whole chain
   from ``self._secret`` and, at every level, recomputes that ancestor's
   exact original token string and checks it against
   ``self._revoked: dict[str, bool]``. That dict only ever gains an entry
   for a token *directly* passed to :meth:`revoke` -- a child's entry is
   never written. Revoking a parent invalidates every descendant the next
   time any of them is verified, with zero bookkeeping proportional to the
   size of the subtree.

Attenuation is enforced at delegation time, not just checked cosmetically:
a child's scopes must be a **strict** (proper) subset of its parent's --
delegation can only narrow, never hold steady or widen -- and a child's TTL
can never let it outlive its parent (``child.exp <= parent.exp``). Both are
enforced inside :meth:`delegate` and raise a typed error immediately; no
invalid token is ever minted.

Delegated tokens also carry a declared **audience** -- the agent they were
minted for. :meth:`verify` alone (matching the base ``Auth`` protocol
signature) cannot check *who* is presenting a token, since the protocol
gives it only the token. :meth:`verify_presented_by` is the audience-aware
sibling: it does everything ``verify`` does and additionally rejects a token
presented by any agent other than its declared audience.

Example::

    auth = DelegatableAuth(secret=b"town-secret", clock=1000.0)
    root = await auth.issue(AgentId("orchestrator"), ["read", "write", "admin"])

    # orchestrator delegates a narrower, shorter-lived capability to a worker
    # -- no call back to the issuer, just the root token orchestrator holds.
    worker_token = await auth.delegate(
        root, AgentId("worker-1"), ["read", "write"], ttl=300.0
    )
    ctx = await auth.verify_presented_by(worker_token, AgentId("worker-1"))
    assert ctx.scopes == ["read", "write"]

    # Revoking the root invalidates worker_token transitively -- no separate
    # revocation entry for worker_token was ever written.
    await auth.revoke(root)
    try:
        await auth.verify(worker_token)
    except RevokedAncestorError:
        pass  # cascading revocation, by construction
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any, cast

from nest_core.types import AgentId, AuthContext, Token

#: Default HMAC key used when no secret is supplied. Matches the naming
#: convention of ``JwtAuth``'s default; the two plugins do not interoperate
#: (different wire formats), so sharing the literal is cosmetic only.
_DEFAULT_SECRET = b"nest-default-secret"

#: Default lifetime, in seconds, of a root token minted by :meth:`issue`.
_DEFAULT_ROOT_TTL = 3600.0


class DelegationError(ValueError):
    """Base class for every capability-delegation failure this plugin raises.

    Subclasses :class:`ValueError` so call sites that only guard against the
    base ``Auth`` protocol's ``ValueError``-raising ``verify`` (see
    ``JwtAuth``) keep working unchanged against the richer plugin.

    Example::

        try:
            await auth.delegate(parent, audience, ["admin"], ttl=60.0)
        except DelegationError as exc:
            print(f"delegation refused: {exc}")
    """


class InvalidTokenError(DelegationError):
    """Raised when a token is malformed, tampered with, or expired.

    Covers structural corruption (not valid JSON, missing caveat chain),
    a signature that does not match its caveat at any level of the chain
    (tamper detection -- any rewritten byte anywhere in the chain breaks
    every signature computed after it), and plain expiry.

    Example::

        try:
            await auth.verify(Token("not-json"))
        except InvalidTokenError as exc:
            assert "malformed" in str(exc)
    """


class ScopeEscalationError(DelegationError):
    """Raised when a delegated scope set is not a strict subset of the parent's.

    "Strict" is enforced literally: a child requesting the *same* scopes as
    its parent is refused, not just a child requesting a superset. Every
    hop down the delegation tree must shed at least one capability -- that
    is what keeps a delegation chain from being usable as a way to launder
    a token's original authority forever.

    Example::

        try:
            await auth.delegate(parent, audience, ["read", "write", "admin"], ttl=60.0)
        except ScopeEscalationError:
            pass  # parent only held ["read", "write"]
    """


class DelegationTtlError(DelegationError):
    """Raised when a requested child TTL is non-positive or outlives its parent.

    A child's expiry (``now + ttl``) must land at or before the parent's own
    expiry -- a delegated capability can never outlive the authority it was
    carved from.

    Example::

        try:
            await auth.delegate(parent, audience, ["read"], ttl=10_000.0)
        except DelegationTtlError:
            pass  # parent expires in under 10,000 seconds
    """


class RevokedAncestorError(DelegationError):
    """Raised when any ancestor in a token's chain has been directly revoked.

    Raised by :meth:`DelegatableAuth.verify` (and therefore also by
    :meth:`DelegatableAuth.verify_presented_by`, which calls it) when the
    transitive parent walk finds a revoked entry anywhere between the root
    and the presented token -- including the presented token itself. This
    is the cascading-revocation contract: revoking one ancestor is enough,
    no descendant token's own digest ever needs a revocation entry.

    Example::

        await auth.revoke(root_token)
        try:
            await auth.verify(child_token)
        except RevokedAncestorError as exc:
            print(f"cascaded: {exc}")
    """


class AudienceMismatchError(DelegationError):
    """Raised when a token is presented by an agent other than its declared audience.

    A token minted via :meth:`DelegatableAuth.delegate` declares the
    ``AgentId`` it was minted for. :meth:`DelegatableAuth.verify_presented_by`
    checks the presenter against that declaration; :meth:`DelegatableAuth.verify`
    alone cannot, since the base ``Auth`` protocol does not pass a presenter.

    Example::

        try:
            await auth.verify_presented_by(worker_token, AgentId("attacker"))
        except AudienceMismatchError:
            pass  # worker_token was minted for "worker-1", not "attacker"
    """


def _canonical(obj: object) -> str:
    """Serialize *obj* to canonical (sorted-key, whitespace-free) JSON.

    Used for every HMAC input and every digest input in this module so that
    the exact same Python structure always serializes to the exact same
    bytes, regardless of insertion order -- required for the signature
    chain and the revocation digests to be reproducible on replay.

    Example::

        assert _canonical({"b": 1, "a": 2}) == '{"a":2,"b":1}'
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _hmac_hex(key: bytes, message: str) -> str:
    """Compute the hex HMAC-SHA256 of *message* under *key*.

    Example::

        sig = _hmac_hex(b"secret", '{"a":1}')
    """
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).hexdigest()


def _digest(token_str: str) -> str:
    """Compute the revocation-table key for a full token string.

    Example::

        key = _digest(str(token))
    """
    return hashlib.sha256(token_str.encode("utf-8")).hexdigest()


class DelegatableAuth:
    """Capability tokens as macaroon-style HMAC caveat chains.

    Implements the ``Auth`` protocol (``issue``/``verify``/``revoke``)
    exactly, and adds :meth:`delegate` and :meth:`verify_presented_by` on
    top. A single instance is meant to be shared by every agent in a
    scenario (mirroring how ``JwtAuth`` shares one signing secret) --
    ``delegate`` and ``verify`` are ordinary methods any holder of a valid
    token can call.

    Example::

        auth = DelegatableAuth(secret=b"secret")
        root = await auth.issue(AgentId("root"), ["read", "write"])
        child = await auth.delegate(root, AgentId("child"), ["read"], ttl=60.0)
        ctx = await auth.verify(child)
        assert ctx.scopes == ["read"]
    """

    def __init__(
        self,
        secret: bytes = _DEFAULT_SECRET,
        clock: float | None = None,
        default_root_ttl: float = _DEFAULT_ROOT_TTL,
    ) -> None:
        self._secret = secret
        self._clock = clock
        self._default_root_ttl = default_root_ttl
        self._revoked: dict[str, bool] = {}

    def _now(self) -> float:
        if self._clock is not None:
            return self._clock
        return time.time()

    def _parse_chain(self, token: Token) -> list[dict[str, Any]]:
        """Parse and structurally validate a token string into its caveat chain.

        Example::

            chain = auth._parse_chain(token)
            assert chain[0]["depth"] == 0
        """
        try:
            obj = json.loads(str(token))
        except (json.JSONDecodeError, TypeError) as exc:
            msg = "malformed token: not valid JSON"
            raise InvalidTokenError(msg) from exc
        if not isinstance(obj, dict):
            msg = "malformed token: expected a JSON object"
            raise InvalidTokenError(msg)
        raw_chain = cast("dict[str, Any]", obj).get("chain")
        if not isinstance(raw_chain, list) or not raw_chain:
            msg = "malformed token: missing or empty caveat chain"
            raise InvalidTokenError(msg)
        chain = cast("list[Any]", raw_chain)
        for entry in chain:
            if not isinstance(entry, dict) or "sig" not in entry:
                msg = "malformed token: caveat entry missing a signature"
                raise InvalidTokenError(msg)
        return cast("list[dict[str, Any]]", chain)

    def _reject_if_any_ancestor_revoked(self, chain: list[dict[str, Any]]) -> None:
        """Raise :class:`RevokedAncestorError` if any prefix of *chain* was directly revoked.

        A pure revocation-table lookup -- reconstructs each ancestor's exact
        original token string from the structure already embedded in
        *chain* and hashes it, needing no secret and no signature check.
        Shared by :meth:`delegate` (which cannot verify signatures without
        the root secret) and :meth:`verify` (which does both).

        Example::

            auth._reject_if_any_ancestor_revoked(chain)
        """
        for idx in range(len(chain)):
            ancestor_str = _canonical({"chain": chain[: idx + 1]})
            if self._revoked.get(_digest(ancestor_str), False):
                subject = chain[idx].get("subject")
                msg = f"ancestor at depth {idx} (subject={subject!r}) has been revoked"
                raise RevokedAncestorError(msg)

    async def issue(self, subject: AgentId, scopes: list[str]) -> Token:
        """Issue a root token for *subject* with *scopes*, signed with the root secret.

        The root caveat has no declared audience (``None``) and sits at
        chain depth 0. Its expiry ceils every capability later delegated
        from it, since no descendant's TTL may exceed its parent's.

        Example::

            token = await auth.issue(AgentId("orchestrator"), ["read", "write"])
        """
        now = self._now()
        caveat: dict[str, Any] = {
            "subject": str(subject),
            "scopes": list(scopes),
            "iat": now,
            "exp": now + self._default_root_ttl,
            "audience": None,
            "depth": 0,
        }
        sig = _hmac_hex(self._secret, _canonical(caveat))
        entry = {**caveat, "sig": sig}
        return Token(_canonical({"chain": [entry]}))

    async def delegate(
        self,
        parent_token: Token,
        audience: AgentId,
        scopes_subset: list[str],
        ttl: float,
    ) -> Token:
        """Mint a narrower, shorter-lived child token from *parent_token*.

        *scopes_subset* must be a strict subset of the parent's current
        scopes (:class:`ScopeEscalationError` otherwise) and *ttl* must be
        positive and land the child's expiry at or before the parent's own
        expiry (:class:`DelegationTtlError` otherwise, which also catches
        delegating from an already-expired parent -- its expiry can never
        be met by a positive-ttl child). Every ancestor's revocation status
        is checked locally against the revocation table
        (:class:`RevokedAncestorError` if any is revoked).

        Crucially, this method never reads the root secret and never
        verifies a signature -- unlike :meth:`verify`, it needs no
        cryptographic material beyond the parent token's own trailing
        signature (used only as the next HMAC *key*, never inspected).
        That is what lets any agent holding a valid-looking token delegate
        immediately, without a round trip to the issuer. A parent token
        that was tampered with or forged is not rejected here; it is
        rejected the next time anyone calls :meth:`verify` on a
        descendant, when the real root secret replays the whole chain.

        Example::

            child = await auth.delegate(root, AgentId("worker-1"), ["read"], ttl=60.0)
        """
        chain = self._parse_chain(parent_token)
        self._reject_if_any_ancestor_revoked(chain)
        parent_entry = chain[-1]
        parent_scopes = set(cast("list[str]", parent_entry["scopes"]))
        requested = set(scopes_subset)
        if not requested < parent_scopes:
            msg = (
                f"delegated scopes {sorted(requested)} must be a strict subset "
                f"of parent scopes {sorted(parent_scopes)}"
            )
            raise ScopeEscalationError(msg)
        if ttl <= 0:
            msg = f"ttl must be positive, got {ttl}"
            raise DelegationTtlError(msg)
        now = self._now()
        parent_exp = float(parent_entry["exp"])
        child_exp = now + ttl
        if child_exp > parent_exp:
            msg = (
                f"child ttl={ttl} would expire at {child_exp}, after the "
                f"parent's own expiry {parent_exp}"
            )
            raise DelegationTtlError(msg)
        caveat: dict[str, Any] = {
            "subject": str(audience),
            "scopes": list(scopes_subset),
            "iat": now,
            "exp": child_exp,
            "audience": str(audience),
            "depth": int(parent_entry["depth"]) + 1,
        }
        key = bytes.fromhex(str(parent_entry["sig"]))
        sig = _hmac_hex(key, _canonical(caveat))
        new_chain = [*chain, {**caveat, "sig": sig}]
        return Token(_canonical({"chain": new_chain}))

    async def verify(self, token: Token) -> AuthContext:
        """Verify a token by replaying its entire caveat chain.

        Walks the chain from the root, recomputing each level's signature
        (tamper anywhere breaks every signature after it), checking each
        ancestor's exact original token string against the revocation
        table, and checking each ancestor's expiry. Raises
        :class:`RevokedAncestorError` the moment any ancestor -- including
        the token itself -- is found directly revoked, and
        :class:`InvalidTokenError` for a bad signature, malformed token, or
        expiry. On success, returns the context for the *leaf* caveat.

        Example::

            ctx = await auth.verify(token)
            assert ctx.subject == AgentId("worker-1")
        """
        chain = self._parse_chain(token)
        self._reject_if_any_ancestor_revoked(chain)
        now = self._now()
        key = self._secret
        for idx, entry in enumerate(chain):
            caveat = {k: v for k, v in entry.items() if k != "sig"}
            carried_sig = str(entry["sig"])
            expected_sig = _hmac_hex(key, _canonical(caveat))
            if not hmac.compare_digest(carried_sig, expected_sig):
                msg = f"invalid signature at chain depth {idx}"
                raise InvalidTokenError(msg)
            if float(caveat["exp"]) < now:
                msg = f"ancestor at depth {idx} (subject={caveat['subject']!r}) has expired"
                raise InvalidTokenError(msg)
            key = bytes.fromhex(carried_sig)
        leaf = chain[-1]
        return AuthContext(
            subject=AgentId(str(leaf["subject"])),
            scopes=list(cast("list[str]", leaf["scopes"])),
            issued_at=float(leaf["iat"]),
            expires_at=float(leaf["exp"]),
        )

    async def verify_presented_by(self, token: Token, presenter: AgentId) -> AuthContext:
        """Verify *token* and additionally check it was presented by its declared audience.

        Performs the full :meth:`verify` chain walk, then compares
        *presenter* against the leaf caveat's declared ``audience``. A root
        token (``audience is None``) falls back to comparing *presenter*
        against its own subject. Raises :class:`AudienceMismatchError` on a
        mismatch.

        Example::

            ctx = await auth.verify_presented_by(child, AgentId("worker-1"))
        """
        ctx = await self.verify(token)
        chain = self._parse_chain(token)
        declared_audience = chain[-1].get("audience")
        expected = str(declared_audience) if declared_audience is not None else str(ctx.subject)
        if str(presenter) != expected:
            msg = f"token declares audience {expected!r} but was presented by {presenter!r}"
            raise AudienceMismatchError(msg)
        return ctx

    async def revoke(self, token: Token) -> None:
        """Directly revoke *token*.

        Only records *this exact token's* digest. Descendants are never
        touched -- they are invalidated transitively the next time
        :meth:`verify` walks a chain that passes through this digest.

        Example::

            await auth.revoke(root_token)
        """
        self._revoked[_digest(str(token))] = True
