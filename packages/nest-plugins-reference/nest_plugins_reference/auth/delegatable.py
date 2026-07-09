# SPDX-License-Identifier: Apache-2.0
"""Delegatable capability tokens with cascading revocation (macaroon-style).

The default :class:`~nest_plugins_reference.auth.jwt_auth.JwtAuth` plugin can
*issue* and *revoke* a token, but it has no notion of one agent minting a
narrower sub-token for another agent, and its revocation set is keyed by the
exact token string — revoking a parent does nothing to its children.

``DelegatableAuth`` closes that gap with the macaroon construction (Birgisson
et al., 2014). A token carries an ordered *chain* of caveats (root → leaf).
Each link is bound to the previous one with an HMAC keyed by the **parent's
signature**, so:

* Delegation needs no issuer round-trip: any holder of a valid parent token can
  mint a child by appending a caveat and re-chaining the MAC. The root secret
  never leaves the issuer.
* Restriction is enforced at *verification*, not mint time. A holder can append
  any caveat (they know the parent signature, which is the child's MAC key), so
  ``verify`` re-checks that every child only **narrows** its parent: scopes must
  be a subset and expiry must not extend. A widened caveat is cryptographically
  well-formed but rejected on verify — this is what defeats scope escalation.
* Revocation cascades by construction: every link carries a ``tid`` and every
  ``tid`` in the chain is checked against the revocation set on verify. Revoke a
  parent's ``tid`` and every descendant fails at the next verify, with no
  per-child bookkeeping.

Determinism (Tier 1): token ids are derived by SHA-256 over the caveat's own
fields — no RNG, no wall clock. Timestamps come from an injected logical clock
(:meth:`set_clock`); ``time.time()`` is only the fallback for out-of-simulation
use, exactly as ``JwtAuth`` does it.

All raised errors subclass :class:`ValueError`, so existing callers that catch
``ValueError`` around ``verify`` keep working unchanged.

Example::

    auth = DelegatableAuth(secret=b"root-secret", clock=0.0)
    root = await auth.issue(AgentId("orchestrator"), ["tool:read", "tool:write"])
    child = await auth.delegate(
        root, audience=AgentId("worker"), scopes_subset=["tool:read"], ttl=600.0
    )
    ctx = await auth.verify(child, presenter=AgentId("worker"))
    assert ctx.scopes == ["tool:read"]
    await auth.revoke(root)          # revoke the parent...
    # ...and the child no longer verifies:
    # await auth.verify(child)  ->  RevokedAncestorError
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any, cast

from nest_core.types import AgentId, AuthContext, Token


class DelegationError(ValueError):
    """Base class for all delegation/verification failures.

    Subclasses :class:`ValueError` so callers that already guard ``verify`` with
    ``except ValueError`` continue to catch every delegation failure.

    Example::

        try:
            await auth.verify(bad_token)
        except DelegationError as exc:
            print("rejected:", exc)
    """


class InvalidTokenError(DelegationError):
    """The token is malformed or its MAC chain does not recompute.

    Example::

        # A token whose bytes were tampered with raises InvalidTokenError.
    """


class ScopeEscalationError(DelegationError):
    """A caveat requests scopes broader than the parent grants.

    Raised at ``delegate`` time (honest minting) and again at ``verify`` time
    (a forged wide caveat that recomputes its MAC correctly).

    Example::

        # delegate(root[read], scopes_subset=["write"]) -> ScopeEscalationError
    """


class RevokedAncestorError(DelegationError):
    """Some token in the chain (this token or an ancestor) has been revoked.

    Example::

        await auth.revoke(parent)
        # await auth.verify(child) -> RevokedAncestorError
    """


class AudienceMismatchError(DelegationError):
    """The presenting agent is not the token's declared audience.

    Example::

        # child is bound to AgentId("worker"); presented by AgentId("intruder")
        # await auth.verify(child, presenter=AgentId("intruder"))
        #   -> AudienceMismatchError
    """


class ExpiredTokenError(DelegationError):
    """The token's leaf caveat has expired relative to the current clock.

    Example::

        # auth.set_clock(token_exp + 1); await auth.verify(token)
        #   -> ExpiredTokenError
    """


def _canonical(caveat: dict[str, Any]) -> bytes:
    """Return the canonical JSON encoding of a caveat for MAC input.

    Keys are sorted and separators are tight so the encoding is byte-stable
    across runs and Python versions.

    Example::

        raw = _canonical({"tid": "abc", "scopes": ["read"]})
    """
    return json.dumps(caveat, sort_keys=True, separators=(",", ":")).encode()


def _derive_tid(
    parent_tid: str | None,
    subject: str,
    scopes: list[str],
    issued_at: float,
    expires_at: float,
    audience: str | None,
) -> str:
    """Derive a deterministic token id from a caveat's own fields.

    No RNG and no wall clock: the same caveat always yields the same id, so
    traces replay byte-for-byte. ``issued_at`` (a logical tick) plus the parent
    id disambiguate otherwise-identical delegations.

    Example::

        tid = _derive_tid(None, "orchestrator", ["read"], 0.0, 3600.0, "orchestrator")
    """
    material = "|".join(
        [
            str(parent_tid),
            subject,
            ",".join(sorted(scopes)),
            repr(issued_at),
            repr(expires_at),
            str(audience),
        ]
    )
    return hashlib.sha256(material.encode()).hexdigest()[:16]


class DelegatableAuth:
    """Macaroon-style delegatable capability tokens with cascading revocation.

    Satisfies the ``Auth`` protocol (``issue`` / ``verify`` / ``revoke``) and
    adds :meth:`delegate`. A single instance is shared by every agent in a
    scenario: it holds the root ``secret`` used to anchor the MAC chain and the
    revocation set consulted on every ``verify``.

    Example::

        auth = DelegatableAuth(secret=b"secret", clock=0.0)
        root = await auth.issue(AgentId("a1"), ["read", "write"])
        child = await auth.delegate(root, AgentId("a2"), ["read"], ttl=60.0)
        assert (await auth.verify(child)).scopes == ["read"]
    """

    def __init__(
        self,
        agent_id: AgentId | None = None,
        secret: bytes = b"nest-delegatable-secret",
        clock: float | None = None,
        default_ttl: float = 3600.0,
        revoked: set[str] | None = None,
    ) -> None:
        self._agent_id = agent_id
        self._secret = secret
        self._clock = clock
        self._default_ttl = default_ttl
        self._revoked: set[str] = revoked if revoked is not None else set()

    # -- clock -------------------------------------------------------------

    def set_clock(self, tick: float) -> None:
        """Pin the logical clock so issuance/expiry are deterministic.

        The scenario driver calls this with ``ctx.time`` before every auth
        operation, exactly as the identity-rotation scenario pins its identity
        plugin's clock. Without it the plugin falls back to ``time.time()``.

        Example::

            auth.set_clock(12.0)
        """
        self._clock = tick

    def _now(self) -> float:
        if self._clock is not None:
            return self._clock
        return time.time()

    # -- MAC chain ---------------------------------------------------------

    def _chain_sig(self, chain: list[dict[str, Any]]) -> str:
        """Compute the macaroon MAC over the whole caveat chain.

        The root caveat is keyed by ``secret``; every subsequent caveat is keyed
        by the running MAC, so the final signature binds the entire chain and
        the parent signature is the child's signing key.

        Example::

            sig = auth._chain_sig([root_caveat, child_caveat])
        """
        key = self._secret
        for caveat in chain:
            key = hmac.new(key, _canonical(caveat), hashlib.sha256).digest()
        return key.hex()

    def _encode(self, chain: list[dict[str, Any]]) -> Token:
        """Serialize a chain + its MAC into an inspectable token string.

        Example::

            token = auth._encode([root_caveat])
        """
        body = json.dumps({"chain": chain}, sort_keys=True, separators=(",", ":"))
        return Token(f"{body}|sig:{self._chain_sig(chain)}")

    def _decode(self, token: Token) -> tuple[list[dict[str, Any]], str]:
        """Parse a token into its caveat chain and transmitted MAC.

        Raises:
            InvalidTokenError: if the envelope is malformed.

        Example::

            chain, sig = auth._decode(token)
        """
        raw = str(token)
        head, _, sig = raw.rpartition("|sig:")
        if not sig or not head:
            msg = "Malformed delegatable token: missing MAC"
            raise InvalidTokenError(msg)
        try:
            data = json.loads(head)
            raw_chain = data["chain"]
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            msg = f"Malformed delegatable token body: {exc}"
            raise InvalidTokenError(msg) from exc
        if not isinstance(raw_chain, list) or not raw_chain:
            msg = "Malformed delegatable token: empty caveat chain"
            raise InvalidTokenError(msg)
        return cast("list[dict[str, Any]]", raw_chain), sig

    # -- Auth protocol -----------------------------------------------------

    async def issue(self, subject: AgentId, scopes: list[str]) -> Token:
        """Issue a root capability token bound to ``subject``.

        Example::

            root = await auth.issue(AgentId("orchestrator"), ["tool:read"])
        """
        now = self._now()
        expires_at = now + self._default_ttl
        sorted_scopes = sorted(scopes)
        caveat = {
            "tid": _derive_tid(None, str(subject), sorted_scopes, now, expires_at, str(subject)),
            "parent_tid": None,
            "sub": str(subject),
            "aud": str(subject),
            "scopes": sorted_scopes,
            "iat": now,
            "exp": expires_at,
        }
        return self._encode([caveat])

    async def delegate(
        self,
        parent_token: Token,
        audience: AgentId,
        scopes_subset: list[str],
        ttl: float,
    ) -> Token:
        """Mint a narrower child token for ``audience`` off ``parent_token``.

        The child's scopes must be a subset of the parent's, and its expiry is
        clamped to at most the parent's. Requires no issuer round-trip; the
        parent's signature keys the new caveat.

        Args:
            parent_token: A structurally valid token held by the delegator.
            audience: The agent the child token is bound to.
            scopes_subset: Scopes to grant; must be ``⊆`` the parent's scopes.
            ttl: Requested lifetime; the effective expiry is
                ``min(now + ttl, parent.exp)``.

        Raises:
            InvalidTokenError: parent MAC does not recompute.
            ScopeEscalationError: ``scopes_subset`` exceeds the parent's scopes.

        Example::

            child = await auth.delegate(
                root, AgentId("worker"), ["tool:read"], ttl=600.0
            )
        """
        chain, sig = self._decode(parent_token)
        if not hmac.compare_digest(sig, self._chain_sig(chain)):
            msg = "Parent token signature does not verify"
            raise InvalidTokenError(msg)

        parent = chain[-1]
        parent_scopes = set(parent["scopes"])
        requested = set(scopes_subset)
        if not requested.issubset(parent_scopes):
            extra = sorted(requested - parent_scopes)
            msg = f"Scope escalation: {extra} not held by parent {sorted(parent_scopes)}"
            raise ScopeEscalationError(msg)

        now = self._now()
        expires_at = min(now + ttl, float(parent["exp"]))
        sorted_scopes = sorted(requested)
        caveat = {
            "tid": _derive_tid(
                parent["tid"], str(audience), sorted_scopes, now, expires_at, str(audience)
            ),
            "parent_tid": parent["tid"],
            "sub": str(audience),
            "aud": str(audience),
            "scopes": sorted_scopes,
            "iat": now,
            "exp": expires_at,
        }
        return self._encode([*chain, caveat])

    async def verify(self, token: Token, presenter: AgentId | None = None) -> AuthContext:
        """Verify a token and return the leaf caveat's auth context.

        Enforces, in order: MAC-chain integrity, per-link revocation (any
        revoked ``tid`` in the chain fails), monotonic narrowing (each child's
        scopes ``⊆`` parent's and ``exp`` not extended, ``parent_tid`` linked),
        leaf expiry, and — when ``presenter`` is supplied — audience binding.

        The ``presenter`` parameter is optional, so this method still satisfies
        the ``Auth`` protocol; omitting it skips only the audience check.

        Raises:
            InvalidTokenError: malformed token or bad MAC / broken chain link.
            RevokedAncestorError: this token or an ancestor was revoked.
            ScopeEscalationError: a child widens its parent's scopes.
            ExpiredTokenError: the leaf caveat has expired.
            AudienceMismatchError: ``presenter`` is not the leaf's audience.

        Example::

            ctx = await auth.verify(child, presenter=AgentId("worker"))
            assert ctx.subject == AgentId("worker")
        """
        chain, sig = self._decode(token)
        if not hmac.compare_digest(sig, self._chain_sig(chain)):
            msg = "Token signature does not verify"
            raise InvalidTokenError(msg)

        for i, caveat in enumerate(chain):
            if caveat["tid"] in self._revoked:
                who = "token" if i == len(chain) - 1 else "ancestor"
                msg = f"Revoked {who} in chain: tid={caveat['tid']}"
                raise RevokedAncestorError(msg)
            if i == 0:
                continue
            parent = chain[i - 1]
            if caveat.get("parent_tid") != parent["tid"]:
                msg = "Broken delegation chain: parent_tid mismatch"
                raise InvalidTokenError(msg)
            if not set(caveat["scopes"]).issubset(set(parent["scopes"])):
                extra = sorted(set(caveat["scopes"]) - set(parent["scopes"]))
                msg = f"Scope escalation in chain: {extra} not held by parent"
                raise ScopeEscalationError(msg)
            if float(caveat["exp"]) > float(parent["exp"]):
                msg = "Child token outlives its parent"
                raise ExpiredTokenError(msg)

        leaf = chain[-1]
        if float(leaf["exp"]) < self._now():
            msg = f"Token expired at {leaf['exp']} (now {self._now()})"
            raise ExpiredTokenError(msg)

        if presenter is not None and leaf["aud"] is not None and str(presenter) != leaf["aud"]:
            msg = f"Audience mismatch: token bound to {leaf['aud']}, presented by {presenter}"
            raise AudienceMismatchError(msg)

        return AuthContext(
            subject=AgentId(leaf["sub"]),
            scopes=list(leaf["scopes"]),
            issued_at=leaf["iat"],
            expires_at=leaf["exp"],
        )

    async def revoke(self, token: Token) -> None:
        """Revoke ``token`` by its leaf id; all descendants fail transitively.

        Because every descendant carries this token's ``tid`` in its chain,
        revoking here invalidates the whole subtree at the next ``verify`` — no
        per-child revocation entries are needed.

        Example::

            await auth.revoke(parent)   # every child of parent now fails verify
        """
        chain, _ = self._decode(token)
        self._revoked.add(chain[-1]["tid"])
