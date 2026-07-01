# SPDX-License-Identifier: Apache-2.0
"""Delegatable capability-token auth plugin with cascading revocation.

A :class:`DelegatableAuth` issues root tokens bound to a subject's
:class:`~nest_plugins_reference.policy.PolicyManifest` and allows any token
holder to *delegate* a strict subset of their scopes to a third party.
Revocation of any node in a delegation chain automatically invalidates every
descendant — no out-of-band notification required.

Threat model: this is a reference, in-memory Auth plugin for deterministic
Nanda Town scenarios. It protects against unsigned/tampered manifests, scope
widening, equal-authority delegation, child TTL extension, stale descendants
after local revocation, audience confusion, and token payload/signature
tampering. Revocation and issued-token knowledge are process-local; distributed
revocation/state replication are intentionally out of scope for this plugin.

Token wire format: ``payload_json|sig_hex``

The payload is ``json.dumps({...}, sort_keys=True)``.  The token id (``tid``)
is ``sha256(payload_json.encode()).hexdigest()``.  Root-token signatures are
``HMAC(secret, payload_json.encode())``.  Each delegated-child signature is
``HMAC(parent_sig.encode(), child_payload_json.encode())``, chaining the
signature material so revocation propagates cryptographically.

Example::

    from nest_core.types import AgentId
    from nest_plugins_reference.policy import Budget, PolicyManifest
    from nest_plugins_reference.policy.manifest import sign_manifest
    from nest_plugins_reference.identity.ed25519_rotating import Ed25519RotatingIdentity
    from nest_plugins_reference.auth.delegatable import DelegatableAuth

    ident = Ed25519RotatingIdentity(AgentId("root"), seed=b"seed")
    manifest = PolicyManifest(
        agent_id=AgentId("root"), tools=["buy", "sell"], budget=Budget(cap=500),
    )
    signed = sign_manifest(ident, manifest)

    auth = DelegatableAuth(manifests={AgentId("root"): signed}, clock=0.0)
    import asyncio
    root = asyncio.run(auth.issue(AgentId("root"), ["tool:buy", "tool:sell"]))
    child = asyncio.run(auth.delegate(root, AgentId("delegatee"), ["tool:buy"], ttl=300))
    ctx = asyncio.run(auth.verify(child, presenter=AgentId("delegatee")))
    assert "tool:buy" in ctx.scopes
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from collections.abc import Mapping

from nest_core.types import AgentId, AuthContext, Token

from nest_plugins_reference.policy.decide import PolicyState, decide
from nest_plugins_reference.policy.manifest import ManifestSigner, PolicyManifest, verify_manifest
from nest_plugins_reference.policy.scopes import scope_to_op

# ---------------------------------------------------------------------------
# Typed errors (all subclass ValueError, matching repo convention)
# ---------------------------------------------------------------------------


class ScopeEscalationError(ValueError):
    """Raised when a delegate request is not narrower than the parent token.

    Example::

        raise ScopeEscalationError(["tool:admin"])
    """

    def __init__(self, offending: list[str]) -> None:
        self.offending = offending
        super().__init__(f"scope escalation: {offending!r} not a strict subset of parent scopes")


class TtlExceededError(ValueError):
    """Raised when the requested child TTL would expire after the parent token.

    Example::

        raise TtlExceededError(child_exp=4000, parent_exp=3600)
    """

    def __init__(self, child_exp: float, parent_exp: float) -> None:
        self.child_exp = child_exp
        self.parent_exp = parent_exp
        super().__init__(f"child exp {child_exp} exceeds parent exp {parent_exp}")


class RevokedAncestorError(ValueError):
    """Raised when verifying a token whose ancestor (or itself) was revoked.

    Example::

        raise RevokedAncestorError("abc123")
    """

    def __init__(self, tid: str) -> None:
        self.tid = tid
        super().__init__(f"token or ancestor {tid!r} has been revoked")


class AudienceMismatchError(ValueError):
    """Raised when the presenter does not match the token's audience.

    Example::

        raise AudienceMismatchError(expected="alice", got="bob")
    """

    def __init__(self, expected: str, got: str) -> None:
        self.expected = expected
        self.got = got
        super().__init__(f"audience mismatch: expected {expected!r}, got {got!r}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _tid(payload_json: str) -> str:
    """Return the token id: sha256 of the UTF-8 encoded payload JSON.

    Example::

        tid = _tid('{"sub": "a1"}')
    """
    return hashlib.sha256(payload_json.encode()).hexdigest()


def _hmac(key: bytes, msg: str) -> str:
    """Return HMAC-SHA256 of *msg* (UTF-8 encoded) under *key* as hex.

    Example::

        sig = _hmac(b"secret", '{"sub": "a1"}')
    """
    return hmac.new(key, msg.encode(), hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# DelegatableAuth
# ---------------------------------------------------------------------------


class DelegatableAuth:
    """Auth plugin implementing delegatable capability tokens with cascading revocation.

    Root tokens are issued with scopes clamped to the subject's
    :class:`~nest_plugins_reference.policy.PolicyManifest`.  Any token holder
    may delegate a *strict subset* of their scopes to another agent, producing
    a child token whose signature is *anchored* to the parent's.  Revoking any
    token invalidates every descendant automatically because descendants carry
    the ancestor ``tid`` in their ``chain`` list.

    This reference implementation keeps issued token metadata and revocations
    in memory. It is meant to make delegation invariants testable inside the
    simulator, not to provide distributed revocation storage.

    Example::

        auth = DelegatableAuth(clock=0.0)
        root = asyncio.run(auth.issue(AgentId("a1"), ["tool:buy", "tool:sell"]))
        child = asyncio.run(auth.delegate(root, AgentId("a2"), ["tool:buy"], ttl=60))
        ctx = asyncio.run(auth.verify(child, presenter=AgentId("a2")))
    """

    def __init__(
        self,
        manifests: Mapping[AgentId, PolicyManifest] | None = None,
        identities: Mapping[AgentId, ManifestSigner] | None = None,
        secret: bytes = b"nest-delegatable-secret",
        clock: float | None = None,
    ) -> None:
        self._manifests: dict[AgentId, PolicyManifest] = dict(manifests or {})
        self._identities: dict[AgentId, ManifestSigner] = dict(identities or {})
        self._secret = secret
        self._clock = clock
        # token-id -> hex HMAC sig (needed for chain recomputation on verify)
        self._sigs: dict[str, str] = {}
        self._payloads: dict[str, str] = {}
        self._revoked: set[str] = set()

    def set_clock(self, t: float) -> None:
        """Override the injected clock value (for testing time-sensitive behaviour).

        Example::

            auth.set_clock(4000.0)
        """
        self._clock = t

    def _now(self) -> float:
        """Return the current time (injected clock or wall clock).

        Example::

            t = auth._now()
        """
        if self._clock is not None:
            return self._clock
        return time.time()

    # ------------------------------------------------------------------
    # Auth protocol
    # ------------------------------------------------------------------

    async def issue(self, subject: AgentId, scopes: list[str]) -> Token:
        """Issue a root token for *subject* with scopes clamped to its manifest.

        Scopes not permitted by the subject's manifest are silently dropped.
        If the subject has no manifest, an empty-scope token is issued.

        Example::

            token = await auth.issue(AgentId("a1"), ["tool:buy", "tool:admin"])
        """
        manifest = self._manifest_for(subject)
        allowed_scopes = _clamp_scopes(scopes, manifest)

        now = self._now()
        payload = json.dumps(
            {
                "aud": str(subject),
                "chain": [],
                "exp": now + 3600,
                "iat": now,
                "scopes": allowed_scopes,
                "sub": str(subject),
            },
            sort_keys=True,
        )
        sig = _hmac(self._secret, payload)
        tid = _tid(payload)
        self._sigs[tid] = sig
        self._payloads[tid] = payload
        return Token(f"{payload}|{sig}")

    async def verify(self, token: Token, presenter: AgentId | None = None) -> AuthContext:
        """Verify *token* and return its :class:`~nest_core.types.AuthContext`.

        Raises :class:`ValueError` for expired or tampered tokens,
        :class:`RevokedAncestorError` if the token or any ancestor was revoked,
        and :class:`AudienceMismatchError` if *presenter* does not match the
        token's audience.

        Example::

            ctx = await auth.verify(token, presenter=AgentId("a2"))
        """
        raw = str(token)
        parts = raw.rsplit("|", 1)
        if len(parts) != 2:
            msg = "invalid token format"
            raise ValueError(msg)
        payload_json, sig = parts

        data = json.loads(payload_json)
        chain: list[str] = data["chain"]
        tid = _tid(payload_json)
        stored_sig = self._sigs.get(tid)
        if stored_sig is None:
            msg = f"unknown token {tid!r}"
            raise ValueError(msg)
        if not hmac.compare_digest(sig, stored_sig):
            msg = "invalid signature"
            raise ValueError(msg)

        # Recompute expected signature and re-check the delegation caveats.
        # The parent signature is visible in the parent token, so signature
        # verification alone would let a holder handcraft a broader child.
        if not chain:
            expected_sig = _hmac(self._secret, payload_json)
        else:
            parent_tid = chain[-1]
            parent_sig = self._sigs.get(parent_tid)
            parent_payload_json = self._payloads.get(parent_tid)
            if parent_sig is None:
                msg = f"unknown parent token {parent_tid!r}"
                raise ValueError(msg)
            if parent_payload_json is None:
                msg = f"unknown parent payload {parent_tid!r}"
                raise ValueError(msg)
            parent_data = json.loads(parent_payload_json)
            expected_chain = parent_data["chain"] + [parent_tid]
            if chain != expected_chain:
                msg = "invalid delegation chain"
                raise ValueError(msg)
            child_scope_set = set(data["scopes"])
            parent_scope_set = set(parent_data["scopes"])
            offending = [s for s in data["scopes"] if s not in parent_scope_set]
            if offending:
                raise ScopeEscalationError(offending)
            if not child_scope_set < parent_scope_set:
                raise ScopeEscalationError(list(data["scopes"]))
            if data["exp"] > parent_data["exp"]:
                raise TtlExceededError(child_exp=data["exp"], parent_exp=parent_data["exp"])
            expected_sig = _hmac(parent_sig.encode(), payload_json)

        if not hmac.compare_digest(sig, expected_sig):
            msg = "invalid signature"
            raise ValueError(msg)

        # Expiry check
        if data["exp"] < self._now():
            msg = "token expired"
            raise ValueError(msg)

        # Transitive revocation
        if tid in self._revoked:
            raise RevokedAncestorError(tid)
        for ancestor_tid in chain:
            if ancestor_tid in self._revoked:
                raise RevokedAncestorError(ancestor_tid)

        # Audience check
        if presenter is not None and str(presenter) != data["aud"]:
            raise AudienceMismatchError(expected=data["aud"], got=str(presenter))

        return AuthContext(
            subject=AgentId(data["aud"]),
            scopes=data["scopes"],
            issued_at=data["iat"],
            expires_at=data["exp"],
        )

    async def revoke(self, token: Token) -> None:
        """Revoke *token*, invalidating it and all descendants.

        Cascade is automatic: descendants carry this token's ``tid`` in their
        ``chain`` list, so :meth:`verify` raises :class:`RevokedAncestorError`
        for them too.

        Example::

            await auth.revoke(root_token)
        """
        raw = str(token)
        parts = raw.rsplit("|", 1)
        if len(parts) != 2:
            msg = "invalid token format"
            raise ValueError(msg)
        payload_json = parts[0]
        tid = _tid(payload_json)
        self._revoked.add(tid)

    # ------------------------------------------------------------------
    # Delegation surface
    # ------------------------------------------------------------------

    async def delegate(
        self,
        parent_token: Token,
        audience: AgentId,
        scopes_subset: list[str],
        ttl: float,
    ) -> Token:
        """Mint a child token delegating *scopes_subset* to *audience*.

        The child's scopes must be a strict subset of the parent's scopes; the
        child's expiry must not exceed the parent's.  The child's HMAC key is
        *anchored* to the parent's signature so revocation propagates automatically.

        Raises:
            Any error from :meth:`verify` if the parent is invalid/revoked/expired.
            :class:`ScopeEscalationError` if *scopes_subset* is not a strict
                subset of the parent.
            :class:`TtlExceededError` if ``now + ttl > parent.exp``.

        Example::

            child = await auth.delegate(root, AgentId("a2"), ["tool:buy"], ttl=60)
        """
        # Verify the parent (propagates revocation/expiry errors)
        await self.verify(parent_token)

        # Parse parent
        raw = str(parent_token)
        parent_payload_json = raw.rsplit("|", 1)[0]
        parent_data = json.loads(parent_payload_json)
        parent_scopes: list[str] = parent_data["scopes"]
        parent_exp: float = parent_data["exp"]
        parent_chain: list[str] = parent_data["chain"]
        parent_tid = _tid(parent_payload_json)

        # Scope escalation check
        parent_scope_set = set(parent_scopes)
        requested_scope_set = set(scopes_subset)
        offending = [s for s in scopes_subset if s not in parent_scope_set]
        if offending:
            raise ScopeEscalationError(offending)
        if not requested_scope_set < parent_scope_set:
            raise ScopeEscalationError(list(scopes_subset))

        # TTL check
        now = self._now()
        child_exp = now + ttl
        if child_exp > parent_exp:
            raise TtlExceededError(child_exp=child_exp, parent_exp=parent_exp)

        # Build child payload (preserve input order for determinism)
        child_payload = json.dumps(
            {
                "aud": str(audience),
                "chain": parent_chain + [parent_tid],
                "exp": child_exp,
                "iat": now,
                "scopes": list(scopes_subset),
                "sub": str(audience),
            },
            sort_keys=True,
        )

        parent_sig = self._sigs[parent_tid]
        child_sig = _hmac(parent_sig.encode(), child_payload)
        child_tid = _tid(child_payload)
        self._sigs[child_tid] = child_sig
        self._payloads[child_tid] = child_payload
        return Token(f"{child_payload}|{child_sig}")

    def _manifest_for(self, subject: AgentId) -> PolicyManifest | None:
        """Return a verified manifest for *subject*, or ``None`` to deny all.

        If an identity verifier is supplied for the subject, the manifest's
        signature must verify at the current logical clock. Without an identity
        verifier, the constructor treats signed manifests as pre-verified by the
        scenario factory and rejects unsigned manifests.
        """
        manifest = self._manifests.get(subject)
        if manifest is None or manifest.signature is None:
            return None
        identity = self._identities.get(subject)
        if identity is None:
            return manifest
        if not verify_manifest(identity, manifest, as_of=self._now()):
            return None
        return manifest


# ---------------------------------------------------------------------------
# Scope clamping helper
# ---------------------------------------------------------------------------


def _clamp_scopes(requested: list[str], manifest: PolicyManifest | None) -> list[str]:
    """Return only those scopes in *requested* that the manifest permits.

    If *manifest* is ``None``, returns an empty list (deny-all root).  Order is
    preserved and duplicates are removed (first occurrence wins).

    Example::

        manifest = PolicyManifest(agent_id=AgentId("a1"), tools=["buy"])
        allowed = _clamp_scopes(["tool:buy", "tool:admin", "tool:buy"], manifest)
        assert allowed == ["tool:buy"]
    """
    if manifest is None:
        return []

    seen: set[str] = set()
    result: list[str] = []
    for scope in requested:
        if scope in seen:
            continue
        parsed = scope_to_op(scope)
        if parsed is None:
            seen.add(scope)
            continue
        op, args = parsed
        d = decide(manifest, op, args, PolicyState())
        if d.allowed:
            result.append(scope)
        seen.add(scope)
    return result
