# SPDX-License-Identifier: Apache-2.0
"""Delegatable capability tokens with cascading revocation via prefix-trie matching.

The reference ``jwt_auth`` plugin issues flat HMAC-signed tokens with no
delegation: an agent cannot mint a scoped-down child token for another agent
without going back to the central issuer, and revoking the parent does **not**
invalidate the child.  Both gaps make it impossible to model the common pattern
"agent A holds a root token, mints a 10-minute sub-token for agent B, then
revokes A's token and expects B's to stop working."

This plugin fixes both by combining **HMAC nonce chaining** with a
**prefix-trie revocation index**:

* **HMAC chain** — each delegation derives the child's nonce by hashing over
  the full ancestor chain plus the child payload:
  ``nonce = HMAC(secret, concat(parent_payloads..., child_payload))``.
  A verifier recomputes the chain from the secret and the ancestor payloads
  embedded in the token, so no per-token issuer state is needed beyond the
  secret.
* **Prefix-trie revocation** — each token carries an explicit ``path``
  (``[root_handle, child_handle, ...]``).  Revoking a path prefix (e.g.
  ``[root_A, child_B]``) instantly invalidates every descendant without a
  separate revocation entry per token: a single prefix match catches the
  entire subtree.
* **Separated concerns** — the HMAC chain proves *authenticity* while the
  path-prefix check proves *non-revocation*.  They compose with a logical AND
  and can be cached independently.

Three attacks this plugin defeats (and ``jwt_auth`` does not):

1. **Scope escalation** — ``delegate()`` enforces ``child_scopes ⊆ parent_scopes``
   and raises :class:`ScopeEscalationError`.
2. **Stale parent** — a child token whose parent was revoked or expired fails
   verification because ``verify()`` checks every ancestor's revocation state
   via prefix matching.
3. **Audience confusion** — a token minted for audience ``B`` is presented by
   agent ``A``.  ``verify()`` checks the presenter against the token's ``aud``
   claim and raises :class:`AudienceMismatchError`.

Example::

    auth = DelegatableAuth(secret=b"root-secret")
    root = await auth.issue(AgentId("admin"), ["read", "write", "delete"])
    child = await auth.delegate(
        root, audience=AgentId("worker"),
        scopes=["read"], ttl=100,
    )
    ctx = await auth.verify(child, presenter=AgentId("worker"))
    assert ctx.scopes == ["read"]

    # Revoke the root — child now fails
    await auth.revoke(root)
    with pytest.raises(RevokedAncestorError):
        await auth.verify(child, presenter=AgentId("worker"))
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any

from nest_core.types import AgentId, AuthContext, Token

# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------


class ScopeEscalationError(ValueError):
    """Raised when a delegate tries to grant a scope the parent does not hold.

    Example::

        with pytest.raises(ScopeEscalationError):
            await auth.delegate(root, audience=AgentId("b"), scopes=["admin"])
    """


class RevokedAncestorError(ValueError):
    """Raised when a token's ancestor chain contains a revoked path prefix.

    Example::

        with pytest.raises(RevokedAncestorError):
            await auth.verify(child, presenter=AgentId("b"))
    """


class AudienceMismatchError(ValueError):
    """Raised when a token is presented by an agent other than its audience.

    Example::

        with pytest.raises(AudienceMismatchError):
            await auth.verify(token, presenter=AgentId("eve"))
    """


class InvalidDelegationChainError(ValueError):
    """Raised when the HMAC nonce chain does not verify.

    Example::

        with pytest.raises(InvalidDelegationChainError):
            await auth.verify(tampered_token, presenter=AgentId("b"))
    """


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


_DELIMITER = "|"
_ANCESTORS_KEY = "_ancestors"


def _encode_b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _decode_b64(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _strip_ancestors(payload: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in payload.items() if k != _ANCESTORS_KEY}


def _chain_nonce(
    secret: bytes,
    ancestor_payloads: list[dict[str, Any]],
    leaf_payload: dict[str, Any],
    path: list[str],
) -> str:
    """Compute the HMAC nonce over the full chain including path.

    Concatenates the canonical forms of all ancestor payloads (from root to
    parent), the canonical form of the leaf payload, and the canonical JSON
    of the path.  Binding the path into the HMAC prevents an attacker from
    rewriting the path prefix to bypass revocation.
    """
    chain_bytes = (
        b"".join(_canonical(a) for a in ancestor_payloads)
        + _canonical(leaf_payload)
        + json.dumps(path, sort_keys=True, separators=(",", ":")).encode()
    )
    return hmac.new(secret, chain_bytes, hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# Token dataclass
# ---------------------------------------------------------------------------


@dataclass
class _DelegationToken:
    """Internal parsed representation of a delegatable token.

    Serialized format: ``<path_hex>|<payload_b64>|<nonce_hex>``
    """

    path: list[str]
    payload: dict[str, Any]
    nonce: str

    def serialize(self) -> str:
        path_hex = json.dumps(self.path, separators=(",", ":")).encode().hex()
        payload_b64 = _encode_b64(_canonical(self.payload))
        return f"{path_hex}{_DELIMITER}{payload_b64}{_DELIMITER}{self.nonce}"

    @classmethod
    def deserialize(cls, raw: str) -> _DelegationToken:
        parts = raw.split(_DELIMITER)
        if len(parts) != 3:
            msg = f"Invalid token format: expected 3 parts, got {len(parts)}"
            raise ValueError(msg)
        path_hex, payload_b64, nonce = parts
        path: list[str] = json.loads(bytes.fromhex(path_hex).decode())
        payload: dict[str, Any] = json.loads(_decode_b64(payload_b64))
        return cls(path=path, payload=payload, nonce=nonce)

    @property
    def path_prefixes(self) -> list[tuple[str, ...]]:
        return [tuple(self.path[:i]) for i in range(1, len(self.path) + 1)]

    @property
    def ancestors(self) -> list[dict[str, Any]]:
        return self.payload.get(_ANCESTORS_KEY, [])

    @property
    def depth(self) -> int:
        return len(self.path)


# ---------------------------------------------------------------------------
# Payload factory
# ---------------------------------------------------------------------------


def _make_payload(
    subject: AgentId,
    scopes: list[str],
    *,
    audience: AgentId | None = None,
    ttl: float = 3600,
    iat: float | None = None,
    ancestors: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "sub": str(subject),
        "scopes": sorted(scopes),
        "aud": str(audience) if audience else "",
        "ttl": ttl,
        "iat": iat if iat is not None else 0.0,
    }
    if ancestors:
        payload[_ANCESTORS_KEY] = ancestors
    return payload


# ---------------------------------------------------------------------------
# The plugin
# ---------------------------------------------------------------------------


class DelegatableAuth:
    """Delegatable capability tokens with cascading revocation.

    Satisfies the ``Auth`` protocol (``issue`` / ``verify`` / ``revoke``) and
    adds a ``delegate`` method for subtree-handle delegation.

    Example::

        auth = DelegatableAuth(secret=b"my-secret")
        root = await auth.issue(AgentId("admin"), ["read", "write"])
        child = await auth.delegate(
            root, audience=AgentId("worker"), scopes=["read"], ttl=100,
        )
        assert await auth.verify(child, presenter=AgentId("worker"))
        await auth.revoke(root)
        with pytest.raises(RevokedAncestorError):
            await auth.verify(child, presenter=AgentId("worker"))
    """

    def __init__(
        self,
        secret: bytes = b"nest-delegatable-secret",
        clock: float | None = None,
        *,
        revoked_paths: set[tuple[str, ...]] | None = None,
    ) -> None:
        self._secret = secret
        self._clock = clock
        self._revoked_paths: set[tuple[str, ...]] = (
            revoked_paths if revoked_paths is not None else set()
        )
        self._handle_counter: int = 0

    # -- Auth protocol methods -------------------------------------------

    async def issue(self, subject: AgentId, scopes: list[str]) -> Token:
        """Issue a root token for *subject* with the given *scopes*.

        A root token has a single-element path with a fresh random handle.
        The nonce is ``HMAC(secret, canonical(payload))``.

        Example::

            token = await auth.issue(AgentId("admin"), ["read", "write"])
        """
        handle = self._make_handle(str(subject))
        payload = _make_payload(subject, scopes)
        path = [handle]
        nonce = _chain_nonce(self._secret, [], payload, path)
        tok = _DelegationToken(path=path, payload=payload, nonce=nonce)
        return Token(tok.serialize())

    async def verify(
        self,
        token: Token,
        *,
        presenter: AgentId | None = None,
    ) -> AuthContext:
        """Verify a token's full delegation chain and revocation state.

        Steps:

        1. Parse the serialized token.
        2. Recompute the HMAC chain from the root secret and the embedded
           ancestor payloads; raise :class:`InvalidDelegationChainError` on
           mismatch.
        3. Check whether **any** prefix of the token's path is in the revoked
           set; raise :class:`RevokedAncestorError` if so.
        4. Check TTL; raise ``ValueError`` if expired.
        5. If *presenter* is supplied, check the token's ``aud`` field; raise
           :class:`AudienceMismatchError` on mismatch.

        Example::

            ctx = await auth.verify(root, presenter=AgentId("admin"))
            assert ctx.subject == AgentId("admin")
        """
        tok = _DelegationToken.deserialize(str(token))

        # --- HMAC chain ---
        expected = _chain_nonce(
            self._secret, tok.ancestors, _strip_ancestors(tok.payload), tok.path
        )
        if not hmac.compare_digest(expected, tok.nonce):
            msg = "Invalid delegation nonce chain"
            raise InvalidDelegationChainError(msg)

        # --- Revocation check ---
        for prefix in tok.path_prefixes:
            if prefix in self._revoked_paths:
                msg = f"Token path prefix {list(prefix)} is revoked"
                raise RevokedAncestorError(msg)

        payload = tok.payload
        now = self._now()

        # --- TTL check ---
        issued_at = payload.get("iat", 0.0)
        ttl = payload.get("ttl", 3600)
        if issued_at + ttl < now:
            msg = f"Token expired at tick {issued_at + ttl} (now={now})"
            raise ValueError(msg)

        # --- Audience check ---
        aud_str: str = payload.get("aud", "")
        if aud_str and presenter is not None and str(presenter) != aud_str:
            msg = f"Token audience is {aud_str!r} but presenter is {presenter!r}"
            raise AudienceMismatchError(msg)

        return AuthContext(
            subject=AgentId(payload["sub"]),
            scopes=list(payload.get("scopes", [])),
            issued_at=issued_at,
            expires_at=issued_at + ttl,
        )

    async def verify_presented(self, token: Token, presenter: AgentId) -> AuthContext:
        """Verify a token *and* that the presenter matches its bound audience.

        Convenience wrapper around :meth:`verify` — equivalent to
        ``verify(token, presenter=presenter)``.

        Example::

            ctx = await auth.verify_presented(child, AgentId("worker"))
        """
        return await self.verify(token, presenter=presenter)

    async def revoke(self, token: Token) -> None:
        """Revoke a token and every descendant in its subtree.

        Stores the token's full path as a blocked prefix.  Any token whose
        path starts with this prefix will fail verification.

        Example::

            await auth.revoke(root)
        """
        tok = _DelegationToken.deserialize(str(token))
        # Verify the nonce before accepting the path — prevents an attacker
        # from crafting a token with an arbitrary path to revoke.
        expected = _chain_nonce(
            self._secret, tok.ancestors, _strip_ancestors(tok.payload), tok.path
        )
        if not hmac.compare_digest(expected, tok.nonce):
            msg = "Invalid nonce chain — cannot revoke"
            raise InvalidDelegationChainError(msg)
        self._revoked_paths.add(tuple(tok.path))

    # -- New API: delegation ---------------------------------------------

    async def delegate(
        self,
        parent_token: Token,
        audience: AgentId,
        scopes: list[str],
        ttl: float,
    ) -> Token:
        """Create a delegated child token from *parent_token*.

        The child inherits a restricted subset of the parent's capabilities:

        * **Scopes** must be a subset of the parent's scopes.
        * **TTL** must be ≤ the parent's remaining TTL.
        * **Audience** is the agent this token is minted *for*.

        The child's nonce is computed over the full ancestor chain plus the
        child payload, so the verifier can recompute it from the embedded
        ancestors without seeing the parent token.

        Example::

            child = await auth.delegate(
                root, AgentId("worker"), ["read"], ttl=100,
            )
        """
        parent = _DelegationToken.deserialize(str(parent_token))

        # --- Verify parent is still valid ---
        parent_expected = _chain_nonce(
            self._secret,
            parent.ancestors,
            _strip_ancestors(parent.payload),
            parent.path,
        )
        if not hmac.compare_digest(parent_expected, parent.nonce):
            msg = "Parent token has invalid nonce chain"
            raise InvalidDelegationChainError(msg)

        for prefix in parent.path_prefixes:
            if prefix in self._revoked_paths:
                msg = f"Parent token path prefix {list(prefix)} is revoked"
                raise RevokedAncestorError(msg)

        now = self._now()
        parent_payload = parent.payload
        parent_iat = parent_payload.get("iat", 0.0)
        parent_ttl = parent_payload.get("ttl", 3600)
        if parent_iat + parent_ttl < now:
            msg = f"Parent token expired at tick {parent_iat + parent_ttl}"
            raise ValueError(msg)

        # --- Validate constraints ---
        parent_scopes: list[str] = parent_payload.get("scopes", [])
        if not set(scopes).issubset(set(parent_scopes)):
            extra = set(scopes) - set(parent_scopes)
            msg = f"Scopes {sorted(extra)} not in parent's scopes {parent_scopes}"
            raise ScopeEscalationError(msg)

        parent_remaining_ttl = max(0, int(parent_iat + parent_ttl - now))
        if ttl > parent_remaining_ttl:
            msg = f"Child TTL ({ttl}) exceeds parent remaining TTL ({parent_remaining_ttl})"
            raise ValueError(msg)

        # --- Build child's ancestor chain ---
        parent_stripped = _strip_ancestors(parent_payload)
        child_ancestors = parent.ancestors + [parent_stripped]

        # --- Construct child ---
        child_subject = parent_payload["sub"]
        child_handle = self._make_handle(str(child_subject))
        child_path = parent.path + [child_handle]
        child_payload = _make_payload(
            AgentId(child_subject),
            scopes,
            audience=audience,
            ttl=ttl,
            iat=now,
            ancestors=child_ancestors,
        )
        child_nonce = _chain_nonce(
            self._secret, child_ancestors, _strip_ancestors(child_payload), child_path
        )

        child = _DelegationToken(path=child_path, payload=child_payload, nonce=child_nonce)
        return Token(child.serialize())

    # -- Internal ---------------------------------------------------------

    def _make_handle(self, subject: str) -> str:
        """Derive a deterministic handle using HMAC + monotonic counter.

        Ensures Tier 1 determinism: same sequence of operations with the
        same secret always yields the same handles.
        """
        self._handle_counter += 1
        material = f"handle:{subject}:{self._handle_counter}".encode()
        return hmac.new(self._secret, material, hashlib.sha256).hexdigest()[:32]

    def _now(self) -> float:
        return self._clock if self._clock is not None else 0.0

    def revoked_paths(self) -> set[tuple[str, ...]]:
        """Return the current set of revoked path prefixes (for testing/inspection).

        Example::

            paths = auth.revoked_paths()
            assert ("root_h",) in paths
        """
        return self._revoked_paths
