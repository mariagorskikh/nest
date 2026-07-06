# SPDX-License-Identifier: Apache-2.0
"""Delegatable capability tokens with offline attenuation and cascading revocation.

This plugin models macaroon/Biscuit-style delegation for the auth layer.  A
root issuer signs the first caveat set with a root HMAC secret.  Each holder can
mint a child token offline by signing the child's narrower caveats with the
parent link signature as the HMAC key.  Verifiers replay the whole chain from
the root secret and reject if any ancestor is expired, revoked, stale, or
structurally widened.

Example::

    auth = CapabilityTokens(secret=b"demo", clock=0.0)
    root = await auth.issue(AgentId("coordinator"), ["read", "write"])
    child = await auth.delegate(root, AgentId("worker"), ["read"], ttl=60)
    ctx = await auth.verify_for_audience(child, AgentId("worker"))
    assert ctx.scopes == ["read"]
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import cast

from nest_core.types import AgentId, AuthContext, Token

_PREFIX = "cap1."
_ROOT_PARENT_HASH = "0" * 64
_DEFAULT_ROOT_TTL = 3600.0

_Clock = float | Callable[[], float]


class CapabilityTokenError(ValueError):
    """Base class for capability-token verification and delegation failures.

    Example::

        try:
            await auth.verify(token)
        except CapabilityTokenError:
            pass
    """


class ScopeEscalationError(CapabilityTokenError):
    """Raised when a delegate asks for scopes the parent never possessed.

    Example::

        with pytest.raises(ScopeEscalationError):
            await auth.delegate(parent, AgentId("worker"), ["admin"], ttl=5)
    """


class TtlEscalationError(CapabilityTokenError):
    """Raised when a child TTL would outlive the parent token.

    Example::

        with pytest.raises(TtlEscalationError):
            await auth.delegate(parent, AgentId("worker"), ["read"], ttl=9999)
    """


class RevokedAncestorError(CapabilityTokenError):
    """Raised when any link in the token's ancestor chain has been revoked.

    Example::

        await auth.revoke(parent)
        with pytest.raises(RevokedAncestorError):
            await auth.verify(child)
    """


class ExpiredAncestorError(CapabilityTokenError):
    """Raised when any ancestor in the delegation chain has expired.

    Example::

        expired = CapabilityTokens(clock=7200.0)
        with pytest.raises(ExpiredAncestorError):
            await expired.verify(token)
    """


class AudienceMismatchError(CapabilityTokenError):
    """Raised when a token is presented by the wrong audience.

    Example::

        with pytest.raises(AudienceMismatchError):
            await auth.verify_for_audience(token, AgentId("wrong-agent"))
    """


class InvalidChainError(CapabilityTokenError):
    """Raised when a token cannot be parsed or its HMAC chain does not replay.

    Example::

        with pytest.raises(InvalidChainError):
            await auth.verify(Token("cap1.not-valid"))
    """


class RevocationViewStaleError(CapabilityTokenError):
    """Raised when a verifier's revocation epoch is too stale to trust.

    Example::

        stale = CapabilityTokens(revocation_store=store, stale_after=0, auto_sync=False)
        await issuer.revoke(parent)
        with pytest.raises(RevocationViewStaleError):
            await stale.verify(child)
    """


@dataclass
class RevocationStore:
    """Shared, monotonic revocation log for partition-aware verifiers.

    The store is deliberately tiny: every revoke event increments ``epoch`` and
    stores the revoked chain hash.  A verifier can snapshot this store and later
    fail closed if ``store.epoch - visible_epoch > stale_after``.

    Example::

        store = RevocationStore()
        epoch = store.revoke("a" * 64)
        assert epoch == 1
    """

    epoch: int = 0
    revoked_hashes: set[str] = field(default_factory=lambda: set[str]())

    def revoke(self, chain_hash: str) -> int:
        """Record a revoked chain hash and return the new epoch.

        Example::

            store = RevocationStore()
            assert store.revoke("f" * 64) == 1
        """
        self.epoch += 1
        self.revoked_hashes.add(chain_hash)
        return self.epoch

    def snapshot(self) -> tuple[int, frozenset[str]]:
        """Return an immutable ``(epoch, revoked_hashes)`` view.

        Example::

            epoch, hashes = store.snapshot()
            assert epoch >= 0 and isinstance(hashes, frozenset)
        """
        return self.epoch, frozenset(self.revoked_hashes)


@dataclass(frozen=True)
class _Link:
    body: dict[str, object]
    sig: str


@dataclass(frozen=True)
class _ReplayResult:
    links: list[_Link]
    chain_hashes: list[str]
    subject: AgentId
    scopes: list[str]
    issued_at: float
    expires_at: float

    @property
    def chain_hash(self) -> str:
        return self.chain_hashes[-1]


def _canonical(data: Mapping[str, object]) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64decode(raw: str) -> bytes:
    padding = "=" * (-len(raw) % 4)
    return base64.urlsafe_b64decode((raw + padding).encode("ascii"))


def _normalize_scopes(scopes: Iterable[str]) -> list[str]:
    unique: set[str] = set()
    for scope in scopes:
        unique.add(scope)
    normalized = sorted(unique)
    if not normalized:
        msg = "capability tokens must carry at least one scope"
        raise InvalidChainError(msg)
    return normalized


def _require_str(body: Mapping[str, object], field_name: str) -> str:
    value = body.get(field_name)
    if not isinstance(value, str):
        msg = f"capability link missing string field {field_name!r}"
        raise InvalidChainError(msg)
    return value


def _require_float(body: Mapping[str, object], field_name: str) -> float:
    value = body.get(field_name)
    if isinstance(value, bool) or not isinstance(value, int | float):
        msg = f"capability link missing numeric field {field_name!r}"
        raise InvalidChainError(msg)
    return float(value)


def _require_scopes(body: Mapping[str, object]) -> list[str]:
    value = body.get("scopes")
    if not isinstance(value, list):
        msg = "capability link missing string-list field 'scopes'"
        raise InvalidChainError(msg)
    raw_scopes = cast("list[object]", value)
    if not all(isinstance(scope, str) for scope in raw_scopes):
        msg = "capability link missing string-list field 'scopes'"
        raise InvalidChainError(msg)
    return [cast("str", scope) for scope in raw_scopes]


def _hmac_hex(key: bytes, purpose: str, body: Mapping[str, object]) -> str:
    payload = f"{purpose}:{_canonical(body)}".encode()
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def _chain_hash(previous_hash: str, body: Mapping[str, object], sig: str) -> str:
    payload = f"{previous_hash}.{_canonical(body)}.{sig}".encode()
    return hashlib.sha256(payload).hexdigest()


def _sig_key(sig: str) -> bytes:
    try:
        return bytes.fromhex(sig)
    except ValueError as exc:
        msg = "capability link signature is not hex"
        raise InvalidChainError(msg) from exc


class CapabilityTokens:
    """Macaroon-style auth plugin with offline attenuation and revocation epochs.

    The class satisfies the base ``Auth`` protocol via ``issue``, ``verify``,
    and ``revoke``.  It adds ``delegate`` for holder-side attenuation and
    ``verify_for_audience`` for explicit confused-deputy protection.

    Example::

        auth = CapabilityTokens(secret=b"root", clock=0.0)
        root = await auth.issue(AgentId("a"), ["read", "write"])
        child = await auth.delegate(root, AgentId("b"), ["read"], ttl=10)
        assert (await auth.verify_for_audience(child, AgentId("b"))).subject == AgentId("b")
    """

    def __init__(
        self,
        secret: bytes = b"nest-capability-secret",
        *,
        root_ttl: float = _DEFAULT_ROOT_TTL,
        clock: _Clock = 0.0,
        agent_id: AgentId | None = None,
        revocation_store: RevocationStore | None = None,
        stale_after: int = 0,
        auto_sync: bool = True,
    ) -> None:
        if root_ttl <= 0:
            msg = "root_ttl must be positive"
            raise ValueError(msg)
        if stale_after < 0:
            msg = "stale_after must be non-negative"
            raise ValueError(msg)
        self._secret = secret
        self._root_ttl = float(root_ttl)
        self._clock = clock
        self._agent_id = agent_id
        self._store = revocation_store if revocation_store is not None else RevocationStore()
        self._stale_after = stale_after
        self._auto_sync = auto_sync
        self._counter = 0
        self._visible_epoch = 0
        self._visible_revoked: frozenset[str] = frozenset()
        self.sync_revocations()

    def sync_revocations(self) -> None:
        """Refresh this verifier's local revocation view from the shared store.

        Example::

            verifier.sync_revocations()
            await verifier.verify(token)
        """
        self._visible_epoch, self._visible_revoked = self._store.snapshot()

    @property
    def visible_epoch(self) -> int:
        """Return the epoch this verifier currently trusts.

        Example::

            assert auth.visible_epoch >= 0
        """
        return self._visible_epoch

    @property
    def current_epoch(self) -> int:
        """Return the latest epoch known to the shared revocation store.

        Example::

            assert auth.current_epoch >= auth.visible_epoch
        """
        return self._store.epoch

    async def issue(self, subject: AgentId, scopes: list[str]) -> Token:
        """Issue a root capability token for ``subject`` and ``scopes``.

        Example::

            token = await auth.issue(AgentId("coordinator"), ["read", "write"])
        """
        now = self._now()
        self._counter += 1
        body: dict[str, object] = {
            "aud": str(subject),
            "exp": now + self._root_ttl,
            "iat": now,
            "jti": f"root-{self._counter}",
            "kind": "root",
            "scopes": _normalize_scopes(scopes),
            "sub": str(subject),
            "v": 1,
        }
        sig = _hmac_hex(self._secret, "root", body)
        return self._encode([_Link(body=body, sig=sig)])

    async def delegate(
        self,
        parent_token: Token,
        audience: AgentId,
        scopes_subset: list[str],
        ttl: float,
    ) -> Token:
        """Mint a child token from ``parent_token`` without issuer re-issuance.

        The child signature is ``HMAC(parent_signature, child_caveats)``.  The
        root secret is not used to mint the child, which is the offline
        attenuation property the capability layer needs.

        Example::

            child = await auth.delegate(root, AgentId("worker"), ["read"], ttl=30)
        """
        if ttl < 0:
            msg = "child ttl must be non-negative"
            raise TtlEscalationError(msg)

        links, parent_hashes = self._unsafe_replay(parent_token)
        parent = links[-1]
        parent_body = parent.body
        parent_audience = _require_str(parent_body, "aud")
        if self._agent_id is not None and parent_audience != str(self._agent_id):
            msg = f"token audience {parent_audience!r} cannot be delegated by {self._agent_id!r}"
            raise AudienceMismatchError(msg)

        now = self._now()
        parent_exp = _require_float(parent_body, "exp")
        if parent_exp < now:
            msg = f"parent token expired at {parent_exp}"
            raise ExpiredAncestorError(msg)
        if now + ttl > parent_exp:
            msg = f"child expiry {now + ttl} would outlive parent expiry {parent_exp}"
            raise TtlEscalationError(msg)

        parent_scopes = set(_require_scopes(parent_body))
        child_scopes = _normalize_scopes(scopes_subset)
        if not set(child_scopes) <= parent_scopes:
            requested = sorted(set(child_scopes) - parent_scopes)
            msg = f"scope escalation denied: {requested}"
            raise ScopeEscalationError(msg)

        self._counter += 1
        parent_hash = parent_hashes[-1]
        child_body: dict[str, object] = {
            "aud": str(audience),
            "delegator": parent_audience,
            "exp": now + ttl,
            "iat": now,
            "jti": f"{parent_hash[:12]}-{self._counter}",
            "kind": "child",
            "parent": parent_hash,
            "scopes": child_scopes,
            "sub": str(audience),
            "v": 1,
        }
        child_sig = _hmac_hex(_sig_key(parent.sig), "child", child_body)
        return self._encode([*links, _Link(body=child_body, sig=child_sig)])

    async def verify(self, token: Token) -> AuthContext:
        """Verify ``token`` and return its effective auth context.

        If this instance was constructed with ``agent_id``, the final token
        audience must match that agent.  Use ``verify_for_audience`` to bind an
        audience explicitly on a shared verifier.

        Example::

            ctx = await auth.verify(token)
            assert "read" in ctx.scopes
        """
        result = self._replay(token, audience=self._agent_id)
        return AuthContext(
            subject=result.subject,
            scopes=result.scopes,
            issued_at=result.issued_at,
            expires_at=result.expires_at,
        )

    async def verify_for_audience(self, token: Token, audience: AgentId) -> AuthContext:
        """Verify ``token`` as presented by ``audience``.

        Example::

            ctx = await auth.verify_for_audience(token, AgentId("worker"))
            assert ctx.subject == AgentId("worker")
        """
        result = self._replay(token, audience=audience)
        return AuthContext(
            subject=result.subject,
            scopes=result.scopes,
            issued_at=result.issued_at,
            expires_at=result.expires_at,
        )

    async def authorize(
        self,
        token: Token,
        presenter: AgentId,
        required_scope: str,
    ) -> AuthContext:
        """Verify ``token`` as presented by ``presenter`` and gate one action scope.

        This is the resource-guard primitive that stops a confused deputy: the
        deputy may hold a perfectly valid token, but the action it performs on
        behalf of a third party must be covered by the token's own scopes.
        Missing scope raises ``ScopeEscalationError`` — fail closed.

        Example::

            with pytest.raises(ScopeEscalationError):
                await auth.authorize(deputy_token, AgentId("deputy"), "payments:write")
        """
        ctx = await self.verify_for_audience(token, presenter)
        if required_scope not in ctx.scopes:
            msg = f"action requires scope {required_scope!r} not granted by this token"
            raise ScopeEscalationError(msg)
        return ctx

    async def revoke(self, token: Token) -> None:
        """Revoke ``token`` by its terminal chain hash.

        Because every descendant embeds the revoked ancestor's chain hash in its
        HMAC replay path, revoking an ancestor invalidates all descendants on
        the next fresh verification.

        Example::

            await auth.revoke(parent)
            with pytest.raises(RevokedAncestorError):
                await auth.verify(child)
        """
        result = self._replay(
            token,
            audience=None,
            check_expiry=False,
            check_revocation=False,
        )
        self._store.revoke(result.chain_hash)
        self.sync_revocations()

    def _now(self) -> float:
        if callable(self._clock):
            return float(self._clock())
        return float(self._clock)

    def _encode(self, links: list[_Link]) -> Token:
        payload = {
            "links": [{"body": link.body, "sig": link.sig} for link in links],
        }
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return Token(f"{_PREFIX}{_b64encode(raw)}")

    def _decode(self, token: Token) -> list[_Link]:
        raw = str(token)
        if not raw.startswith(_PREFIX):
            msg = "capability token has an unknown prefix"
            raise InvalidChainError(msg)
        try:
            decoded = _b64decode(raw[len(_PREFIX) :])
            loaded: object = json.loads(decoded)
        except (ValueError, json.JSONDecodeError) as exc:
            msg = "capability token is not decodable JSON"
            raise InvalidChainError(msg) from exc

        if not isinstance(loaded, dict):
            msg = "capability token envelope must be a JSON object"
            raise InvalidChainError(msg)
        envelope = cast("dict[str, object]", loaded)
        links_value = envelope.get("links")
        if not isinstance(links_value, list) or not links_value:
            msg = "capability token must contain at least one link"
            raise InvalidChainError(msg)
        links_raw = cast("list[object]", links_value)

        links: list[_Link] = []
        for item_value in links_raw:
            if not isinstance(item_value, dict):
                msg = "capability token link must be a JSON object"
                raise InvalidChainError(msg)
            item = cast("dict[str, object]", item_value)
            body_value = item.get("body")
            sig_value = item.get("sig")
            if not isinstance(body_value, dict) or not isinstance(sig_value, str):
                msg = "capability token link must carry body and sig"
                raise InvalidChainError(msg)
            links.append(_Link(body=cast("dict[str, object]", body_value), sig=sig_value))
        return links

    def _unsafe_replay(self, token: Token) -> tuple[list[_Link], list[str]]:
        links = self._decode(token)
        previous_hash = _ROOT_PARENT_HASH
        chain_hashes: list[str] = []
        for index, link in enumerate(links):
            if index == 0 and _require_str(link.body, "kind") != "root":
                msg = "first capability link must be a root"
                raise InvalidChainError(msg)
            if index > 0:
                if _require_str(link.body, "kind") != "child":
                    msg = "non-root capability links must be children"
                    raise InvalidChainError(msg)
                parent_hash = _require_str(link.body, "parent")
                if parent_hash != previous_hash:
                    msg = "child parent hash does not match previous link"
                    raise InvalidChainError(msg)
            previous_hash = _chain_hash(previous_hash, link.body, link.sig)
            chain_hashes.append(previous_hash)
        return links, chain_hashes

    def _replay(
        self,
        token: Token,
        *,
        audience: AgentId | None,
        check_expiry: bool = True,
        check_revocation: bool = True,
    ) -> _ReplayResult:
        if check_revocation:
            self._ensure_revocation_fresh()

        links, _ = self._unsafe_replay(token)
        previous_hash = _ROOT_PARENT_HASH
        parent_sig: str | None = None
        parent_scopes: set[str] | None = None
        parent_exp: float | None = None
        chain_hashes: list[str] = []
        now = self._now()

        for index, link in enumerate(links):
            kind = _require_str(link.body, "kind")
            if index == 0:
                expected = _hmac_hex(self._secret, "root", link.body)
                if kind != "root":
                    msg = "first capability link must be a root"
                    raise InvalidChainError(msg)
            else:
                if parent_sig is None:
                    msg = "child link has no parent signature"
                    raise InvalidChainError(msg)
                expected = _hmac_hex(_sig_key(parent_sig), "child", link.body)
                if kind != "child":
                    msg = "non-root capability links must be children"
                    raise InvalidChainError(msg)
                parent_hash = _require_str(link.body, "parent")
                if parent_hash != previous_hash:
                    msg = "child parent hash does not match previous link"
                    raise InvalidChainError(msg)

            if not hmac.compare_digest(link.sig, expected):
                msg = f"capability link {index} has an invalid HMAC"
                raise InvalidChainError(msg)

            scopes = _require_scopes(link.body)
            exp = _require_float(link.body, "exp")
            if parent_scopes is not None and not set(scopes) <= parent_scopes:
                msg = f"capability link {index} widens parent scopes"
                raise InvalidChainError(msg)
            if parent_exp is not None and exp > parent_exp:
                msg = f"capability link {index} outlives its parent"
                raise InvalidChainError(msg)
            if check_expiry and exp < now:
                msg = f"capability link {index} expired at {exp}"
                raise ExpiredAncestorError(msg)

            current_hash = _chain_hash(previous_hash, link.body, link.sig)
            if check_revocation and current_hash in self._visible_revoked:
                msg = f"capability ancestor link {index} has been revoked"
                raise RevokedAncestorError(msg)

            chain_hashes.append(current_hash)
            previous_hash = current_hash
            parent_sig = link.sig
            parent_scopes = set(scopes)
            parent_exp = exp

        tail = links[-1].body
        tail_audience = _require_str(tail, "aud")
        if audience is not None and tail_audience != str(audience):
            msg = f"token audience {tail_audience!r} does not match presenter {audience!r}"
            raise AudienceMismatchError(msg)

        return _ReplayResult(
            links=links,
            chain_hashes=chain_hashes,
            subject=AgentId(_require_str(tail, "sub")),
            scopes=_require_scopes(tail),
            issued_at=_require_float(tail, "iat"),
            expires_at=_require_float(tail, "exp"),
        )

    def _ensure_revocation_fresh(self) -> None:
        if self._auto_sync:
            self.sync_revocations()
        lag = self._store.epoch - self._visible_epoch
        if lag > self._stale_after:
            msg = (
                f"revocation view stale by {lag} epoch(s); "
                f"configured fail-closed bound is {self._stale_after}"
            )
            raise RevocationViewStaleError(msg)
