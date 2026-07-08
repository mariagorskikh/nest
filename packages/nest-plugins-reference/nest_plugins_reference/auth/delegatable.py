# SPDX-License-Identifier: Apache-2.0
"""Delegatable capability-token auth with cascading revocation.

The token format is intentionally deterministic and self-contained. A root
segment is HMAC-signed by the issuer secret; each delegated child segment is
HMAC-signed by the previous segment signature. Verification recomputes the full
chain and checks every segment for expiry and revocation.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import time
from typing import Any, cast

from nest_core.types import AgentId, AuthContext, Token

_VERSION = "ndcap1"
_EFS_WRITE_SCOPE_PREFIX = "efs.write:"


class DelegationError(ValueError):
    """Base class for delegation failures."""


class DelegatableAuthError(DelegationError):
    """Base class for delegatable auth failures."""


class MalformedTokenError(DelegatableAuthError):
    """Raised when a token cannot be decoded."""


class InvalidSignatureError(DelegatableAuthError):
    """Raised when a token segment signature is invalid."""


class ScopeEscalationError(DelegatableAuthError):
    """Raised when a child asks for a scope its parent does not cover."""


class TtlEscalationError(DelegatableAuthError):
    """Raised when a child asks to outlive its parent."""


class RevokedAncestorError(DelegatableAuthError):
    """Raised when a token or one of its ancestors has been revoked."""


class ExpiredAncestorError(DelegatableAuthError):
    """Raised when a token or one of its ancestors has expired."""


class AudienceMismatchError(DelegatableAuthError):
    """Raised when a token is presented by a different audience."""


class InsufficientScopeError(DelegatableAuthError):
    """Raised when a verified token lacks a required scope."""


class DelegatableAuth:
    """HMAC-chained delegatable auth plugin.

    Child tokens must attenuate the parent grant. Wildcard EFS write scopes
    must narrow when delegated: a child may receive
    ``efs.write:/agents/leaf-0/*`` from ``efs.write:/agents/*``, but it may
    not receive the unchanged wildcard ``efs.write:/agents/*``.

    Example::

        auth = DelegatableAuth(clock=0.0)
        root = await auth.issue(AgentId("coordinator-0"), ["scribe:*"])
        child = await auth.delegate(root, AgentId("leaf-0"), ["scribe:verify"], 10.0)
        ctx = await auth.verify_for(child, AgentId("leaf-0"), ["scribe:verify"])
    """

    def __init__(
        self,
        secret: bytes = b"nest-delegatable-secret",
        clock: float | None = None,
    ) -> None:
        self._secret = secret
        self._clock = clock
        self._revoked: set[str] = set()

    def set_clock(self, value: float) -> None:
        """Set the deterministic logical clock used by tests and scenarios."""
        self._clock = value

    def _now(self) -> float:
        return time.time() if self._clock is None else self._clock

    async def issue(self, subject: AgentId, scopes: list[str]) -> Token:
        """Issue a root token for a subject.

        Example::

            token = await auth.issue(AgentId("coordinator-0"), ["efs.write:/agents/*"])
        """
        now = self._now()
        claims: dict[str, Any] = {
            "aud": str(subject),
            "depth": 0,
            "exp": now + 3600.0,
            "iat": now,
            "pid": None,
            "scp": _scopes(scopes),
            "sub": str(subject),
        }
        segment = {"claims": claims, "sig": _hmac_hex(self._secret, _canonical(claims))}
        return _encode_chain([segment])

    async def delegate(
        self,
        parent_token: Token,
        audience: AgentId,
        scopes_subset: list[str],
        ttl: float,
    ) -> Token:
        """Delegate a strict subset of parent scopes to ``audience``.

        Example::

            leaf = await auth.delegate(parent, AgentId("leaf-0"), ["scribe:verify"], 10.0)
        """
        parent_ctx = await self.verify(parent_token)
        parent_chain = _decode_chain(parent_token)
        parent_segment = parent_chain[-1]
        parent_claims = _segment_claims(parent_segment)
        requested = _scopes(scopes_subset)
        _validate_child_scopes(requested, parent_ctx.scopes)

        now = self._now()
        parent_exp = float(parent_claims["exp"])
        exp = now + ttl
        if not math.isfinite(ttl) or ttl <= 0 or exp > parent_exp:
            msg = "Child TTL must be positive and must not exceed parent expiry"
            raise TtlEscalationError(msg)

        claims: dict[str, Any] = {
            "aud": str(audience),
            "depth": int(parent_claims["depth"]) + 1,
            "exp": exp,
            "iat": now,
            "pid": _segment_id(parent_segment),
            "scp": requested,
            "sub": str(audience),
        }
        sig_key = bytes.fromhex(str(parent_segment["sig"]))
        segment = {"claims": claims, "sig": _hmac_hex(sig_key, _canonical(claims))}
        return _encode_chain([*parent_chain, segment])

    async def verify(self, token: Token) -> AuthContext:
        """Verify a token and its ancestor chain.

        Example::

            ctx = await auth.verify(token)
            assert "scribe:verify" in ctx.scopes
        """
        chain = _decode_chain(token)
        now = self._now()
        prior_sig: str | None = None
        prior_id: str | None = None
        prior_claims: dict[str, Any] | None = None
        terminal: dict[str, Any] | None = None
        for index, segment in enumerate(chain):
            claims = _segment_claims(segment)
            sig = _segment_sig(segment)
            key = self._secret if index == 0 else bytes.fromhex(str(prior_sig))
            expected = _hmac_hex(key, _canonical(claims))
            if not hmac.compare_digest(sig, expected):
                raise InvalidSignatureError("Invalid token segment signature")
            if index == 0:
                _validate_root_claims(claims)
            elif prior_claims is not None:
                _validate_child_claims(claims, prior_claims, prior_id)

            segment_id = _segment_id(segment)
            if segment_id in self._revoked:
                msg = f"Token ancestor {segment_id} has been revoked"
                raise RevokedAncestorError(msg)
            if float(claims["exp"]) < now:
                msg = f"Token ancestor {segment_id} has expired"
                raise ExpiredAncestorError(msg)

            terminal = segment
            prior_claims = claims
            prior_sig = sig
            prior_id = segment_id

        if terminal is None:
            raise MalformedTokenError("Token has no segments")
        terminal_claims = cast("dict[str, Any]", terminal["claims"])
        return AuthContext(
            subject=AgentId(str(terminal_claims["sub"])),
            scopes=cast("list[str]", terminal_claims["scp"]),
            issued_at=float(terminal_claims["iat"]),
            expires_at=float(terminal_claims["exp"]),
        )

    async def verify_for(
        self,
        token: Token,
        presenter: AgentId,
        required_scopes: list[str] | None = None,
    ) -> AuthContext:
        """Verify a token for a concrete presenter and optional required scopes.

        Example::

            await auth.verify_for(token, AgentId("leaf-0"), ["scribe:verify"])
        """
        ctx = await self.verify(token)
        if ctx.subject != presenter:
            msg = f"Token for {ctx.subject} presented by {presenter}"
            raise AudienceMismatchError(msg)
        for scope in required_scopes or []:
            if not any(scope_covers(held, scope) for held in ctx.scopes):
                msg = f"Token lacks required scope {scope!r}"
                raise InsufficientScopeError(msg)
        return ctx

    async def verify_presented(self, token: Token, presenter: AgentId) -> AuthContext:
        """Verify a token and that the presenter is its bound audience.

        Example::

            await auth.verify_presented(token, AgentId("leaf-0"))
        """
        return await self.verify_for(token, presenter)

    async def revoke(self, token: Token) -> None:
        """Revoke a token segment id; descendants fail transitively.

        Example::

            await auth.revoke(parent)
            await auth.verify(child)  # raises RevokedAncestorError
        """
        chain = _decode_chain(token)
        terminal = chain[-1]
        self._revoked.add(_segment_id(terminal))


def scope_covers(parent_scope: str, child_scope: str) -> bool:
    """Return true when ``parent_scope`` covers ``child_scope``.

    Example::

        assert scope_covers("scribe:*", "scribe:publish")
    """
    if not _is_valid_efs_write_scope(parent_scope):
        return False
    if not _is_valid_efs_write_scope(child_scope):
        return False
    if parent_scope == child_scope:
        return True
    if parent_scope.endswith("*"):
        prefix = parent_scope[:-1]
        if parent_scope.startswith("efs.write:") and not prefix.endswith("/"):
            return False
        return child_scope.startswith(prefix)
    return False


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _hmac_hex(key: bytes, payload: bytes) -> str:
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def _scopes(scopes: list[str]) -> list[str]:
    for scope in scopes:
        _validate_efs_write_scope(scope)
    return sorted(set(scopes))


def _segment_claims(segment: dict[str, Any]) -> dict[str, Any]:
    claims_obj = segment.get("claims")
    sig = segment.get("sig")
    if not isinstance(claims_obj, dict) or not isinstance(sig, str):
        raise MalformedTokenError("Token segment is malformed")
    claims = cast("dict[str, Any]", claims_obj)
    required = {"aud", "depth", "exp", "iat", "pid", "scp", "sub"}
    if not required.issubset(claims.keys()):
        raise MalformedTokenError("Token segment claims are incomplete")
    scopes_obj = claims["scp"]
    if not isinstance(scopes_obj, list):
        raise MalformedTokenError("Token scopes are malformed")
    scope_values = cast("list[Any]", scopes_obj)
    if not all(isinstance(scope, str) for scope in scope_values):
        raise MalformedTokenError("Token scopes are malformed")
    for scope in scope_values:
        _validate_efs_write_scope(scope)
    if not isinstance(claims["aud"], str) or not isinstance(claims["sub"], str):
        raise MalformedTokenError("Token subject is malformed")
    try:
        int(claims["depth"])
        exp = _finite_float(claims["exp"], "exp")
        iat = _finite_float(claims["iat"], "iat")
    except (TypeError, ValueError) as exc:
        raise MalformedTokenError("Token timing claims are malformed") from exc
    if exp < iat:
        raise TtlEscalationError("Token expiry predates issue time")
    if claims["pid"] is not None and not isinstance(claims["pid"], str):
        raise MalformedTokenError("Token parent id is malformed")
    return claims


def _finite_float(value: Any, field: str) -> float:
    try:
        converted = float(value)
    except (TypeError, ValueError) as exc:
        msg = f"Token {field} is malformed"
        raise MalformedTokenError(msg) from exc
    if not math.isfinite(converted):
        msg = f"Token {field} must be finite"
        raise MalformedTokenError(msg)
    return converted


def _segment_sig(segment: dict[str, Any]) -> str:
    sig = segment.get("sig")
    if not isinstance(sig, str):
        raise MalformedTokenError("Token segment signature is malformed")
    return sig


def _validate_root_claims(claims: dict[str, Any]) -> None:
    if int(claims["depth"]) != 0 or claims["pid"] is not None:
        raise InvalidSignatureError("Root token claims are malformed")
    if claims["aud"] != claims["sub"]:
        raise InvalidSignatureError("Root token subject does not match audience")


def _validate_child_claims(
    claims: dict[str, Any],
    parent_claims: dict[str, Any],
    expected_parent_id: str | None,
) -> None:
    if claims.get("pid") != expected_parent_id:
        raise InvalidSignatureError("Token parent id does not match previous segment")
    if int(claims["depth"]) != int(parent_claims["depth"]) + 1:
        raise InvalidSignatureError("Token depth does not match delegation chain")
    if claims["aud"] != claims["sub"]:
        raise InvalidSignatureError("Token subject does not match audience")
    if float(claims["exp"]) > float(parent_claims["exp"]):
        msg = "Child expiry exceeds parent expiry"
        raise TtlEscalationError(msg)
    if float(claims["iat"]) < float(parent_claims["iat"]):
        raise InvalidSignatureError("Token issue time predates parent")
    parent_scopes = cast("list[str]", parent_claims["scp"])
    child_scopes = _scopes(cast("list[str]", claims["scp"]))
    _validate_child_scopes(child_scopes, parent_scopes)


def _validate_child_scopes(child_scopes: list[str], parent_scopes: list[str]) -> None:
    for scope in [*parent_scopes, *child_scopes]:
        _validate_efs_write_scope(scope)
    for scope in child_scopes:
        covering = [
            parent_scope for parent_scope in parent_scopes if scope_covers(parent_scope, scope)
        ]
        if not covering:
            msg = f"Parent token does not cover child scope {scope!r}"
            raise ScopeEscalationError(msg)
        if scope.endswith("*") and all(parent_scope == scope for parent_scope in covering):
            msg = f"Child wildcard scope must narrow parent scope {scope!r}"
            raise ScopeEscalationError(msg)


def _is_valid_efs_write_scope(scope: str) -> bool:
    if not scope.startswith(_EFS_WRITE_SCOPE_PREFIX):
        return True

    path = scope[len(_EFS_WRITE_SCOPE_PREFIX) :]
    if not path.startswith("/"):
        return False

    parts = path.split("/")[1:]
    for index, part in enumerate(parts):
        lowered = part.lower()
        if part in {"", ".", ".."}:
            return False
        if lowered in {"%2e", "%2e%2e"} or "%2f" in lowered or "%5c" in lowered:
            return False
        if "*" in part and (part != "*" or index != len(parts) - 1):
            return False
    return True


def _validate_efs_write_scope(scope: str) -> None:
    if not _is_valid_efs_write_scope(scope):
        msg = f"Malformed efs.write scope path {scope!r}"
        raise ScopeEscalationError(msg)


def _segment_id(segment: dict[str, Any]) -> str:
    payload = _canonical(_segment_claims(segment)) + b"." + _segment_sig(segment).encode()
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _encode_chain(chain: list[dict[str, Any]]) -> Token:
    raw = json.dumps({"chain": chain}, sort_keys=True, separators=(",", ":")).encode()
    encoded = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    return Token(f"{_VERSION}.{encoded}")


def _decode_chain(token: Token) -> list[dict[str, Any]]:
    raw = str(token)
    prefix = f"{_VERSION}."
    if not raw.startswith(prefix):
        raise MalformedTokenError("Unsupported token version")
    encoded = raw[len(prefix) :]
    padded = encoded + "=" * (-len(encoded) % 4)
    try:
        decoded = base64.urlsafe_b64decode(padded.encode())
        data: Any = json.loads(decoded)
    except (ValueError, json.JSONDecodeError) as exc:
        raise MalformedTokenError("Malformed token") from exc
    data_obj = cast("dict[str, Any] | None", data) if isinstance(data, dict) else None
    chain_obj: Any | None = data_obj.get("chain") if data_obj is not None else None
    if not isinstance(chain_obj, list) or not chain_obj:
        raise MalformedTokenError("Token chain is missing")
    chain: list[dict[str, Any]] = []
    for raw_segment in cast("list[Any]", chain_obj):
        if not isinstance(raw_segment, dict):
            raise MalformedTokenError("Token chain contains malformed segment")
        chain.append(cast("dict[str, Any]", raw_segment))
    return chain
