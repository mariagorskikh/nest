# SPDX-License-Identifier: Apache-2.0
"""Delegatable capability tokens auth plugin with cascading revocation.

Example::

    auth = DelegatableAuth(secret=b"my-secret")
    token = await auth.issue(AgentId("a1"), ["read", "write"])
    child = await auth.delegate(token, AgentId("a2"), ["read"], ttl=60.0)
    ctx = await auth.verify(child, presenter=AgentId("a2"))
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from typing import Any, cast

from nest_core.types import AgentId, AuthContext, Token


class RevokedAncestorError(ValueError):
    """Raised when a token or any of its ancestors has been revoked.

    Example::

        raise RevokedAncestorError("Token ancestor is revoked")
    """


class DelegatableAuth:
    """Delegatable capability token auth plugin using macaroon-style HMAC chaining.

    Example::

        auth = DelegatableAuth(secret=b"secret")
        token = await auth.issue(AgentId("a1"), ["read"])
    """

    def __init__(self, secret: bytes = b"nest-default-secret", clock: Any | None = None) -> None:
        """Initialize the auth plugin.

        Example::

            auth = DelegatableAuth(secret=b"s3cr3t")
        """
        self._secret = secret
        self._clock = clock
        self._revoked_ids: set[str] = set()
        self._token_keys: dict[str, bytes] = {}

    def set_clock(self, clock: Any) -> None:
        """Dynamically set or update the clock.

        Example::

            auth.set_clock(lambda: ctx.time)
        """
        self._clock = clock

    def _now(self) -> float:
        if self._clock is not None:
            if isinstance(self._clock, (int, float)):
                return float(self._clock)
            if callable(self._clock):
                return float(cast("float", self._clock()))
            if hasattr(self._clock, "now"):
                return float(cast("float", self._clock.now))
            if hasattr(self._clock, "time"):
                return float(cast("float", self._clock.time))
        return time.time()

    def _derive_key_chain(self, frames: list[dict[str, Any]]) -> bytes:
        if not frames:
            msg = "Empty frames list"
            raise ValueError(msg)
        # Start by deriving root key from master secret and root token_id
        key = hmac.new(self._secret, frames[0]["token_id"].encode(), hashlib.sha256).digest()
        # Chaining: child key = hmac(parent_key, child_token_id)
        for frame in frames[1:]:
            key = hmac.new(key, frame["token_id"].encode(), hashlib.sha256).digest()
        return key

    async def issue(self, subject: AgentId, scopes: list[str]) -> Token:
        """Issue a root auth token for a subject with given scopes.

        Example::

            token = await auth.issue(AgentId("a1"), ["read", "write"])
        """
        now = self._now()
        token_id = str(uuid.uuid4())
        payload = {
            "token_id": token_id,
            "parent_id": None,
            "subject": str(subject),
            "audience": str(subject),
            "scopes": scopes,
            "issued_at": now,
            "expires_at": now + 3600.0,
        }

        # Derive root key
        root_key = hmac.new(self._secret, token_id.encode(), hashlib.sha256).digest()
        self._token_keys[token_id] = root_key

        # Sign payload
        payload_str = json.dumps(payload, sort_keys=True)
        sig = hmac.new(root_key, payload_str.encode(), hashlib.sha256).hexdigest()

        frame = {**payload, "sig": sig}
        return Token(json.dumps([frame]))

    async def delegate(
        self,
        parent_token: Token,
        audience: AgentId,
        scopes_subset: list[str],
        ttl: float,
    ) -> Token:
        """Delegate a sub-token to an audience with a subset of scopes and TTL.

        Example::

            child = await auth.delegate(parent, AgentId("b"), ["read"], ttl=60.0)
        """
        try:
            raw_frames = json.loads(str(parent_token))
            if not isinstance(raw_frames, list) or not raw_frames:
                msg = "Invalid token format"
                raise ValueError(msg)
            parent_frames = cast("list[dict[str, Any]]", raw_frames)
        except Exception as e:
            msg = "Invalid token format"
            raise ValueError(msg) from e

        parent_frame: dict[str, Any] = parent_frames[-1]

        # Verify parent scopes
        parent_scopes: list[str] = parent_frame["scopes"]
        if not set(scopes_subset).issubset(set(parent_scopes)):
            msg = "Scope escalation: child scopes must be a subset of parent scopes"
            raise ValueError(msg)

        # Verify parent TTL
        now = self._now()
        parent_exp: float = parent_frame["expires_at"]
        if now > parent_exp:
            msg = "Parent token has expired"
            raise ValueError(msg)
        if now + ttl > parent_exp:
            msg = "Child TTL exceeds parent remaining lifetime"
            raise ValueError(msg)

        parent_token_id: str = parent_frame["token_id"]

        # Get or derive parent key
        parent_key: bytes | None = self._token_keys.get(parent_token_id)
        if parent_key is None:
            parent_key = self._derive_key_chain(parent_frames)
            self._token_keys[parent_token_id] = parent_key

        # Create child token
        child_token_id = str(uuid.uuid4())
        child_payload: dict[str, Any] = {
            "token_id": child_token_id,
            "parent_id": parent_token_id,
            "subject": parent_frame["subject"],
            "audience": str(audience),
            "scopes": scopes_subset,
            "issued_at": now,
            "expires_at": now + ttl,
        }

        # Derive child key
        child_key = hmac.new(parent_key, child_token_id.encode(), hashlib.sha256).digest()
        self._token_keys[child_token_id] = child_key

        # Sign payload
        payload_str = json.dumps(child_payload, sort_keys=True)
        sig = hmac.new(child_key, payload_str.encode(), hashlib.sha256).hexdigest()

        child_frame: dict[str, Any] = {**child_payload, "sig": sig}

        # New token has all parent frames + child frame
        return Token(json.dumps(parent_frames + [child_frame]))

    async def verify(self, token: Token, presenter: AgentId | None = None) -> AuthContext:
        """Verify a token and return its verified context.

        Example::

            ctx = await auth.verify(token, presenter=AgentId("a1"))
        """
        raw = str(token)
        try:
            raw_frames = json.loads(raw)
            if not isinstance(raw_frames, list) or not raw_frames:
                msg = "Invalid token format"
                raise ValueError(msg)
            frames = cast("list[dict[str, Any]]", raw_frames)
        except Exception as e:
            msg = "Invalid token format"
            raise ValueError(msg) from e

        # 1. Cascading revocation check
        for frame in frames:
            tid: str = frame["token_id"]
            if tid in self._revoked_ids:
                msg = f"Token or an ancestor has been revoked: {tid}"
                raise RevokedAncestorError(msg)

        # 2. Expiration check on all frames in the chain
        now = self._now()
        for frame in frames:
            exp_time: float = frame["expires_at"]
            if exp_time < now:
                msg = "Token or an ancestor has expired"
                raise ValueError(msg)

        # 3. Transitive scope narrowing check
        for i in range(1, len(frames)):
            parent_scopes: list[str] = frames[i - 1]["scopes"]
            child_scopes: list[str] = frames[i]["scopes"]
            if not set(child_scopes).issubset(set(parent_scopes)):
                msg = "Transitive scope escalation detected in token chain"
                raise ValueError(msg)

        # 4. Signature verification along the chain
        root_frame: dict[str, Any] = frames[0]
        root_tid: str = root_frame["token_id"]
        # Derive root key
        root_key = hmac.new(self._secret, root_tid.encode(), hashlib.sha256).digest()
        # Verify root signature
        root_payload: dict[str, Any] = {k: v for k, v in root_frame.items() if k != "sig"}
        root_payload_str = json.dumps(root_payload, sort_keys=True)
        expected_sig = hmac.new(root_key, root_payload_str.encode(), hashlib.sha256).hexdigest()
        root_sig: str = root_frame["sig"]
        if not hmac.compare_digest(root_sig, expected_sig):
            msg = "Invalid root signature"
            raise ValueError(msg)

        current_key = root_key
        # Verify children signatures
        for i in range(1, len(frames)):
            frame = frames[i]
            tid: str = frame["token_id"]
            current_key = hmac.new(current_key, tid.encode(), hashlib.sha256).digest()
            payload: dict[str, Any] = {k: v for k, v in frame.items() if k != "sig"}
            payload_str = json.dumps(payload, sort_keys=True)
            expected_sig = hmac.new(current_key, payload_str.encode(), hashlib.sha256).hexdigest()
            frame_sig: str = frame["sig"]
            if not hmac.compare_digest(frame_sig, expected_sig):
                msg = f"Invalid signature at delegation index {i}"
                raise ValueError(msg)

        # 5. Check audience constraint if presenter is provided
        last_frame: dict[str, Any] = frames[-1]
        if presenter is not None and last_frame["audience"] != str(presenter):
            msg = (
                f"Audience confusion: token intended for {last_frame['audience']} "
                f"but presented by {presenter}"
            )
            raise ValueError(msg)

        # 6. Return AuthContext
        return AuthContext(
            subject=AgentId(last_frame["subject"]),
            scopes=last_frame["scopes"],
            issued_at=last_frame["issued_at"],
            expires_at=last_frame["expires_at"],
        )

    async def revoke(self, token: Token) -> None:
        """Revoke a token (by adding its token_id to the revoked store).

        Example::

            await auth.revoke(token)
        """
        try:
            raw_frames = json.loads(str(token))
            if isinstance(raw_frames, list) and raw_frames:
                frames = cast("list[dict[str, Any]]", raw_frames)
                last_frame = frames[-1]
                tid: str = last_frame["token_id"]
                self._revoked_ids.add(tid)
            else:
                self._revoked_ids.add(str(token))
        except Exception:
            self._revoked_ids.add(str(token))
