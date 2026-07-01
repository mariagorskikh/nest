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

    def _serialize(self, obj: dict[str, Any]) -> bytes:
        """Produce a perfectly stable canonical string (sorted keys, no spaces)."""
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

    async def issue(self, subject: AgentId, scopes: list[str]) -> Token:
        """Issue a root auth token for a subject with given scopes.

        Example::

            token = await auth.issue(AgentId("a1"), ["read", "write"])
        """
        now = self._now()
        root_id = str(uuid.uuid4())
        root_payload = {
            "root_id": root_id,
            "subject": str(subject),
            "audience": str(subject),
            "scopes": scopes,
            "issued_at": now,
            "expires_at": now + 3600.0,
        }

        # Derive root signature
        sig_0 = hmac.new(self._secret, self._serialize(root_payload), hashlib.sha256).digest()

        token_dict = {
            **root_payload,
            "caveats": [],
            "sig": sig_0.hex(),
        }
        return Token(json.dumps(token_dict))

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
            raw_data = json.loads(str(parent_token))
            if not isinstance(raw_data, dict):
                raise ValueError("Invalid token format: root must be an object")
            required_keys = {
                "root_id",
                "subject",
                "audience",
                "scopes",
                "issued_at",
                "expires_at",
                "caveats",
                "sig",
            }
            if not all(k in raw_data for k in required_keys):
                raise ValueError("Invalid token format: missing root keys")
            parent = cast("dict[str, Any]", raw_data)
            if not isinstance(parent["caveats"], list):
                raise ValueError("Invalid token format: caveats must be a list")
        except Exception as e:
            raise ValueError(f"Invalid token format: {e}") from e

        # Get parent scopes and expiration bounds from the end of the chain
        parent_scopes: list[str]
        parent_exp: float
        if parent["caveats"]:
            last_caveat = cast("dict[str, Any]", parent["caveats"][-1])
            parent_scopes = cast("list[str]", last_caveat["scopes"])
            parent_exp = cast("float", last_caveat["expires_at"])
        else:
            parent_scopes = cast("list[str]", parent["scopes"])
            parent_exp = cast("float", parent["expires_at"])

        # Verify parent scopes
        if not set(scopes_subset).issubset(set(parent_scopes)):
            msg = "Scope escalation: child scopes must be a subset of parent scopes"
            raise ValueError(msg)

        # Verify parent TTL
        now = self._now()
        if now > parent_exp:
            msg = "Parent token has expired"
            raise ValueError(msg)
        if now + ttl > parent_exp:
            msg = "Child TTL exceeds parent remaining lifetime"
            raise ValueError(msg)

        # Create new caveat
        new_caveat = {
            "token_id": str(uuid.uuid4()),
            "audience": str(audience),
            "scopes": scopes_subset,
            "expires_at": now + ttl,
        }

        # Chained HMAC delegation signature (Offline: no master secret required!)
        parent_sig_bytes = bytes.fromhex(parent["sig"])
        new_sig_bytes = hmac.new(
            parent_sig_bytes, self._serialize(new_caveat), hashlib.sha256
        ).digest()

        child_token: dict[str, Any] = {
            "root_id": parent["root_id"],
            "subject": parent["subject"],
            "audience": parent["audience"],
            "scopes": parent["scopes"],
            "issued_at": parent["issued_at"],
            "expires_at": parent["expires_at"],
            "caveats": parent["caveats"] + [new_caveat],
            "sig": new_sig_bytes.hex(),
        }
        return Token(json.dumps(child_token))

    async def verify(self, token: Token, presenter: AgentId | None = None) -> AuthContext:
        """Verify a token and return its verified context.

        Example::

            ctx = await auth.verify(token, presenter=AgentId("a1"))
        """
        raw = str(token)
        try:
            raw_data = json.loads(raw)
            if not isinstance(raw_data, dict):
                raise ValueError("Invalid token format: root must be a JSON object")
            required_keys = {
                "root_id",
                "subject",
                "audience",
                "scopes",
                "issued_at",
                "expires_at",
                "caveats",
                "sig",
            }
            if not all(k in raw_data for k in required_keys):
                raise ValueError("Invalid token format: missing root keys")
            data = cast("dict[str, Any]", raw_data)
            if not isinstance(data["caveats"], list):
                raise ValueError("Invalid token format: caveats must be a list")

            required_caveat = {"token_id", "audience", "scopes", "expires_at"}
            caveats: list[dict[str, Any]] = []
            caveats_raw = cast("list[Any]", data["caveats"])
            for caveat_raw in caveats_raw:
                if not isinstance(caveat_raw, dict):
                    raise ValueError("Invalid token format: caveat must be an object")
                caveat = cast("dict[str, Any]", caveat_raw)
                if not all(k in caveat for k in required_caveat):
                    raise ValueError("Invalid token format: missing caveat keys")
                caveats.append(caveat)
        except (json.JSONDecodeError, TypeError, KeyError) as e:
            raise ValueError(f"Invalid token format: {e}") from e

        # 1. Cascading revocation check
        if data["root_id"] in self._revoked_ids:
            raise RevokedAncestorError("Token or an ancestor has been revoked")
        for caveat in caveats:
            if caveat["token_id"] in self._revoked_ids:
                raise RevokedAncestorError("Token or an ancestor has been revoked")

        # 2. Expiration check on all frames in the chain
        now = self._now()
        if data["expires_at"] < now:
            raise ValueError("Token or an ancestor has expired")
        for caveat in caveats:
            if caveat["expires_at"] < now:
                raise ValueError("Token or an ancestor has expired")

        # 3. Transitive scope & TTL monotonicity check
        parent_scopes = cast("list[str]", data["scopes"])
        parent_exp = cast("float", data["expires_at"])
        for caveat in caveats:
            caveat_scopes = cast("list[str]", caveat["scopes"])
            if not set(caveat_scopes).issubset(set(parent_scopes)):
                raise ValueError("Transitive scope escalation detected in token chain")
            caveat_exp = cast("float", caveat["expires_at"])
            if caveat_exp > parent_exp:
                raise ValueError("Transitive TTL escalation detected in token chain")
            parent_scopes = caveat_scopes
            parent_exp = caveat_exp

        # 4. Signature verification chain re-derivation (reconstruct from root down to tail)
        root_payload = {
            "root_id": data["root_id"],
            "subject": data["subject"],
            "audience": data["audience"],
            "scopes": data["scopes"],
            "issued_at": data["issued_at"],
            "expires_at": data["expires_at"],
        }
        current_sig = hmac.new(self._secret, self._serialize(root_payload), hashlib.sha256).digest()
        for caveat in caveats:
            current_sig = hmac.new(current_sig, self._serialize(caveat), hashlib.sha256).digest()

        expected_sig_hex = current_sig.hex()
        if not hmac.compare_digest(data["sig"], expected_sig_hex):
            raise ValueError("Invalid token signature chain")

        # 5. Check audience constraint
        if caveats:
            last_caveat = caveats[-1]
            last_aud = cast("str", last_caveat["audience"])
            last_scopes = cast("list[str]", last_caveat["scopes"])
            last_exp = cast("float", last_caveat["expires_at"])
        else:
            last_aud = cast("str", data["audience"])
            last_scopes = cast("list[str]", data["scopes"])
            last_exp = cast("float", data["expires_at"])

        if presenter is not None and last_aud != str(presenter):
            msg = f"Audience confusion: token intended for {last_aud} but presented by {presenter}"
            raise ValueError(msg)

        # 6. Return AuthContext
        return AuthContext(
            subject=AgentId(data["subject"]),
            scopes=last_scopes,
            issued_at=data["issued_at"],
            expires_at=last_exp,
        )

    async def revoke(self, token: Token) -> None:
        """Revoke a token (by adding its token_id to the revoked store).

        Example::

            await auth.revoke(token)
        """
        try:
            raw_data = json.loads(str(token))
            if isinstance(raw_data, dict):
                data = cast("dict[str, Any]", raw_data)
                if data.get("caveats"):
                    tid: str = data["caveats"][-1]["token_id"]
                else:
                    tid = data["root_id"]
                self._revoked_ids.add(tid)
            else:
                self._revoked_ids.add(str(token))
        except Exception:
            self._revoked_ids.add(str(token))
