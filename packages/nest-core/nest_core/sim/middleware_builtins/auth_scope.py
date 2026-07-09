# SPDX-License-Identifier: Apache-2.0
"""Auth scope middleware — enforce bearer tokens on inbound messages."""

from __future__ import annotations

import base64
import json
from typing import Any, cast

from nest_core.sim.middleware import MessageContext, MessageMiddleware
from nest_core.types import Token


def _extract_auth_token(payload: bytes) -> str | None:
    """Read a bearer token from nest-native JSON metadata when present."""
    try:
        data = cast("dict[str, Any]", json.loads(payload.decode("utf-8")))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    metadata_raw = data.get("metadata")
    if isinstance(metadata_raw, dict):
        meta = cast("dict[str, Any]", metadata_raw)
        token = meta.get("auth_token")
        if token is not None:
            return str(token)
    envelope = data.get("nest_auth")
    if envelope is not None:
        return str(envelope)
    return None


class AuthScopeMiddleware(MessageMiddleware):
    """Verify inbound messages carry a valid token with a required scope."""

    def __init__(self, *, config: dict[str, Any] | None = None) -> None:
        cfg = config or {}
        self._required_scope = str(cfg.get("required_scope", "read"))
        self._denied_count = 0

    @property
    def denied_count(self) -> int:
        return self._denied_count

    async def on_send(self, ctx: MessageContext) -> MessageContext | None:
        return ctx

    async def on_receive(self, ctx: MessageContext) -> MessageContext | None:
        auth = ctx.plugins.get("auth")
        if auth is None:
            self._denied_count += 1
            ctx.metadata["deny_reason"] = "auth_plugin_missing"
            ctx.drop = True
            return None

        token_raw = _extract_auth_token(ctx.payload)
        if token_raw is None:
            self._denied_count += 1
            ctx.metadata["deny_reason"] = "missing_auth_token"
            ctx.drop = True
            return None

        try:
            auth_ctx = await auth.verify(Token(token_raw))
        except ValueError as exc:
            self._denied_count += 1
            ctx.metadata["deny_reason"] = str(exc)
            ctx.drop = True
            return None

        if self._required_scope not in auth_ctx.scopes:
            self._denied_count += 1
            ctx.metadata["deny_reason"] = f"missing_scope:{self._required_scope}"
            ctx.drop = True
            return None

        ctx.metadata["auth_subject"] = str(auth_ctx.subject)
        return ctx


def attach_auth_token(payload: bytes, token: str) -> bytes:
    """Helper for tests: embed a token in nest-native JSON metadata."""
    try:
        data = cast("dict[str, Any]", json.loads(payload.decode("utf-8")))
    except (UnicodeDecodeError, json.JSONDecodeError):
        wrapped = {
            "nest_auth": token,
            "payload": base64.b64encode(payload).decode("ascii"),
        }
        return json.dumps(wrapped, sort_keys=True).encode("utf-8")

    metadata = dict(cast("dict[str, Any]", data.get("metadata", {})))
    metadata["auth_token"] = token
    data["metadata"] = metadata
    return json.dumps(data, sort_keys=True).encode("utf-8")
