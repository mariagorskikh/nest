# SPDX-License-Identifier: Apache-2.0
"""Latency middleware — deterministic per-hop delivery delay."""

from __future__ import annotations

from typing import Any

from nest_core.sim.middleware import MessageContext, MessageMiddleware


class LatencyMiddleware(MessageMiddleware):
    """Add deterministic delivery delay using the simulation RNG."""

    def __init__(self, *, config: dict[str, Any] | None = None) -> None:
        cfg = config or {}
        self._base_delay = float(cfg.get("base_delay", 0.001))
        self._jitter = float(cfg.get("jitter", 0.001))

    async def on_send(self, ctx: MessageContext) -> MessageContext | None:
        jitter = ctx.rng.uniform(0.0, self._jitter) if self._jitter > 0 else 0.0
        ctx.metadata["deliver_at"] = ctx.now + self._base_delay + jitter
        return ctx

    async def on_receive(self, ctx: MessageContext) -> MessageContext | None:
        return ctx
