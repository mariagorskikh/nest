# SPDX-License-Identifier: Apache-2.0
"""Observability middleware — structured per-message counters and logging."""

from __future__ import annotations

from typing import Any

from nest_core.log import get_logger
from nest_core.sim.middleware import MessageContext, MessageMiddleware

log = get_logger(__name__)


class ObservabilityMiddleware(MessageMiddleware):
    """Emit structured logs and in-memory counters for message traffic."""

    def __init__(self, *, config: dict[str, Any] | None = None) -> None:
        del config
        self.sent_count = 0
        self.received_count = 0
        self.dropped_count = 0

    async def on_send(self, ctx: MessageContext) -> MessageContext | None:
        self.sent_count += 1
        log.debug(
            "middleware_send",
            sender=str(ctx.sender),
            recipient=str(ctx.recipient),
            size=len(ctx.payload),
            ts=ctx.now,
        )
        return ctx

    async def on_receive(self, ctx: MessageContext) -> MessageContext | None:
        self.received_count += 1
        log.debug(
            "middleware_receive",
            sender=str(ctx.sender),
            recipient=str(ctx.recipient),
            size=len(ctx.payload),
            ts=ctx.now,
        )
        return ctx
