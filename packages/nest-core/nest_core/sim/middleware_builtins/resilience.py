# SPDX-License-Identifier: Apache-2.0
"""Resilience middleware — isolate agent delivery failures."""

from __future__ import annotations

from typing import Any

from nest_core.sim.middleware import DeliveryErrorMiddleware, MessageContext, MessageMiddleware


class ResilienceMiddleware(MessageMiddleware, DeliveryErrorMiddleware):
    """Swallow ``on_message`` exceptions so one agent cannot crash the run."""

    def __init__(self, *, config: dict[str, Any] | None = None) -> None:
        del config

    async def on_send(self, ctx: MessageContext) -> MessageContext | None:
        return ctx

    async def on_receive(self, ctx: MessageContext) -> MessageContext | None:
        return ctx

    async def on_delivery_error(self, ctx: MessageContext, error: BaseException) -> bool:
        del ctx, error
        return True
