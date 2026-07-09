# SPDX-License-Identifier: Apache-2.0
"""Message middleware for the Tier 1 simulator.
Composable hooks on outbound (send/broadcast) and inbound (receive) paths.
Deterministic: middleware must use the simulation clock and seeded RNG from
``MessageContext``, never wall-clock time or unseeded randomness.
Example::
    chain = MiddlewareChain([ObservabilityMiddleware()])
    ctx = MessageContext(sender=AgentId("a1"), recipient=AgentId("a2"), ...)
    result = await chain.on_send(ctx)
"""

from __future__ import annotations
import random
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol, runtime_checkable
from nest_core.types import AgentId, CorrelationId


def _empty_str_any_dict() -> dict[str, Any]:
    return {}


@dataclass
class MessageContext:
    """Mutable context for a single message crossing a middleware seam."""

    sender: AgentId
    recipient: AgentId
    payload: bytes
    correlation_id: CorrelationId | None
    now: float
    rng: random.Random
    direction: Literal["send", "receive"]
    plugins: dict[str, Any] = field(default_factory=_empty_str_any_dict)
    metadata: dict[str, Any] = field(default_factory=_empty_str_any_dict)
    drop: bool = False


@runtime_checkable
class MessageMiddleware(Protocol):
    """Hook invoked on outbound or inbound message paths."""

    async def on_send(self, ctx: MessageContext) -> MessageContext | None:
        """Transform or drop an outbound message. Return ``None`` to drop."""

    async def on_receive(self, ctx: MessageContext) -> MessageContext | None:
        """Transform or drop an inbound message. Return ``None`` to drop."""


@runtime_checkable
class DeliveryErrorMiddleware(Protocol):
    """Optional hook for middleware that handles agent delivery failures."""

    async def on_delivery_error(self, ctx: MessageContext, error: BaseException) -> bool:
        """Return ``True`` to swallow the error and continue the simulation."""
        ...


class MiddlewareChain:
    """Compose an ordered list of middleware into send/receive pipelines."""

    def __init__(
        self,
        middlewares: list[MessageMiddleware] | None = None,
        *,
        trace: Any | None = None,
    ) -> None:
        self._middlewares = list(middlewares or [])
        self._trace = trace

    @property
    def middlewares(self) -> list[MessageMiddleware]:
        return list(self._middlewares)

    def has_delivery_error_handlers(self) -> bool:
        return any(isinstance(mw, DeliveryErrorMiddleware) for mw in self._middlewares)

    async def on_send(self, ctx: MessageContext) -> MessageContext | None:
        current = ctx
        for mw in self._middlewares:
            before = current.payload
            result = await mw.on_send(current)
            if result is None:
                self._record_action(mw, current, "drop", "send", before_payload=before)
                return None
            if result.payload != before:
                self._record_action(mw, result, "transform", "send", before_payload=before)
            current = result
        return current

    async def on_receive(self, ctx: MessageContext) -> MessageContext | None:
        current = ctx
        for mw in self._middlewares:
            before = current.payload
            result = await mw.on_receive(current)
            if result is None:
                self._record_action(mw, current, "drop", "receive", before_payload=before)
                return None
            if result.payload != before:
                self._record_action(mw, result, "transform", "receive", before_payload=before)
            current = result
        return current

    async def run_delivery(
        self,
        ctx: MessageContext,
        deliver: Callable[[], Awaitable[None]],
    ) -> None:
        """Run ``deliver`` with optional delivery-error middleware."""
        try:
            await deliver()
        except BaseException as exc:
            for mw in self._middlewares:
                if isinstance(mw, DeliveryErrorMiddleware) and await mw.on_delivery_error(ctx, exc):
                    if self._trace is not None:
                        self._trace.record(
                            {
                                "ts": ctx.now,
                                "agent": str(ctx.recipient),
                                "kind": "error",
                                "from": str(ctx.sender),
                                "error": type(exc).__name__,
                                "detail": str(exc),
                            }
                        )
                    return
            raise

    def _record_action(
        self,
        mw: MessageMiddleware,
        ctx: MessageContext,
        action: str,
        direction: str,
        *,
        before_payload: bytes,
    ) -> None:
        if self._trace is None:
            return
        self._trace.record(
            {
                "ts": ctx.now,
                "agent": str(ctx.sender if direction == "send" else ctx.recipient),
                "kind": "middleware",
                "middleware": type(mw).__name__,
                "action": action,
                "direction": direction,
                "from": str(ctx.sender),
                "to": str(ctx.recipient),
                "size": len(ctx.payload),
                "before_size": len(before_payload),
            }
        )
