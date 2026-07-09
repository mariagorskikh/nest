# SPDX-License-Identifier: Apache-2.0
"""Streaming payments scenario: buyers open streams to sellers, drain ticks, close.

Runs a deterministic marketplace of 5 buyers and 5 sellers where each buyer
opens a rate-limited stream to a seller, the stream drains one tick per logical
round, and streams are closed or refunded at the end.

Designed to stress the ``streaming`` payments plugin under:
* concurrent stream pressure (5-10 simultaneous bilateral streams)
* mid-stream cancellation (closing before max_total)
* refund of unused remainder
* conservation-of-funds invariant at every tick

Example::

    agents = streaming_payments_factory(config, plugins)
"""

from __future__ import annotations

import contextlib
import json
from typing import Any, cast

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId, PaymentRef

# ---------------------------------------------------------------------------
# Event helpers
# ---------------------------------------------------------------------------


def _json(data: dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()


def _load(payload: bytes) -> dict[str, Any]:
    try:
        data: object = json.loads(payload.decode("utf-8"))
    except json.JSONDecodeError:
        return {}
    return cast("dict[str, Any]", data) if isinstance(data, dict) else {}


async def _audit(ctx: AgentContext, data: dict[str, Any]) -> None:
    event = {"type": "streaming_audit", "tick": int(ctx.time), **data}
    await ctx.send(ctx.agent_id, _json(event))


# ---------------------------------------------------------------------------
# Buyer agent
# ---------------------------------------------------------------------------


class StreamingBuyer(StateMachineAgent):
    """Buyer that opens a stream to a seller and drains it tick-by-tick.

    On start: opens a stream to the assigned seller.
    On tick (message from scheduler): drains one tick, checks if max reached.
    On stop: closes any remaining open stream.
    """

    def __init__(
        self,
        seller: AgentId,
        rate_per_tick: int,
        max_total: int,
        close_early: bool = False,
        close_tick: int = 100,
    ) -> None:
        super().__init__()
        self._seller = seller
        self._rate_per_tick = rate_per_tick
        self._max_total = max_total
        self._close_early = close_early
        self._close_tick = close_tick
        self._ref: PaymentRef | None = None
        self._opened = False
        self._closed = False

    async def on_start(self, ctx: AgentContext) -> None:
        if not self._opened:
            self._ref = PaymentRef(f"stream-{ctx.agent_id}-{self._seller}")
            payments = ctx.plugins.get("payments")
            if payments is not None:
                try:
                    _ = await payments.open_stream(
                        to=self._seller,
                        rate_per_tick=self._rate_per_tick,
                        max_total=self._max_total,
                        ref=self._ref,
                        current_tick=int(ctx.time),
                    )
                    self._opened = True
                    await _audit(
                        ctx,
                        {
                            "kind": "payment_debited",
                            "event_type": "stream_opened",
                            "stream_ref": str(self._ref),
                            "to": str(self._seller),
                            "rate_per_tick": self._rate_per_tick,
                            "max_total": self._max_total,
                            "agent": str(ctx.agent_id),
                            "amount": self._rate_per_tick,
                        },
                    )
                except Exception:
                    pass

    async def on_message(
        self,
        ctx: AgentContext,
        sender: AgentId,
        payload: bytes,
    ) -> None:
        data = _load(payload)
        if data.get("kind") == "tick":
            await self._on_tick(ctx, int(ctx.time))

    async def _on_tick(self, ctx: AgentContext, tick: int) -> None:
        if not self._opened or self._closed:
            return
        payments = ctx.plugins.get("payments")
        if payments is None or self._ref is None:
            return

        still_open = True
        try:
            still_open = await payments.tick_stream(self._ref, tick)
            _ = payments.stream(self._ref) if hasattr(payments, "stream") else None
        except Exception:
            pass

        await _audit(
            ctx,
            {
                "kind": "payment_debited",
                "stream_ref": str(self._ref),
                "agent": str(ctx.agent_id),
                "tick": tick,
                "amount": self._rate_per_tick,
            },
        )

        if (
            not still_open or (self._close_early and tick >= self._close_tick)
        ) and not self._closed:
            with contextlib.suppress(Exception):
                await payments.close_stream(self._ref)
            self._closed = True
            await _audit(
                ctx,
                {
                    "kind": "payment_debited",
                    "event_type": "stream_closed",
                    "stream_ref": str(self._ref),
                    "agent": str(ctx.agent_id),
                    "tick": tick,
                    "amount": self._rate_per_tick,
                },
            )

    async def on_stop(self, ctx: AgentContext) -> None:
        if self._opened and not self._closed:
            payments = ctx.plugins.get("payments")
            if payments is not None and self._ref is not None:
                with contextlib.suppress(Exception):
                    await payments.close_stream(self._ref)
                self._closed = True
                await _audit(
                    ctx,
                    {
                        "kind": "payment_debited",
                        "event_type": "stream_closed",
                        "stream_ref": str(self._ref),
                        "agent": str(ctx.agent_id),
                        "tick": int(ctx.time),
                        "amount": self._rate_per_tick,
                    },
                )


# ---------------------------------------------------------------------------
# Seller agent
# ---------------------------------------------------------------------------


class StreamingSeller(StateMachineAgent):
    """Seller that receives streaming payments from buyers.

    Listens for crediting events and tracks balance.
    """

    async def on_start(self, ctx: AgentContext) -> None:
        pass

    async def on_message(
        self,
        ctx: AgentContext,
        sender: AgentId,
        payload: bytes,
    ) -> None:
        data = _load(payload)
        if (
            data.get("kind") == "payment_debited" or data.get("type") == "streaming_audit"
        ) and data.get("kind") == "payment_debited":
            await _audit(
                ctx,
                {
                    "kind": "payment_credited",
                    "stream_ref": data.get("stream_ref", ""),
                    "agent": str(ctx.agent_id),
                    "tick": int(ctx.time),
                    "amount": data.get("amount", 0),
                },
            )

    async def on_stop(self, ctx: AgentContext) -> None:
        pass


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def streaming_payments_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create agents for the streaming payments scenario.

    Example::

        agents = streaming_payments_factory(config, plugins)
    """
    agents: dict[AgentId, StateMachineAgent] = {}

    buyers: int = 5
    sellers_count: int = 5
    rate: int = 50
    max_total: int = 500
    close_early_pct: float = 0.2
    close_tick_base: int = 50

    seller_ids: list[AgentId] = [AgentId(f"seller-{i}") for i in range(sellers_count)]

    for i in range(buyers):
        buyer_id = AgentId(f"buyer-{i}")
        seller_id: AgentId = seller_ids[i % sellers_count]
        close_early = (i / max(buyers, 1)) < close_early_pct
        agents[buyer_id] = StreamingBuyer(
            seller=seller_id,
            rate_per_tick=rate,
            max_total=max_total,
            close_early=close_early,
            close_tick=close_tick_base + i * 5,
        )

    for i in range(sellers_count):
        agents[seller_ids[i]] = StreamingSeller()

    return agents
