# SPDX-License-Identifier: Apache-2.0
"""Streaming payments scenario: buyers open streams to sellers, drain ticks, close.

Runs a deterministic marketplace of 5 buyers and 5 sellers where each buyer
opens a rate-limited stream to a seller, the stream drains one tick per logical
round (self-scheduled, not driven by an external tick broadcast), and streams
are closed (naturally exhausted, early-closed, or closed at shutdown) before
the run ends.

Designed to stress the ``streaming`` payments plugin under:
* concurrent stream pressure (5-10 simultaneous bilateral streams)
* mid-stream cancellation (closing before max_total)
* conservation-of-funds invariant at every tick

Each buyer and seller is given its own instance of the resolved payments
plugin via the ``_agent_plugins`` override channel (see
``escrow_marketplace.py``'s ``_instance`` pattern), sharing one ledger of
balances/payments/streams across all ten agents so debits and credits are
mutually visible for conservation checks.

Example::

    agents = streaming_payments_factory(config, plugins)
"""

from __future__ import annotations

import json
from typing import Any, cast

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId, PaymentRef

# ---------------------------------------------------------------------------
# Event helpers
# ---------------------------------------------------------------------------


def _int(value: object, default: int = 0) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return default
    return default


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

    On start: opens a stream to the assigned seller and self-schedules every
    tick it will drive for the rest of the run (scheduling all ticks upfront,
    rather than chaining "schedule the next tick from this tick", means a
    single dropped self-message only skips that one tick instead of
    permanently halting the buyer -- self-scheduled messages are subject to
    the same ``message_drop_rate`` as any other message).
    On tick: drains one tick, closes early or on exhaustion.
    On stop: closes any remaining open stream (idempotent backstop).
    """

    def __init__(
        self,
        seller: AgentId,
        rate_per_tick: int,
        max_total: int,
        n_ticks: int,
        close_early: bool = False,
        close_tick: int = 100,
    ) -> None:
        super().__init__()
        self._seller = seller
        self._rate_per_tick = rate_per_tick
        self._max_total = max_total
        self._n_ticks = n_ticks
        self._close_early = close_early
        self._close_tick = close_tick
        self._ref: PaymentRef | None = None
        self._opened = False
        self._closed = False

    async def _emit_debit_credit(
        self,
        ctx: AgentContext,
        *,
        tick: int,
        amount: int,
        event_type: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        """Emit matching debit/credit audit events for the same tick.

        Co-emitting both sides from the buyer (rather than having the seller
        separately observe and emit its own credit) keeps debit and credit
        atomic at the same tick, avoiding a scheduling race against
        ``validate_streaming_conservation_per_tick`` (which requires
        debited == credited at every tick boundary).
        """
        debit: dict[str, Any] = {
            "kind": "payment_debited",
            "stream_ref": str(self._ref),
            "agent": str(ctx.agent_id),
            "tick": tick,
            "amount": amount,
        }
        if event_type:
            debit["event_type"] = event_type
        if extra:
            debit.update(extra)
        await _audit(ctx, debit)

        if amount:
            credit = {
                "kind": "payment_credited",
                "stream_ref": str(self._ref),
                "agent": str(self._seller),
                "tick": tick,
                "amount": amount,
            }
            await _audit(ctx, credit)

    async def on_start(self, ctx: AgentContext) -> None:
        if self._opened:
            return
        self._ref = PaymentRef(f"stream-{ctx.agent_id}-{self._seller}")
        payments = ctx.plugins["payments"]
        tick = int(ctx.time)

        try:
            handle = await payments.open_stream(
                to=self._seller,
                rate_per_tick=self._rate_per_tick,
                max_total=self._max_total,
                ref=self._ref,
                current_tick=tick,
            )
        except AttributeError:
            # The configured payments plugin has no streaming protocol
            # (e.g. the ``prepaid_credits`` baseline) -- nothing to drive.
            return
        self._opened = True

        amount = 0
        if (
            handle.entries
            and handle.entries[-1].tick == tick
            and handle.entries[-1].kind == "debit"
        ):
            amount = handle.entries[-1].amount

        await self._emit_debit_credit(
            ctx,
            tick=tick,
            amount=amount,
            event_type="stream_opened",
            extra={
                "to": str(self._seller),
                "rate_per_tick": self._rate_per_tick,
                "max_total": self._max_total,
            },
        )

        for t in range(1, self._n_ticks + 1):
            await ctx.schedule(float(t), _json({"kind": "tick"}))

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
        if not self._opened or self._closed or self._ref is None:
            return
        payments = ctx.plugins["payments"]

        still_open = await payments.tick_stream(self._ref, tick)

        handle = payments.stream(self._ref)
        amount = 0
        if (
            handle
            and handle.entries
            and handle.entries[-1].tick == tick
            and handle.entries[-1].kind == "debit"
        ):
            amount = handle.entries[-1].amount
        if amount:
            await self._emit_debit_credit(ctx, tick=tick, amount=amount)

        should_close = (not still_open) or (self._close_early and tick >= self._close_tick)
        if should_close and not self._closed:
            await payments.close_stream(self._ref)
            self._closed = True
            await self._emit_debit_credit(
                ctx,
                tick=tick,
                amount=0,
                event_type="stream_closed",
            )

    async def on_stop(self, ctx: AgentContext) -> None:
        if self._opened and not self._closed and self._ref is not None:
            payments = ctx.plugins["payments"]
            await payments.close_stream(self._ref)
            self._closed = True
            await self._emit_debit_credit(
                ctx,
                tick=int(ctx.time),
                amount=0,
                event_type="stream_closed",
            )


# ---------------------------------------------------------------------------
# Seller agent
# ---------------------------------------------------------------------------


class StreamingSeller(StateMachineAgent):
    """Seller that receives streaming payments from buyers.

    Passive: the buyer emits the seller's ``payment_credited`` audit
    directly (see ``StreamingBuyer._emit_debit_credit``), so this agent does
    not need to react to anything itself. It still needs its own
    ``_agent_plugins`` override so its balance is represented in the shared
    ledger the conservation validators reconstruct.
    """

    async def on_start(self, ctx: AgentContext) -> None:
        pass

    async def on_message(
        self,
        ctx: AgentContext,
        sender: AgentId,
        payload: bytes,
    ) -> None:
        pass

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

    Every buyer and seller gets its own instance of the resolved payments
    plugin, installed via the ``_agent_plugins`` override channel and
    sharing one ledger (balances/payments/streams), mirroring the pattern in
    ``escrow_marketplace_factory``.

    Example::

        agents = streaming_payments_factory(config, plugins)
    """
    payments_cls = plugins["payments"]
    agents: dict[AgentId, StateMachineAgent] = {}
    overrides: dict[AgentId, dict[str, Any]] = {}

    shared_balances: dict[AgentId, int] = {}
    shared_payments: dict[PaymentRef, Any] = {}
    shared_streams: dict[PaymentRef, Any] = {}

    def _instance(agent_id: AgentId) -> Any:
        try:
            return payments_cls(
                agent_id,
                initial_balance=1000,
                balances=shared_balances,
                payments=shared_payments,
                streams=shared_streams,
            )
        except TypeError:
            try:
                return payments_cls(
                    agent_id,
                    initial_balance=1000,
                    balances=shared_balances,
                    payments=shared_payments,
                )
            except TypeError:
                return payments_cls(agent_id, initial_balance=1000)

    buyers: int = 5
    sellers_count: int = 5
    rate: int = 50
    max_total: int = 500
    close_early_pct: float = 0.2
    close_tick_base: int = 50
    n_ticks: int = _int(config.task.config.get("rounds"), default=100)

    seller_ids: list[AgentId] = [AgentId(f"seller-{i}") for i in range(sellers_count)]

    for i in range(buyers):
        buyer_id = AgentId(f"buyer-{i}")
        seller_id: AgentId = seller_ids[i % sellers_count]
        close_early = (i / max(buyers, 1)) < close_early_pct
        agents[buyer_id] = StreamingBuyer(
            seller=seller_id,
            rate_per_tick=rate,
            max_total=max_total,
            n_ticks=n_ticks,
            close_early=close_early,
            close_tick=close_tick_base + i * 5,
        )
        overrides[buyer_id] = {"payments": _instance(buyer_id)}

    for i in range(sellers_count):
        agents[seller_ids[i]] = StreamingSeller()
        overrides[seller_ids[i]] = {"payments": _instance(seller_ids[i])}

    plugins["_agent_plugins"] = overrides
    return agents
