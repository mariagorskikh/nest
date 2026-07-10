# SPDX-License-Identifier: Apache-2.0
"""Streaming payments scenario — buyers meter payments to sellers per tick.

Five buyers open rolling streams to five sellers. Each tick the buyer sends work;
the seller acknowledges delivery, which arms the next per-tick debit. Under
network partition the seller never receives work, so billing stops. Audit events
are written via :meth:`AgentContext.record_event` for the three streaming
validators.

Example::

    agents = streaming_payments_factory(config, plugins)
"""

from __future__ import annotations

from typing import Any

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId, PaymentRef, PaymentStatus

_OP_WORK = b"op:work"
_OP_ACK = b"op:ack"
_OP_TICK = b"op:tick"
_OP_CLOSE = b"op:close"
_OP_OPEN_NEXT = b"op:open_next"


def _parse_op(payload: bytes) -> tuple[str, dict[str, str]]:
    text = payload.decode("utf-8", errors="replace")
    if not text.startswith("op:"):
        return "", {}
    parts = text.split(":")
    if len(parts) < 2:
        return "", {}
    op = parts[1]
    fields: dict[str, str] = {}
    for piece in parts[2:]:
        if "=" in piece:
            key, _, value = piece.partition("=")
            fields[key] = value
    return op, fields


def _emit(op: str, **fields: str | int) -> bytes:
    body = ":".join(f"{k}={v}" for k, v in fields.items())
    return f"op:{op}:{body}".encode() if body else f"op:{op}".encode()


def _record_debit(
    ctx: AgentContext,
    *,
    ref: str,
    payer: AgentId,
    payee: AgentId,
    amount: int,
) -> None:
    tick = int(ctx.time)
    ctx.record_event(
        {
            "kind": "payment_debited",
            "stream_ref": ref,
            "agent": str(payer),
            "to": str(payee),
            "amount": amount,
            "tick": tick,
        }
    )
    ctx.record_event(
        {
            "kind": "payment_credited",
            "stream_ref": ref,
            "agent": str(payee),
            "from": str(payer),
            "amount": amount,
            "tick": tick,
        }
    )


class StreamingBuyerAgent(StateMachineAgent):
    """Buyer that opens metered streams and debits only after seller acks work.

    Example::

        agent = StreamingBuyerAgent(
            AgentId("buyer-0"),
            seller=AgentId("seller-0"),
            pair_index=0,
            rounds=20,
            rate_per_tick=10,
            max_total=100,
            stream_length=5,
        )
    """

    def __init__(
        self,
        agent_id: AgentId,
        *,
        seller: AgentId,
        pair_index: int,
        rounds: int,
        rate_per_tick: int,
        max_total: int,
        stream_length: int,
    ) -> None:
        self._id = agent_id
        self._seller = seller
        self._pair_index = pair_index
        self._rounds = rounds
        self._rate = rate_per_tick
        self._max_total = max_total
        self._stream_length = stream_length
        self._round = 0
        self._tick_in_stream = 0
        self._active_ref: PaymentRef | None = None
        self._pending_ref: PaymentRef | None = None

    def _stream_ref(self, round_idx: int) -> PaymentRef:
        return PaymentRef(f"stream-{self._pair_index}-{round_idx}")

    async def on_start(self, ctx: AgentContext) -> None:
        """Open the first stream and schedule the first work tick."""
        await self._open_stream(ctx, self._stream_ref(0))

    async def _open_stream(self, ctx: AgentContext, ref: PaymentRef) -> None:
        payments = ctx.plugins.get("payments")
        if payments is None or not hasattr(payments, "open_stream"):
            return

        tick = int(ctx.time)
        handle = await payments.open_stream(
            self._seller,
            self._rate,
            self._max_total,
            ref,
            opened_at_tick=tick,
        )
        self._active_ref = ref
        self._tick_in_stream = 0
        ctx.record_event(
            {
                "event_type": "stream_opened",
                "stream_ref": str(ref),
                "agent": str(self._id),
                "to": str(self._seller),
                "tick": tick,
            }
        )
        _record_debit(
            ctx,
            ref=str(ref),
            payer=self._id,
            payee=self._seller,
            amount=handle.total_debited,
        )
        await ctx.schedule(1.0, _emit("tick", ref=str(ref), n="1"))

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Handle scheduled ticks, seller acks, and stream lifecycle."""
        op, fields = _parse_op(payload)
        if op == "ack":
            await self._on_ack(ctx, fields)
        elif op == "tick":
            await self._on_tick(ctx, fields)
        elif op == "close":
            await self._on_close(ctx, fields)
        elif op == "open_next":
            await self._on_open_next(ctx, fields)

    async def _on_tick(self, ctx: AgentContext, fields: dict[str, str]) -> None:
        ref = PaymentRef(fields.get("ref", ""))
        if ref != self._active_ref:
            return

        await ctx.send(self._seller, _emit("work", ref=str(ref), tick=str(int(ctx.time))))

        self._tick_in_stream += 1
        if self._tick_in_stream >= self._stream_length:
            await ctx.schedule(1.0, _emit("close", ref=str(ref)))
            if self._round + 1 < self._rounds:
                self._pending_ref = self._stream_ref(self._round + 1)
                await ctx.schedule(2.0, _emit("open_next", ref=str(self._pending_ref)))
        else:
            n = str(self._tick_in_stream + 1)
            await ctx.schedule(1.0, _emit("tick", ref=str(ref), n=n))

    async def _on_ack(self, ctx: AgentContext, fields: dict[str, str]) -> None:
        ref = PaymentRef(fields.get("ref", ""))
        if ref != self._active_ref:
            return

        payments = ctx.plugins.get("payments")
        if payments is None:
            return

        tick = int(ctx.time)
        before = payments.stream_total_debited(ref)
        still_open = await payments.advance_stream(ref, tick)
        after = payments.stream_total_debited(ref)

        delta = after - before
        if delta > 0:
            _record_debit(
                ctx,
                ref=str(ref),
                payer=self._id,
                payee=self._seller,
                amount=delta,
            )

        if not still_open and (await payments.verify_payment(ref)) == PaymentStatus.STREAMING:
            await self._finalize_close(ctx, ref)

    async def _on_close(self, ctx: AgentContext, fields: dict[str, str]) -> None:
        ref = PaymentRef(fields.get("ref", ""))
        if ref != self._active_ref:
            return
        await self._finalize_close(ctx, ref)
        self._round += 1

    async def _on_open_next(self, ctx: AgentContext, fields: dict[str, str]) -> None:
        ref = PaymentRef(fields.get("ref", ""))
        if self._active_ref is not None and ref == self._pending_ref:
            await self._open_stream(ctx, ref)

    async def _finalize_close(self, ctx: AgentContext, ref: PaymentRef) -> None:
        payments = ctx.plugins.get("payments")
        if payments is None:
            return
        if (await payments.verify_payment(ref)) != PaymentStatus.STREAMING:
            return

        tick = int(ctx.time)
        await payments.close_stream(ref, current_tick=tick)
        ctx.record_event(
            {
                "event_type": "stream_closed",
                "stream_ref": str(ref),
                "agent": str(self._id),
                "to": str(self._seller),
                "tick": tick,
            }
        )
        if self._active_ref == ref:
            self._active_ref = None


class StreamingSellerAgent(StateMachineAgent):
    """Seller that acknowledges work so the buyer may advance the stream.

    Example::

        agent = StreamingSellerAgent(AgentId("seller-0"))
    """

    def __init__(self, agent_id: AgentId) -> None:
        self._id = agent_id

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Acknowledge delivered work so the buyer can debit the next tick."""
        op, fields = _parse_op(payload)
        if op != "work":
            return

        ref = PaymentRef(fields.get("ref", ""))
        payments = ctx.plugins.get("payments")
        if payments is not None:
            await payments.acknowledge_work(ref, tick=int(ctx.time))

        await ctx.send(sender, _emit("ack", ref=str(ref), tick=str(int(ctx.time))))


def streaming_payments_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create paired buyers and sellers for the streaming payments scenario.

    Example::

        agents = streaming_payments_factory(config, plugins)
    """
    task = config.task.config
    rounds = int(task.get("rounds", 100))
    rate_per_tick = int(task.get("rate_per_tick", 10))
    max_total = int(task.get("max_total", 100))
    stream_length = int(task.get("stream_length", 5))

    buyer_count = 0
    seller_count = 0
    buyer_balance = 5000
    seller_balance = 100
    for role in config.agents.roles:
        if role.name == "buyer":
            buyer_count = role.count
            buyer_balance = int(role.config.get("initial_balance", buyer_balance))
        elif role.name == "seller":
            seller_count = role.count
            seller_balance = int(role.config.get("initial_balance", seller_balance))

    if buyer_count == 0 or seller_count == 0:
        buyer_count = config.agents.count // 2
        seller_count = config.agents.count - buyer_count

    buyer_ids = [AgentId(f"buyer-{i}") for i in range(buyer_count)]
    seller_ids = [AgentId(f"seller-{i}") for i in range(seller_count)]
    all_ids = buyer_ids + seller_ids

    _instantiate_plugins(
        plugins,
        all_ids,
        buyer_balance=buyer_balance,
        seller_balance=seller_balance,
    )

    agents: dict[AgentId, StateMachineAgent] = {}
    pairs = min(buyer_count, seller_count)
    for i in range(pairs):
        agents[buyer_ids[i]] = StreamingBuyerAgent(
            buyer_ids[i],
            seller=seller_ids[i],
            pair_index=i,
            rounds=rounds,
            rate_per_tick=rate_per_tick,
            max_total=max_total,
            stream_length=stream_length,
        )
        agents[seller_ids[i]] = StreamingSellerAgent(seller_ids[i])

    return agents


def _instantiate_plugins(
    plugins: dict[str, Any],
    all_ids: list[AgentId],
    *,
    buyer_balance: int,
    seller_balance: int,
) -> None:
    """Instantiate shared streaming payment handles for every agent."""
    if not plugins:
        return

    agent_plugins: dict[AgentId, dict[str, Any]] = plugins.setdefault("_agent_plugins", {})

    payments_cls = plugins.get("payments")
    if payments_cls is not None and isinstance(payments_cls, type):
        balances: dict[AgentId, int] = {}
        for aid in all_ids:
            if str(aid).startswith("buyer"):
                balances[aid] = buyer_balance
            else:
                balances[aid] = seller_balance

        payment_records: dict[PaymentRef, Any] = {}
        streams: dict[PaymentRef, Any] = {}
        system_id = AgentId("system")
        shared_kwargs: dict[str, Any] = {
            "initial_balance": 0,
            "balances": balances,
            "payments": payment_records,
        }
        try:
            plugins["payments"] = payments_cls(system_id, **shared_kwargs, streams=streams)
            per_agent_kwargs = {**shared_kwargs, "streams": streams}
        except TypeError:
            plugins["payments"] = payments_cls(system_id, **shared_kwargs)
            per_agent_kwargs = shared_kwargs
        for aid in all_ids:
            agent_plugins.setdefault(aid, {})["payments"] = payments_cls(
                aid,
                **per_agent_kwargs,
            )
