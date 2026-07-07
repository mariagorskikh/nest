# SPDX-License-Identifier: Apache-2.0
"""Streaming payments scenario — buyers open metered streams to sellers.

Buyers open a per-tick stream to a randomly chosen seller, tick it each
round, and close it when done.  The trace carries ``stream_opened``,
``payment_debited``, and ``stream_closed`` events so the three adversarial
validators (conservation, no-drain-after-close, no-overbill-on-partition)
can run against it.

Example::

    agents = streaming_payments_factory(config, plugins)
"""

from __future__ import annotations

import contextlib
from typing import Any

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId, PaymentRef


def _emit(ctx: AgentContext, event: dict[str, Any]) -> None:
    """Write a custom event to the trace via ctx.emit if available."""
    emit_fn = getattr(ctx, "emit", None)
    if emit_fn is not None:
        emit_fn(event)


class StreamingBuyerAgent(StateMachineAgent):
    """Buyer that opens a per-tick stream to a seller and ticks it each round.

    Opens one stream per seller contact, drains it for ``rounds`` ticks,
    then closes it.  Emits ``stream_opened``, ``payment_debited``, and
    ``stream_closed`` events into the trace for validator inspection.

    Example::

        agent = StreamingBuyerAgent(AgentId("buyer-0"), num_sellers=5, rounds=10)
    """

    def __init__(
        self,
        agent_id: AgentId,
        num_sellers: int,
        rounds: int = 100,
        rate_per_tick: int = 10,
        max_total: int = 1000,
    ) -> None:
        self._id = agent_id
        self._num_sellers = num_sellers
        self._rounds = rounds
        self._rate_per_tick = rate_per_tick
        self._max_total = max_total
        self._stream_counter = 0
        self._active_streams: dict[PaymentRef, AgentId] = {}
        self._closed_streams: set[PaymentRef] = set()

    def _pick_seller(self, ctx: AgentContext) -> AgentId:
        idx = ctx.rng.randint(0, self._num_sellers - 1)
        return AgentId(f"seller-{idx}")

    async def on_start(self, ctx: AgentContext) -> None:
        """Open a stream to a random seller and schedule first tick.

        Example::

            await agent.on_start(ctx)
        """
        seller = self._pick_seller(ctx)
        payments = ctx.plugins.get("payments")
        if payments is None:
            return

        self._stream_counter += 1
        ref = PaymentRef(f"{self._id}-stream-{self._stream_counter}")

        with contextlib.suppress(ValueError):
            await payments.open_stream(
                to=seller,
                rate_per_tick=self._rate_per_tick,
                max_total=self._max_total,
                ref=ref,
            )
            self._active_streams[ref] = seller
            _emit(
                ctx,
                {
                    "event_type": "stream_opened",
                    "stream_ref": str(ref),
                    "agent": str(self._id),
                    "to": str(seller),
                    "tick": int(ctx.time),
                },
            )
            _emit(
                ctx,
                {
                    "kind": "payment_debited",
                    "stream_ref": str(ref),
                    "agent": str(self._id),
                    "amount": self._rate_per_tick,
                    "tick": int(ctx.time),
                },
            )
            _emit(
                ctx,
                {
                    "kind": "payment_credited",
                    "stream_ref": str(ref),
                    "agent": str(seller),
                    "amount": self._rate_per_tick,
                    "tick": int(ctx.time),
                },
            )
            # Notify seller
            await ctx.send(seller, f"stream_open:{ref}:{self._rate_per_tick}".encode())

            # Pre-schedule all ticks so drop rate doesn't kill the heartbeat
            for i in range(1, self._rounds + 1):
                await ctx.schedule(float(i), f"tick:{ref}:{i}".encode())

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Handle tick self-messages and seller acks.

        Example::

            await agent.on_message(ctx, sender, b"tick:buyer-0-stream-1")
        """
        msg = payload.decode("utf-8", errors="replace")
        payments = ctx.plugins.get("payments")

        if msg.startswith("tick:") and payments is not None:
            # Format is "tick:<ref>:<seq>" — extract just the ref part
            parts = msg.split(":", 2)
            ref_str = parts[1] if len(parts) >= 2 else ""
            ref = PaymentRef(ref_str)

            if ref not in self._active_streams:
                return

            still_open = await payments.tick_stream(ref, int(ctx.time))

            if ref in self._closed_streams:
                return

            if still_open:
                seller = self._active_streams.get(ref)
                _emit(
                    ctx,
                    {
                        "kind": "payment_debited",
                        "stream_ref": ref_str,
                        "agent": str(self._id),
                        "amount": self._rate_per_tick,
                        "tick": int(ctx.time),
                    },
                )
                if seller is not None:
                    _emit(
                        ctx,
                        {
                            "kind": "payment_credited",
                            "stream_ref": ref_str,
                            "agent": str(seller),
                            "amount": self._rate_per_tick,
                            "tick": int(ctx.time),
                        },
                    )
            else:
                # Stream exhausted its max_total — close once
                if ref not in self._closed_streams:
                    await self._close(ctx, ref, payments)

    async def _close(
        self,
        ctx: AgentContext,
        ref: PaymentRef,
        payments: Any,
    ) -> None:
        """Close the stream and emit a closed event."""
        self._closed_streams.add(ref)
        seller = self._active_streams.pop(ref, None)
        with contextlib.suppress(ValueError):
            await payments.close_stream(ref)
        _emit(
            ctx,
            {
                "event_type": "stream_closed",
                "stream_ref": str(ref),
                "agent": str(self._id),
                "tick": int(ctx.time),
            },
        )
        if seller is not None:
            await ctx.send(seller, f"stream_close:{ref}".encode())

    async def on_stop(self, ctx: AgentContext) -> None:
        """Close any still-open streams at simulation end.

        Example::

            await agent.on_stop(ctx)
        """
        payments = ctx.plugins.get("payments")
        for ref in list(self._active_streams.keys()):
            if ref not in self._closed_streams and payments is not None:
                await self._close(ctx, ref, payments)


class StreamingSellerAgent(StateMachineAgent):
    """Seller that acknowledges stream open/close messages.

    Passive participant — simply acks the buyer so the buyer knows
    the seller is reachable.

    Example::

        agent = StreamingSellerAgent(AgentId("seller-0"))
    """

    def __init__(self, agent_id: AgentId) -> None:
        self._id = agent_id

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Ack stream open and close messages from buyers.

        Example::

            await agent.on_message(ctx, sender, b"stream_open:ref:10")
        """
        msg = payload.decode("utf-8", errors="replace")
        if msg.startswith("stream_open:"):
            await ctx.send(sender, b"ack")
        elif msg.startswith("stream_close:"):
            await ctx.send(sender, b"closed_ack")


def streaming_payments_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create buyer and seller agents for the streaming payments scenario.

    Mirrors the marketplace factory's shared-ledger pattern: all agents
    share a single ``balances`` dict and ``payments`` dict so the
    conservation invariant holds globally.  Injects a ``_trace`` plugin
    so agents can write structured stream events directly to the trace.

    Example::

        agents = streaming_payments_factory(config, plugins)
    """
    task_config = config.task.config
    rounds = task_config.get("rounds", 100)

    buyer_count = 0
    seller_count = 0
    if config.agents.roles:
        for role in config.agents.roles:
            if role.name == "buyer":
                buyer_count = role.count
            elif role.name == "seller":
                seller_count = role.count
    else:
        buyer_count = config.agents.count // 2
        seller_count = config.agents.count - buyer_count

    buyer_ids = [AgentId(f"buyer-{i}") for i in range(buyer_count)]
    seller_ids = [AgentId(f"seller-{i}") for i in range(seller_count)]
    all_ids = buyer_ids + seller_ids

    _instantiate_plugins(plugins, all_ids)

    agents: dict[AgentId, StateMachineAgent] = {}
    for aid in seller_ids:
        agents[aid] = StreamingSellerAgent(aid)
    for aid in buyer_ids:
        agents[aid] = StreamingBuyerAgent(
            aid,
            num_sellers=seller_count,
            rounds=rounds,
        )

    return agents


def _instantiate_plugins(plugins: dict[str, Any], all_ids: list[AgentId]) -> None:
    """Instantiate plugin classes into shared instances in-place.

    Identical to the marketplace factory pattern — per-agent payment
    handles share a single ledger dict so wealth is conserved globally.

    Example::

        _instantiate_plugins(plugins, [AgentId("buyer-0"), AgentId("seller-0")])
    """
    if not plugins:
        return

    agent_plugins: dict[AgentId, dict[str, Any]] = plugins.setdefault("_agent_plugins", {})

    payments_cls = plugins.get("payments")
    if payments_cls is not None and isinstance(payments_cls, type):
        balances: dict[AgentId, int] = {aid: 5000 for aid in all_ids}
        payment_records: dict[PaymentRef, Any] = {}
        streams: dict[PaymentRef, Any] = {}
        system_id = AgentId("system")
        try:
            plugins["payments"] = payments_cls(
                system_id,
                initial_balance=0,
                balances=balances,
                payments=payment_records,
                streams=streams,
            )
            for aid in all_ids:
                agent_plugins.setdefault(aid, {})["payments"] = payments_cls(
                    aid,
                    initial_balance=0,
                    balances=balances,
                    payments=payment_records,
                    streams=streams,
                )
        except TypeError:
            plugins["payments"] = payments_cls(system_id, initial_balance=0)
