# SPDX-License-Identifier: Apache-2.0
"""Streaming payments scenario — buyers open metered streams to sellers.

Each buyer opens one stream to a randomly chosen seller.  Billing is
driven by a request/ack exchange: the buyer sends ``tick_req`` to the
seller, the seller delivers the service and replies ``tick_ack``, and
only on receipt of the ack does the buyer call ``tick_stream`` and emit
``payment_debited``/``payment_credited``.  A network partition drops the
ack before it arrives, so the buyer stops billing — no over-bill on
partition.

The adversarial validator ``validate_streaming_no_drain_after_close``
is exercised by the scenario: buyers close their stream cleanly after
``rounds`` acks, so any buggy plugin that continued debiting after
``close_stream`` would produce ``payment_debited`` events after the
``stream_closed`` marker and trigger a FAIL.

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
    """Write a structured domain event to the trace via ctx.emit if available.

    Degrades silently when called against a mock context that lacks ``emit``.

    Example::

        _emit(ctx, {"event_type": "stream_opened", "stream_ref": "s-1",
                    "agent": "buyer-0", "to": "seller-2", "tick": 0})
    """
    emit_fn = getattr(ctx, "emit", None)
    if emit_fn is not None:
        emit_fn(event)


class StreamingBuyerAgent(StateMachineAgent):
    """Buyer that gates each tick on a seller ack to prevent over-billing.

    Protocol per tick::

        buyer  --tick_req:{ref}:{seq}-->  seller
        seller --tick_ack:{ref}:{seq}-->  buyer   (service delivered)
        buyer calls tick_stream() and emits payment_debited/credited

    A dropped ack means no debit — the buyer never bills for service
    the seller couldn't deliver.  This is what the
    ``streaming_no_overbill_on_partition`` validator checks.

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
        # ref -> seller
        self._active_streams: dict[PaymentRef, AgentId] = {}
        self._closed_streams: set[PaymentRef] = set()
        # ref -> acks received so far
        self._acks: dict[PaymentRef, int] = {}

    def _pick_seller(self, ctx: AgentContext) -> AgentId:
        idx = ctx.rng.randint(0, self._num_sellers - 1)
        return AgentId(f"seller-{idx}")

    async def on_start(self, ctx: AgentContext) -> None:
        """Open a stream to a random seller and send the first tick request.

        Example::

            await agent.on_start(ctx)
        """
        payments = ctx.plugins.get("payments")
        if payments is None:
            return

        seller = self._pick_seller(ctx)
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
            self._acks[ref] = 0
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
            # First tick request — billing only happens when ack arrives
            await ctx.send(seller, f"tick_req:{ref}:0".encode())

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Handle tick acks from the seller.

        On each ack the buyer calls ``tick_stream`` (actual money movement)
        and emits accounting events.  If more acks are still needed, it
        sends the next ``tick_req``.  A dropped ``tick_req`` or ``tick_ack``
        ends billing naturally — no extra scheduling needed.

        Example::

            await agent.on_message(ctx, AgentId("seller-2"), b"tick_ack:ref:0")
        """
        msg = payload.decode("utf-8", errors="replace")
        payments = ctx.plugins.get("payments")

        if not msg.startswith("tick_ack:") or payments is None:
            return

        parts = msg.split(":", 2)
        if len(parts) < 3:
            return
        ref_str = parts[1]
        ref = PaymentRef(ref_str)

        if ref not in self._active_streams or ref in self._closed_streams:
            return

        # Ack received — service was delivered; now debit
        still_open = await payments.tick_stream(ref, int(ctx.time))

        if still_open:
            self._acks[ref] = self._acks.get(ref, 0) + 1
            seller = self._active_streams[ref]
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

            acks_so_far = self._acks[ref]
            if acks_so_far < self._rounds:
                # Request next tick — only bills if seller acks
                await ctx.send(seller, f"tick_req:{ref}:{acks_so_far}".encode())
            else:
                await self._close(ctx, ref, payments)
        else:
            await self._close(ctx, ref, payments)

    async def _close(
        self,
        ctx: AgentContext,
        ref: PaymentRef,
        payments: Any,
    ) -> None:
        """Close the stream and emit stream_closed.

        Example::

            await agent._close(ctx, PaymentRef("s-1"), payments)
        """
        if ref in self._closed_streams:
            return
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
        """Close any streams still open when the simulation ends.

        Example::

            await agent.on_stop(ctx)
        """
        payments = ctx.plugins.get("payments")
        for ref in list(self._active_streams.keys()):
            if ref not in self._closed_streams and payments is not None:
                await self._close(ctx, ref, payments)


class StreamingSellerAgent(StateMachineAgent):
    """Seller that delivers one unit of service per tick request.

    On each ``tick_req`` the seller performs the service and replies with
    ``tick_ack``.  The buyer only bills after receiving the ack, so a
    network partition (dropped ack) stops billing automatically.

    Example::

        agent = StreamingSellerAgent(AgentId("seller-0"))
    """

    def __init__(self, agent_id: AgentId) -> None:
        self._id = agent_id

    async def on_message(
        self,
        ctx: AgentContext,
        sender: AgentId,
        payload: bytes,
    ) -> None:
        """Deliver service on tick_req; ack stream close.

        Example::

            await agent.on_message(ctx, AgentId("buyer-0"), b"tick_req:ref:0")
        """
        msg = payload.decode("utf-8", errors="replace")
        if msg.startswith("tick_req:"):
            parts = msg.split(":", 2)
            if len(parts) >= 3:
                ref_str = parts[1]
                seq = parts[2]
                await ctx.send(sender, f"tick_ack:{ref_str}:{seq}".encode())
        elif msg.startswith("stream_close:"):
            pass  # nothing to do; stream is already closed by buyer


def streaming_payments_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create buyer and seller agents for the streaming payments scenario.

    All agents share a single ``balances`` / ``streams`` dict (shared-ledger
    pattern from the marketplace factory) so the conservation invariant holds
    globally.

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

    Per-agent payment handles share a single ``balances`` and ``streams``
    dict so wealth is conserved globally across all agents.

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
