# SPDX-License-Identifier: Apache-2.0
"""Streaming payments scenario — buyers open metered streams to sellers.

Protocol per tick::

    buyer  --tick_req:{ref}:{seq}-->  seller
    seller --tick_ack:{ref}:{seq}-->  buyer   (service delivered)
    buyer reads plugin state (balance delta), audits payment_debited/credited,
    then sends the next tick_req.

Domain events are written as JSON self-messages via ``ctx.send(ctx.agent_id, ...)``
so the engine records them as engine-attributed ``kind:send`` events with ``ts``,
``agent``, and ``corr`` fields — the same pattern used by the EMPIC scenario.
Validators parse them via ``_streaming_audit_events()``.

Two cancellation paths are exercised:

* **Natural terminus:** stream reaches ``max_total``; ``tick_stream`` returns
  False and the buyer calls ``close_stream``.
* **Mid-stream cancellation:** buyers whose index is even cancel after half of
  ``rounds`` acks regardless of remaining balance.

Example::

    agents = streaming_payments_factory(config, plugins)
"""

from __future__ import annotations

import contextlib
import json
from typing import Any

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId, PaymentRef

_AUDIT_TYPE = "streaming_audit"


async def _audit(ctx: AgentContext, data: dict[str, Any]) -> None:
    """Send a JSON self-message that the engine records as a kind:send event.

    Validators read these via ``_streaming_audit_events()``.

    Example::

        await _audit(ctx, {"event_type": "stream_opened", "stream_ref": "s-1",
                           "payer": "buyer-0", "payee": "seller-2"})
    """
    event = {"type": _AUDIT_TYPE, "tick": int(ctx.time), **data}
    await ctx.send(ctx.agent_id, json.dumps(event, sort_keys=True).encode())


class StreamingBuyerAgent(StateMachineAgent):
    """Buyer that gates each tick on a seller ack to prevent over-billing.

    Billing is never speculative: the buyer only records a debit after the
    seller replies ``tick_ack``, and derives the debited amount from the
    plugin's own balance delta rather than a config constant.

    Every other buyer (even index) cancels its stream mid-way, exercising
    ``close_stream`` as a genuine early termination rather than a natural
    terminus.

    Example::

        agent = StreamingBuyerAgent(AgentId("buyer-0"), num_sellers=5,
                                    rounds=10, cancel_early=True)
    """

    def __init__(
        self,
        agent_id: AgentId,
        num_sellers: int,
        rounds: int = 100,
        rate_per_tick: int = 10,
        max_total: int = 1000,
        cancel_early: bool = False,
    ) -> None:
        self._id = agent_id
        self._num_sellers = num_sellers
        self._rounds = rounds
        self._cancel_rounds = rounds // 2 if cancel_early else rounds
        self._rate_per_tick = rate_per_tick
        self._max_total = max_total
        self._stream_counter = 0
        self._active_streams: dict[PaymentRef, AgentId] = {}
        self._closed_streams: set[PaymentRef] = set()
        self._acks: dict[PaymentRef, int] = {}

    def _pick_seller(self, ctx: AgentContext) -> AgentId:
        idx = ctx.rng.randint(0, self._num_sellers - 1)
        return AgentId(f"seller-{idx}")

    async def on_start(self, ctx: AgentContext) -> None:
        """Open a stream and send the first tick request.

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
            await _audit(
                ctx,
                {
                    "event_type": "stream_opened",
                    "stream_ref": str(ref),
                    "payer": str(self._id),
                    "payee": str(seller),
                },
            )
            await ctx.send(seller, f"tick_req:{ref}:0".encode())

    async def on_message(
        self,
        ctx: AgentContext,
        sender: AgentId,
        payload: bytes,
    ) -> None:
        """Handle tick acks; derive debit from plugin balance delta.

        On each ack the buyer reads the payer balance before and after calling
        ``tick_stream``, so the audited amount reflects what the plugin actually
        moved — not a config constant.

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

        seller = self._active_streams[ref]

        # Derive actual amount from balance delta — not the config constant
        balance_before = payments.balance(self._id)
        still_open = await payments.tick_stream(ref, int(ctx.time))
        balance_after = payments.balance(self._id)
        amount_debited = balance_before - balance_after

        if still_open and amount_debited > 0:
            self._acks[ref] = self._acks.get(ref, 0) + 1
            await _audit(
                ctx,
                {
                    "event_type": "payment_debited",
                    "stream_ref": ref_str,
                    "payer": str(self._id),
                    "payee": str(seller),
                    "amount": amount_debited,
                },
            )
            await _audit(
                ctx,
                {
                    "event_type": "payment_credited",
                    "stream_ref": ref_str,
                    "payer": str(self._id),
                    "payee": str(seller),
                    "amount": amount_debited,
                },
            )

            acks_so_far = self._acks[ref]
            if acks_so_far < self._cancel_rounds:
                # Use schedule so each tick lands at a later virtual time,
                # making tick values non-uniform and drain-after-close checkable.
                await ctx.schedule(1.0, f"next_tick:{ref}:{acks_so_far}".encode())
            else:
                await self._close(ctx, ref, payments)
        else:
            await self._close(ctx, ref, payments)

    async def on_message_scheduled(
        self,
        ctx: AgentContext,
        sender: AgentId,
        payload: bytes,
    ) -> None:
        """Not used — scheduled messages are handled via on_message."""

    async def _close(
        self,
        ctx: AgentContext,
        ref: PaymentRef,
        payments: Any,
    ) -> None:
        """Close the stream and audit stream_closed.

        Example::

            await agent._close(ctx, PaymentRef("s-1"), payments)
        """
        if ref in self._closed_streams:
            return
        self._closed_streams.add(ref)
        self._active_streams.pop(ref, None)
        with contextlib.suppress(ValueError):
            await payments.close_stream(ref)
        await _audit(
            ctx,
            {
                "event_type": "stream_closed",
                "stream_ref": str(ref),
                "payer": str(self._id),
            },
        )

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

    Replies ``tick_ack`` on each ``tick_req``; the buyer only bills after
    receiving the ack, so a network partition stops billing automatically.

    Also handles ``next_tick`` self-messages forwarded from the buyer's
    scheduled wakeup, which triggers sending the next ``tick_req``.

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
        """Deliver service on tick_req.

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


class _TickRelayBuyer(StreamingBuyerAgent):
    """Buyer that routes scheduled next_tick wakeups to tick_req sends.

    ``ctx.schedule`` delivers back to the same agent; on receipt the buyer
    reads the ref from the payload and sends the next ``tick_req`` to the
    seller.
    """

    async def on_message(
        self,
        ctx: AgentContext,
        sender: AgentId,
        payload: bytes,
    ) -> None:
        msg = payload.decode("utf-8", errors="replace")
        payments = ctx.plugins.get("payments")

        if msg.startswith("next_tick:") and payments is not None:
            # Scheduled self-wakeup: send the next tick_req to the seller
            parts = msg.split(":", 2)
            if len(parts) >= 2:
                ref_str = parts[1]
                ref = PaymentRef(ref_str)
                if ref in self._active_streams and ref not in self._closed_streams:
                    seller = self._active_streams[ref]
                    seq = self._acks.get(ref, 0)
                    await ctx.send(seller, f"tick_req:{ref_str}:{seq}".encode())
        else:
            await super().on_message(ctx, sender, payload)


def streaming_payments_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create buyer and seller agents for the streaming payments scenario.

    All agents share a single ``balances`` / ``streams`` dict (shared-ledger
    pattern) so the conservation invariant holds globally.  Every other buyer
    (even index) cancels its stream at half ``rounds`` to exercise mid-stream
    cancellation.

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
    for i, aid in enumerate(buyer_ids):
        agents[aid] = _TickRelayBuyer(
            aid,
            num_sellers=seller_count,
            rounds=rounds,
            cancel_early=(i % 2 == 0),
        )

    return agents


def _instantiate_plugins(plugins: dict[str, Any], all_ids: list[AgentId]) -> None:
    """Instantiate plugin classes into shared instances in-place.

    Per-agent payment handles share a single ``balances`` and ``streams`` dict
    so wealth is conserved globally.

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
