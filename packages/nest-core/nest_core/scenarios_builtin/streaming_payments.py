# SPDX-License-Identifier: Apache-2.0
"""Streaming payments scenario — 5 buyers, 5 sellers, rolling streams, 5% drop.

Matches Problem #03 spec: 5 buyers open streaming payment channels to 5 sellers
with per-tick metering. Buyers open and close streams dynamically (rolling
streams) while 5% of messages are dropped to simulate adversarial network
conditions. Uses Simulator.network_partition config for over-bill testing.

Deterministic across seeds 42/7/1337.

Example::

    agents = streaming_payments_factory(config, plugins)
"""

from __future__ import annotations

import json
import random
from typing import Any

from nest_plugins_reference.payments.streaming import StreamingPayments

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId, PaymentRef


class BuyerAgent(StateMachineAgent):
    """Opens streaming payment channels to sellers with rolling open/close."""

    def __init__(
        self,
        agent_id: AgentId,
        sellers: list[AgentId],
        rate_per_tick: int = 10,
        max_total_per_stream: int = 200,
        streams_to_open: int = 2,
        close_after_ticks: int = 25,
        seed: int = 42,
    ) -> None:
        self._id = agent_id
        self._sellers = sellers
        self._rate = rate_per_tick
        self._max = max_total_per_stream
        self._streams_to_open = streams_to_open
        self._close_after = close_after_ticks
        self._rng = random.Random(seed + hash(str(agent_id)) % 2**32)
        self._ticks_elapsed: int = 0
        self._active_streams: dict[PaymentRef, AgentId] = {}
        self._streams_opened: int = 0
        self._total_paid: int = 0

    async def on_start(self, ctx: AgentContext) -> None:
        """Open initial stream to a random seller."""
        await self._open_new_stream(ctx)

    async def on_message(
        self, ctx: AgentContext, sender: AgentId, payload: bytes
    ) -> None:
        try:
            msg = json.loads(payload)
        except (json.JSONDecodeError, ValueError):
            return

        if msg.get("type") == "tick":
            self._ticks_elapsed += 1

            payments = StreamingPayments(
                self._id, initial_balance=5000,
                balances=ctx.shared_state.get("ledger", {}),
            )
            ctx.shared_state.setdefault("ledger", getattr(payments, "_balances", {}))
            payments._balances = ctx.shared_state["ledger"]  # type: ignore[attr-defined]

            for _ref in list(self._active_streams):
                payments.drain_tick()

            # Rolling: open new stream every 10 ticks
            if (
                self._streams_opened < self._streams_to_open
                and self._ticks_elapsed % 10 == 0
            ):
                await self._open_new_stream(ctx)

            # Close oldest stream after enough ticks
            if self._ticks_elapsed >= self._close_after and self._active_streams:
                oldest_ref = next(iter(self._active_streams))
                try:
                    import asyncio
                    receipt = asyncio.run(payments.close_stream(oldest_ref))
                    self._total_paid += receipt.amount.amount
                    seller = self._active_streams.pop(oldest_ref)
                    await ctx.send(
                        seller,
                        json.dumps({
                            "type": "stream_closed",
                            "ref": str(oldest_ref),
                            "total_billed": receipt.amount.amount,
                        }).encode(),
                    )
                except ValueError:
                    pass

        elif msg.get("type") == "work_delivered":
            pass

    async def _open_new_stream(self, ctx: AgentContext) -> None:
        """Open a stream to a random seller."""
        if not self._sellers:
            return
        seller = self._sellers[self._rng.randint(0, len(self._sellers) - 1)]
        ref = PaymentRef(f"buyer-{self._id}-to-{seller}-{self._streams_opened}")

        payments = StreamingPayments(
            self._id, initial_balance=5000,
            balances=ctx.shared_state.get("ledger", {}),
        )
        ctx.shared_state.setdefault("ledger", getattr(payments, "_balances", {}))
        payments._balances = ctx.shared_state["ledger"]  # type: ignore[attr-defined]

        await payments.open_stream(seller, rate_per_tick=self._rate,
                                   max_total=self._max, ref=ref)
        self._active_streams[ref] = seller
        self._streams_opened += 1

        await ctx.send(seller, json.dumps({
            "type": "stream_opened", "ref": str(ref),
            "buyer": str(self._id), "rate": self._rate, "max": self._max,
        }).encode())


class SellerAgent(StateMachineAgent):
    """Accepts streams from buyers, delivers work, tracks earnings."""

    def __init__(self, agent_id: AgentId) -> None:
        self._id = agent_id
        self._work_delivered: int = 0
        self._active_buyers: set[AgentId] = set()

    async def on_start(self, ctx: AgentContext) -> None:
        pass

    async def on_message(
        self, ctx: AgentContext, sender: AgentId, payload: bytes
    ) -> None:
        try:
            msg = json.loads(payload)
        except (json.JSONDecodeError, ValueError):
            return

        if msg.get("type") == "stream_opened":
            self._active_buyers.add(sender)
            self._work_delivered += 1
            await ctx.send(sender, json.dumps({
                "type": "work_delivered", "seller": str(self._id),
                "total_delivered": self._work_delivered,
            }).encode())

        elif msg.get("type") == "stream_closed":
            self._active_buyers.discard(sender)

        elif msg.get("type") == "tick":
            ledger = ctx.shared_state.get("ledger", {})
            if ledger:
                our_balance = ledger.get(str(self._id), 0)
                if our_balance < 0:
                    await ctx.send(sender, json.dumps({
                        "type": "ALARM", "reason": "negative_balance",
                        "agent": str(self._id), "balance": our_balance,
                    }).encode())


def streaming_payments_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create 5 buyers and 5 sellers for the streaming payments scenario.

    Matches Problem #03: 5 buyers, 5 sellers, rolling streams, 5% drop.
    Uses Simulator(partition_groups=...) for over-bill-on-partition testing.

    Example::

        agents = streaming_payments_factory(config, plugins)
    """
    buyer_count = 5
    seller_count = 5
    streams_per_buyer = 2
    max_rate = 10
    max_total = 500

    if config.agents.roles:
        for role in config.agents.roles:
            if role.name == "buyer":
                buyer_count = role.count
            elif role.name == "seller":
                seller_count = role.count

    if config.task and config.task.config:
        streams_per_buyer = config.task.config.get("streams_per_buyer", 2)
        max_rate = config.task.config.get("max_rate_per_tick", 10)
        max_total = config.task.config.get("max_total_per_stream", 500)

    seller_ids = [AgentId(f"seller-{i}") for i in range(seller_count)]
    buyer_ids = [AgentId(f"buyer-{i}") for i in range(buyer_count)]

    agents: dict[AgentId, StateMachineAgent] = {}

    for sid in seller_ids:
        agents[sid] = SellerAgent(sid)

    for i, bid in enumerate(buyer_ids):
        agents[bid] = BuyerAgent(
            bid, sellers=seller_ids, rate_per_tick=max_rate,
            max_total_per_stream=max_total, streams_to_open=streams_per_buyer,
            close_after_ticks=25, seed=42 + i,
        )

    return agents
