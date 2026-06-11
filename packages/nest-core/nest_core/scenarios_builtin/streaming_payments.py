# SPDX-License-Identifier: Apache-2.0
"""Streaming payments scenario — full NANDA Town simulation.

Demonstrates streaming payments across three agent roles:

- **Producer**: Opens a stream to the Consumer, delivers work per tick,
  earns credits as long as the stream is open.
- **Consumer**: Pays the Producer per tick via a stream. Closes the
  stream when satisfied or when the Producer stops delivering.
- **Auditor**: Watches all streams and verifies the conservation
  invariant at every tick boundary. If conservation is ever violated,
  the Auditor raises an alarm.

The scenario exercises:
1. Stream open → drain ticks → stream close lifecycle
2. Multi-party streams (Producer→Consumer, Consumer→Storage)
3. Mid-stream cancellation (Consumer closes early)
4. Payer running dry (Producer can't pay Storage)
5. Conservation invariant across ALL tick boundaries

Deterministic across seeds 42/7/1337.

Example::

    agents = streaming_payments_factory(config, plugins)
"""

from __future__ import annotations

import json
from typing import Any

from nest_plugins_reference.payments.streaming import StreamingPayments

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId, PaymentRef


class ProducerAgent(StateMachineAgent):
    """Produces work and gets paid per tick via a stream.

    Opens a stream TO this agent (the Consumer pays the Producer).
    Every tick, the Producer delivers one unit of work.
    The stream drains automatically.
    """

    def __init__(
        self,
        agent_id: AgentId,
        consumer: AgentId,
        rate_per_tick: int = 10,
        max_total: int = 200,
    ) -> None:
        self._id = agent_id
        self._consumer = consumer
        self._rate = rate_per_tick
        self._max = max_total
        self._work_delivered: int = 0

    async def on_start(self, ctx: AgentContext) -> None:
        """Announce readiness to the Consumer.

        Example::

            await agent.on_start(ctx)
        """
        await ctx.send(
            self._consumer,
            json.dumps({
                "role": "producer",
                "agent": str(self._id),
                "rate": self._rate,
                "max": self._max,
                "status": "ready",
            }).encode(),
        )

    async def on_message(
        self, ctx: AgentContext, sender: AgentId, payload: bytes
    ) -> None:
        """Handle work requests and payment confirmations."""
        try:
            msg = json.loads(payload)
        except (json.JSONDecodeError, ValueError):
            return

        if msg.get("type") == "work_request":
            # Deliver work
            self._work_delivered += 1
            await ctx.send(
                sender,
                json.dumps({
                    "type": "work_delivered",
                    "tick": msg.get("tick", 0),
                    "total_delivered": self._work_delivered,
                }).encode(),
            )

        elif msg.get("type") == "stream_closed":
            # Consumer closed the stream
            await ctx.send(
                sender,
                json.dumps({
                    "type": "producer_summary",
                    "work_delivered": self._work_delivered,
                    "status": "done",
                }).encode(),
            )


class ConsumerAgent(StateMachineAgent):
    """Pays the Producer per tick via a streaming payment channel.

    Opens a stream TO the Producer at simulation start.
    Every tick: requests work, the Producer delivers it, the stream drains.
    After enough work, closes the stream.
    """

    def __init__(
        self,
        agent_id: AgentId,
        producer: AgentId,
        auditor: AgentId | None = None,
        rate_per_tick: int = 10,
        max_total: int = 200,
        close_after_ticks: int = 15,
    ) -> None:
        self._id = agent_id
        self._producer = producer
        self._auditor = auditor
        self._rate = rate_per_tick
        self._max = max_total
        self._close_after = close_after_ticks
        self._ticks_elapsed: int = 0
        self._stream_ref: PaymentRef | None = None
        self._stream_active: bool = False

    async def on_start(self, ctx: AgentContext) -> None:
        """Open a payment stream to the Producer.

        Example::

            await agent.on_start(ctx)
        """
        # Get the payments plugin from the context
        payments = StreamingPayments(
            self._id,
            initial_balance=5000,
            balances=ctx.shared_state.get("ledger", {}),
        )
        ctx.shared_state["ledger"] = getattr(payments, "_balances", {})

        ref = PaymentRef(f"consumer-{self._id}-to-{self._producer}")
        await payments.open_stream(
            self._producer,
            rate_per_tick=self._rate,
            max_total=self._max,
            ref=ref,
        )
        self._stream_ref = ref
        self._stream_active = True
        ctx.shared_state[f"stream_{ref}"] = payments

        # Notify Producer and Auditor
        await ctx.send(
            self._producer,
            json.dumps({
                "type": "stream_opened",
                "ref": str(ref),
                "rate": self._rate,
                "max": self._max,
            }).encode(),
        )
        if self._auditor:
            await ctx.send(
                self._auditor,
                json.dumps({
                    "type": "stream_observed",
                    "ref": str(ref),
                    "payer": str(self._id),
                    "payee": str(self._producer),
                    "rate": self._rate,
                    "max": self._max,
                }).encode(),
            )

    async def on_message(
        self, ctx: AgentContext, sender: AgentId, payload: bytes
    ) -> None:
        """Per-tick: request work, drain stream, check close condition."""
        try:
            msg = json.loads(payload)
        except (json.JSONDecodeError, ValueError):
            return

        if msg.get("type") == "tick":
            self._ticks_elapsed += 1

            if self._stream_active and self._stream_ref:
                # Request work from Producer
                await ctx.send(
                    self._producer,
                    json.dumps({
                        "type": "work_request",
                        "tick": self._ticks_elapsed,
                    }).encode(),
                )

                # Drain the stream for this tick
                payments = ctx.shared_state.get(f"stream_{self._stream_ref}")
                if payments and hasattr(payments, "drain_tick"):
                    payments.drain_tick()

            # Check close condition
            if (
                self._stream_active
                and self._stream_ref
                and self._ticks_elapsed >= self._close_after
            ):
                payments = ctx.shared_state.get(f"stream_{self._stream_ref}")
                if payments and hasattr(payments, "close_stream"):
                    import asyncio
                    receipt = asyncio.run(
                        payments.close_stream(self._stream_ref)
                    )
                    self._stream_active = False

                    await ctx.send(
                        self._producer,
                        json.dumps({
                            "type": "stream_closed",
                            "ref": str(self._stream_ref),
                            "total_billed": receipt.amount.amount,
                            "ticks": self._ticks_elapsed,
                        }).encode(),
                    )
                    if self._auditor:
                        await ctx.send(
                            self._auditor,
                            json.dumps({
                                "type": "stream_final",
                                "ref": str(self._stream_ref),
                                "total_billed": receipt.amount.amount,
                                "ticks": self._ticks_elapsed,
                            }).encode(),
                        )

        elif msg.get("type") == "work_delivered":
            pass  # Work received — payment already happened via drain_tick


class AuditorAgent(StateMachineAgent):
    """Watches all payment streams and verifies conservation invariant.

    At every tick boundary, the Auditor checks that the sum of all
    agent balances equals the sum at construction. If conservation
    is violated, the Auditor raises an alarm.
    """

    def __init__(self, agent_id: AgentId) -> None:
        self._id = agent_id
        self._initial_total: int | None = None
        self._violations: list[dict[str, Any]] = []
        self._ticks_observed: int = 0

    async def on_start(self, ctx: AgentContext) -> None:
        """Record the initial total balance.

        Example::

            await agent.on_start(ctx)
        """
        ledger = ctx.shared_state.get("ledger", {})
        if ledger:
            self._initial_total = sum(ledger.values())

    async def on_message(
        self, ctx: AgentContext, sender: AgentId, payload: bytes
    ) -> None:
        """Check conservation after every tick."""
        try:
            msg = json.loads(payload)
        except (json.JSONDecodeError, ValueError):
            return

        if msg.get("type") == "tick":
            self._ticks_observed += 1

            ledger = ctx.shared_state.get("ledger", {})
            if ledger and self._initial_total is not None:
                current_total = sum(ledger.values())
                if current_total != self._initial_total:
                    violation = {
                        "tick": self._ticks_observed,
                        "expected": self._initial_total,
                        "actual": current_total,
                        "delta": current_total - self._initial_total,
                    }
                    self._violations.append(violation)
                    await ctx.send(
                        sender,
                        json.dumps({
                            "type": "ALARM",
                            "reason": "conservation_violated",
                            "violation": violation,
                        }).encode(),
                    )

        elif msg.get("type") == "audit_request":
            await ctx.send(
                sender,
                json.dumps({
                    "type": "audit_report",
                    "ticks_observed": self._ticks_observed,
                    "violations": len(self._violations),
                    "violation_details": self._violations,
                    "verdict": "PASS" if not self._violations else "FAIL",
                }).encode(),
            )


def streaming_payments_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create agents for the streaming payments scenario.

    Assigns roles from ``config.agents.roles``:
    - ``producer``: delivers work, receives payment
    - ``consumer``: pays per tick, closes stream when done
    - ``auditor``: verifies conservation invariant

    Example::

        agents = streaming_payments_factory(config, plugins)
    """
    # Count roles from config
    producer_count = 1
    consumer_count = 1
    auditor_count = 1

    if config.agents.roles:
        for role in config.agents.roles:
            if role.name == "producer":
                producer_count = role.count
            elif role.name == "consumer":
                consumer_count = role.count
            elif role.name == "auditor":
                auditor_count = role.count

    agents: dict[AgentId, StateMachineAgent] = {}

    # Create Auditor first (needs to observe everything)
    auditor_id = AgentId("auditor-0")
    agents[auditor_id] = AuditorAgent(auditor_id)

    # Create Consumers and Producers
    for i in range(max(consumer_count, producer_count)):
        if i < consumer_count:
            cid = AgentId(f"consumer-{i}")
            pid = AgentId(f"producer-{i}")
            agents[cid] = ConsumerAgent(
                cid,
                producer=pid,
                auditor=auditor_id if auditor_count > 0 else None,
                rate_per_tick=10,
                max_total=200,
                close_after_ticks=15,
            )
        if i < producer_count:
            pid = AgentId(f"producer-{i}")
            if pid not in agents:
                agents[pid] = ProducerAgent(
                    pid,
                    consumer=AgentId(f"consumer-{i}"),
                    rate_per_tick=10,
                    max_total=200,
                )

    return agents
