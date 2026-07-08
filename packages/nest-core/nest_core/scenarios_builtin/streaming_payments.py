# SPDX-License-Identifier: Apache-2.0
"""Streaming payments scenario -- five buyer/seller pairs with rolling streams.

Each buyer opens a sequence of payment streams to its seller and bills one
work unit at a time, **only after the seller's ack for that unit arrives**.
Every billing-relevant transition is broadcast as a structured
``stream:<kind>:k=v`` payload that the three ``streaming_payments``
validators (see :mod:`nest_core.validators`) read back from the trace:

* ``stream:opened`` -- ref, payer, payee, rate, max, tick;
* ``stream:debit``  -- one per billed unit, citing the acked unit number;
* ``stream:closed`` -- ref, settled total, tick, closing party, reason.

The seller's per-unit ack travels as a *direct* message
(``stream:ack:ref=..:unit=..``), so the trace shows exactly which acks were
delivered (``receive``) and which the failure injector killed (``dropped``).
A debit without a delivered ack is an over-bill — that is what the
partition validator hunts.

If the payments plugin lacks the streaming surface (e.g. ``prepaid_credits``),
buyers fall back to one-shot ``pay()`` and the trace contains **no**
``stream:*`` events, which the validators report as a failure. That is the
adversarial discrimination the charter asks for.

Example::

    agents = streaming_payments_factory(config, plugins)
"""

from __future__ import annotations

from typing import Any

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId, Money, PaymentRef

# Time layout per stream slot: open, then a cancel deadline (generous --
# in-memory delivery is same-instant, so only dropped messages ever reach
# it), then a gap before the next slot.
_SLOT_PERIOD = 9.0
_CANCEL_AFTER = 7.0
_BUYER_STAGGER = 0.13

_OP_OPEN = b"op:open:"  # + slot number
_OP_CANCEL = b"op:cancel:"  # + slot number


def _emit(kind: str, fields: dict[str, str | int]) -> bytes:
    """Build a structured ``stream:<kind>:k=v:...`` payload.

    The colon-separated ``k=v`` form matches the parser in
    :func:`nest_core.validators._parse_stream_fields`.

    Example::

        payload = _emit("debit", {"ref": "s-buyer-0-1", "amount": 5, "unit": 2})
    """
    body = ":".join(f"{k}={v}" for k, v in fields.items())
    return f"stream:{kind}:{body}".encode()


def _parse_kv(body: str) -> dict[str, str]:
    """Parse a ``k=v:k=v`` message body into a dict.

    Example::

        fields = _parse_kv("ref=s-buyer-0-1:unit=2")
    """
    out: dict[str, str] = {}
    for part in body.split(":"):
        key, sep, value = part.partition("=")
        if sep:
            out[key] = value
    return out


class StreamBuyerAgent(StateMachineAgent):
    """Opens rolling streams to one seller and bills only acked work units.

    The buyer owns the payer side: it opens each stream slot on schedule,
    requests one work unit at a time, bills a unit when (and only when) the
    seller's ack for that unit is delivered, and closes the stream -- at the
    unit budget, mid-stream for every third slot, or on the cancel deadline
    when drops or a partition stall the ack chain.

    Example::

        agent = StreamBuyerAgent(
            AgentId("buyer-0"),
            seller=AgentId("seller-0"),
            index=0,
            slots=20,
            rate_per_tick=5,
            units_per_stream=5,
        )
    """

    def __init__(
        self,
        agent_id: AgentId,
        seller: AgentId,
        index: int,
        slots: int,
        rate_per_tick: int,
        units_per_stream: int,
    ) -> None:
        self._id = agent_id
        self._seller = seller
        self._index = index
        self._slots = slots
        self._rate = rate_per_tick
        self._units = units_per_stream
        self._open_refs: set[PaymentRef] = set()

    def _ref(self, slot: int) -> PaymentRef:
        """Unique stream ref for a slot.

        Example::

            ref = agent._ref(3)  # PaymentRef("s-buyer-0-3")
        """
        return PaymentRef(f"s-{self._id}-{slot}")

    def _early_close_unit(self, slot: int) -> int | None:
        """Every third slot cancels mid-stream after two billed units.

        Example::

            assert StreamBuyerAgent._early_close_unit(agent, 2) == 2
        """
        return 2 if slot % 3 == 2 else None

    async def on_start(self, ctx: AgentContext) -> None:
        """Schedule every slot's open and cancel deadline upfront.

        Example::

            await agent.on_start(ctx)
        """
        stagger = _BUYER_STAGGER * self._index
        for slot in range(self._slots):
            base = 1.0 + stagger + slot * _SLOT_PERIOD
            await ctx.schedule(base, _OP_OPEN + str(slot).encode())
            await ctx.schedule(base + _CANCEL_AFTER, _OP_CANCEL + str(slot).encode())

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Dispatch open/cancel self-ops and seller acks.

        Example::

            await agent.on_message(ctx, AgentId("seller-0"), b"stream:ack:ref=s-buyer-0-0:unit=1")
        """
        payments = ctx.plugins["payments"]

        if payload.startswith(_OP_OPEN):
            slot = int(payload[len(_OP_OPEN) :])
            await self._open(ctx, payments, slot)
            return

        if payload.startswith(_OP_CANCEL):
            slot = int(payload[len(_OP_CANCEL) :])
            await self._close(ctx, payments, self._ref(slot), reason="deadline")
            return

        text = payload.decode("utf-8", errors="replace")
        if text.startswith("stream:ack:"):
            await self._on_ack(ctx, payments, _parse_kv(text[len("stream:ack:") :]))

    async def _open(self, ctx: AgentContext, payments: Any, slot: int) -> None:
        ref = self._ref(slot)
        if not hasattr(payments, "open_stream"):
            # Fallback for plugins without streaming (e.g. prepaid_credits):
            # pay the full budget upfront. The trace then carries no
            # stream:* events, which is exactly what the validators flag.
            await payments.pay(self._seller, Money(amount=self._rate * self._units), ref)
            return
        tick = int(ctx.time)
        await payments.open_stream(
            to=self._seller,
            rate_per_tick=self._rate,
            max_total=self._rate * self._units,
            ref=ref,
            at_tick=tick,
        )
        self._open_refs.add(ref)
        await ctx.broadcast(
            _emit(
                "opened",
                {
                    "ref": ref,
                    "payer": str(self._id),
                    "payee": str(self._seller),
                    "rate": self._rate,
                    "max": self._rate * self._units,
                    "tick": tick,
                },
            )
        )
        await ctx.send(self._seller, _emit("work", {"ref": ref, "unit": 1}))

    async def _on_ack(self, ctx: AgentContext, payments: Any, fields: dict[str, str]) -> None:
        ref = PaymentRef(fields.get("ref", ""))
        unit = int(fields.get("unit", "0"))
        if ref not in self._open_refs:
            return  # late ack for a closed/unknown stream: never billed
        if not payments.record_delivery(ref, unit):
            return
        tick = int(ctx.time)
        drained = await payments.tick_stream(ref, tick)
        if drained > 0:
            await ctx.broadcast(
                _emit("debit", {"ref": ref, "amount": drained, "unit": unit, "tick": tick})
            )
        handle = payments.stream(ref)
        still_open = handle is not None and handle.closed_at_tick is None
        slot = int(str(ref).rsplit("-", 1)[-1])
        early = self._early_close_unit(slot)
        if not still_open or (early is not None and unit >= early):
            await self._close(ctx, payments, ref, reason="done")
            return
        await ctx.send(self._seller, _emit("work", {"ref": ref, "unit": unit + 1}))

    async def _close(self, ctx: AgentContext, payments: Any, ref: PaymentRef, reason: str) -> None:
        if ref not in self._open_refs:
            return  # never opened (dropped op) or already closed
        self._open_refs.discard(ref)
        tick = int(ctx.time)
        receipt = await payments.close_stream(ref, at_tick=tick)
        await ctx.broadcast(
            _emit(
                "closed",
                {
                    "ref": ref,
                    "total": receipt.amount.amount,
                    "tick": tick,
                    "by": str(self._id),
                    "reason": reason,
                },
            )
        )


class StreamSellerAgent(StateMachineAgent):
    """Serves work requests: one ack per requested unit, nothing else.

    The ack is a direct message so the trace records its delivery
    (``receive``) or its loss (``dropped``) between exactly this seller and
    its buyer — the evidence the over-bill validator audits.

    Example::

        agent = StreamSellerAgent()
    """

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Ack any well-formed work request from the buyer.

        Example::

            await agent.on_message(ctx, AgentId("buyer-0"), b"stream:work:ref=s-buyer-0-0:unit=1")
        """
        text = payload.decode("utf-8", errors="replace")
        if not text.startswith("stream:work:"):
            return
        fields = _parse_kv(text[len("stream:work:") :])
        ref = fields.get("ref", "")
        unit = fields.get("unit", "")
        if ref and unit:
            await ctx.send(sender, _emit("ack", {"ref": ref, "unit": unit}))


def _role_balance(config: ScenarioConfig, role: str, default: int) -> int:
    """Read a role's ``initial_balance`` from the scenario config.

    Example::

        balance = _role_balance(config, "buyer", 5000)
    """
    for rc in config.agents.roles:
        if rc.name == role:
            return int(rc.config.get("initial_balance", default))
    return default


def streaming_payments_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Build five buyer/seller pairs with a shared ledger per pair.

    ``task.config`` knobs: ``rounds`` (total work units each buyer attempts,
    default 100), ``rate_per_tick`` (default 5), ``units_per_stream``
    (default 5). Each pair's two agents share the same balances/payments/
    streams dicts (the escrow-factory convention) so the buyer's drain and
    any payee-side close hit one ledger; pairs are economically independent.

    For payment plugins that do not accept the shared-dict kwargs (e.g.
    ``prepaid_credits``), each agent gets a plain per-agent instance and
    buyers fall back to one-shot ``pay()``.

    Example::

        agents = streaming_payments_factory(config, plugins)
    """
    payments_cls = plugins["payments"]
    task_cfg = config.task.config
    rounds = int(task_cfg.get("rounds", 100))
    rate = int(task_cfg.get("rate_per_tick", 5))
    units = int(task_cfg.get("units_per_stream", 5))
    slots = max(1, rounds // units)
    pairs = 5

    buyer_balance = _role_balance(config, "buyer", 5000)
    seller_balance = _role_balance(config, "seller", 100)

    agents: dict[AgentId, StateMachineAgent] = {}
    overrides: dict[AgentId, dict[str, Any]] = {}

    def _pair_instances(buyer_id: AgentId, seller_id: AgentId) -> tuple[Any, Any]:
        shared_balances: dict[AgentId, int] = {}
        shared_payments: dict[PaymentRef, Any] = {}
        shared_streams: dict[PaymentRef, Any] = {}
        try:
            buyer_inst = payments_cls(
                buyer_id,
                initial_balance=buyer_balance,
                balances=shared_balances,
                payments=shared_payments,
                streams=shared_streams,
            )
            seller_inst = payments_cls(
                seller_id,
                initial_balance=seller_balance,
                balances=shared_balances,
                payments=shared_payments,
                streams=shared_streams,
            )
        except TypeError:
            buyer_inst = payments_cls(buyer_id, initial_balance=buyer_balance)
            seller_inst = payments_cls(seller_id, initial_balance=seller_balance)
        return buyer_inst, seller_inst

    for i in range(pairs):
        buyer_id = AgentId(f"buyer-{i}")
        seller_id = AgentId(f"seller-{i}")
        agents[buyer_id] = StreamBuyerAgent(
            buyer_id,
            seller=seller_id,
            index=i,
            slots=slots,
            rate_per_tick=rate,
            units_per_stream=units,
        )
        agents[seller_id] = StreamSellerAgent()

        buyer_inst, seller_inst = _pair_instances(buyer_id, seller_id)
        overrides[buyer_id] = {"payments": buyer_inst}
        overrides[seller_id] = {"payments": seller_inst}

    plugins["_agent_plugins"] = overrides
    return agents
