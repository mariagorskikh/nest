# SPDX-License-Identifier: Apache-2.0
"""Escrow marketplace scenario -- three buyer/seller/arbiter triples.

Drives the escrow plugin through both the happy path and two dispute paths,
emitting one structured ``escrow:<kind>:<fields>`` broadcast per state
transition. The four ``escrow_marketplace`` validators (see
:mod:`nest_core.validators`) read those broadcasts and confirm:

* every escrow walked a legal state-machine path;
* every transition was broadcast by the role authorized to perform it;
* every arbitration verdict stayed in ``[0, 10000]`` bps;
* no payout happened without a preceding delivery proof.

If the underlying payments plugin lacks the escrow protocol (e.g.
``prepaid_credits``), the agents fall back to a plain ``pay()`` and the
trace will contain **no** ``escrow:*`` events -- which the validators
report as a failure ("no escrow lifecycle observed"). That is the
adversarial discrimination the charter asks for.

Example::

    agents = escrow_marketplace_factory(config, plugins)
"""

from __future__ import annotations

from typing import Any

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId, Money, PaymentRef

# Per-triple tick schedule -- spaced wide enough that ticks land in order
# regardless of broadcast latency in the simulator.
_TICK_OPEN = 1.0
_TICK_DELIVER = 4.0
_TICK_RESOLVE = 7.0
_TICK_ARBITRATE = 10.0

_OP_OPEN = b"op:open"
_OP_DELIVER = b"op:deliver"
_OP_RESOLVE = b"op:resolve"
_OP_ARBITRATE = b"op:arbitrate"


def _emit(fields: dict[str, str | int]) -> str:
    """Build a structured ``escrow:<kind>:k=v:...`` broadcast payload.

    The colon-separated ``k=v`` form matches the parser in
    :func:`nest_core.validators._parse_escrow_events`.
    """
    kind = str(fields.pop("kind"))
    body = ":".join(f"{k}={v}" for k, v in fields.items())
    return f"escrow:{kind}:{body}" if body else f"escrow:{kind}"


class BuyerAgent(StateMachineAgent):
    """Opens an escrow, then resolves it as either ``release`` or ``dispute``.

    The buyer owns the payer's plugin instance and is the only agent that
    can ``open_escrow`` / ``release`` / ``dispute`` / ``refund``.

    Example::

        agent = BuyerAgent(
            AgentId("buyer-0"),
            payee=AgentId("seller-0"),
            arbiter=AgentId("arbiter-0"),
            amount=250,
            ref=PaymentRef("e-0"),
            mode="happy",
        )
    """

    def __init__(
        self,
        agent_id: AgentId,
        payee: AgentId,
        arbiter: AgentId,
        amount: int,
        ref: PaymentRef,
        mode: str,
    ) -> None:
        self._id = agent_id
        self._payee = payee
        self._arbiter = arbiter
        self._amount = amount
        self._ref = ref
        self._mode = mode

    async def on_start(self, ctx: AgentContext) -> None:
        await ctx.schedule(_TICK_OPEN, _OP_OPEN)
        await ctx.schedule(_TICK_RESOLVE, _OP_RESOLVE)

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        payments = ctx.plugins["payments"]
        if payload == _OP_OPEN:
            if hasattr(payments, "open_escrow"):
                await payments.open_escrow(
                    payee=self._payee,
                    arbiter=self._arbiter,
                    amount=Money(amount=self._amount),
                    ref=self._ref,
                )
                await ctx.broadcast(
                    _emit(
                        {
                            "kind": "opened",
                            "ref": self._ref,
                            "payer": str(self._id),
                            "payee": str(self._payee),
                            "arbiter": str(self._arbiter),
                            "amount": self._amount,
                        }
                    ).encode()
                )
            else:
                # Fallback for plugins without escrow (e.g. prepaid_credits):
                # pay() upfront. Trace will then contain no escrow:* events,
                # which is exactly what the validators flag.
                await payments.pay(self._payee, Money(amount=self._amount), self._ref)
            return
        if payload == _OP_RESOLVE:
            if not hasattr(payments, "release"):
                return  # prepaid_credits has nothing left to do
            if self._mode == "happy":
                await payments.release(self._ref)
                await ctx.broadcast(_emit({"kind": "released", "ref": self._ref}).encode())
            else:
                reason = f"mode={self._mode}"
                await payments.dispute(self._ref, reason=reason)
                await ctx.broadcast(
                    _emit({"kind": "disputed", "ref": self._ref, "reason": reason}).encode()
                )


class SellerAgent(StateMachineAgent):
    """Posts a delivery proof against ``ref``. Payee-only by construction.

    Example::

        agent = SellerAgent(AgentId("seller-0"), ref=PaymentRef("e-0"))
    """

    def __init__(self, agent_id: AgentId, ref: PaymentRef) -> None:
        self._id = agent_id
        self._ref = ref

    async def on_start(self, ctx: AgentContext) -> None:
        await ctx.schedule(_TICK_DELIVER, _OP_DELIVER)

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        if payload != _OP_DELIVER:
            return
        payments = ctx.plugins["payments"]
        if not hasattr(payments, "deliver"):
            return
        proof = f"sha256-{self._ref}"
        await payments.deliver(self._ref, proof=proof)
        await ctx.broadcast(_emit({"kind": "delivered", "ref": self._ref, "proof": proof}).encode())


class ArbiterAgent(StateMachineAgent):
    """Settles a disputed escrow with a pre-configured ``payee_bps`` verdict.

    No-op in the ``happy`` mode (never asked to arbitrate).

    Example::

        agent = ArbiterAgent(
            AgentId("arbiter-1"),
            ref=PaymentRef("e-1"),
            payee_bps=3000,
            mode="dispute",
        )
    """

    def __init__(
        self,
        agent_id: AgentId,
        ref: PaymentRef,
        payee_bps: int,
        mode: str,
    ) -> None:
        self._id = agent_id
        self._ref = ref
        self._payee_bps = payee_bps
        self._mode = mode

    async def on_start(self, ctx: AgentContext) -> None:
        if self._mode != "happy":
            await ctx.schedule(_TICK_ARBITRATE, _OP_ARBITRATE)

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        if payload != _OP_ARBITRATE:
            return
        payments = ctx.plugins["payments"]
        if not hasattr(payments, "arbitrate"):
            return
        await payments.arbitrate(
            self._ref,
            payee_bps=self._payee_bps,
            rationale=f"verdict from arbiter for mode {self._mode}",
        )
        await ctx.broadcast(
            _emit(
                {
                    "kind": "arbitrated",
                    "ref": self._ref,
                    "payee_bps": self._payee_bps,
                }
            ).encode()
        )


# Three triples: one happy + two dispute (different bps).
_TRIPLES: list[dict[str, Any]] = [
    {"suffix": "0", "mode": "happy", "amount": 250, "payee_bps": 10_000},
    {"suffix": "1", "mode": "dispute", "amount": 400, "payee_bps": 3_000},
    {"suffix": "2", "mode": "dispute", "amount": 600, "payee_bps": 8_000},
]


def escrow_marketplace_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Build the 9 agents (3 triples) and wire shared per-agent payments.

    Each triple's three agents share the same balances + payments +
    escrows dicts (so the vault is a single ledger), but each agent
    holds its own plugin instance keyed by ``self._agent_id``. The
    factory installs them as per-agent overrides via the
    ``_agent_plugins`` channel the runner understands.

    For payment plugins that do not accept ``balances`` / ``payments`` /
    ``escrows`` kwargs (e.g. a future plugin with a different ctor),
    the factory falls back to a single shared instance.

    Example::

        agents = escrow_marketplace_factory(config, plugins)
    """
    payments_cls = plugins["payments"]
    agents: dict[AgentId, StateMachineAgent] = {}
    overrides: dict[AgentId, dict[str, Any]] = {}

    # All triples share one global ledger, so a buyer with insufficient
    # balance for triple-2 would propagate naturally; the per-triple amounts
    # below total < the buyer's default 1000.
    shared_balances: dict[AgentId, int] = {}
    shared_payments: dict[PaymentRef, Any] = {}
    shared_escrows: dict[PaymentRef, Any] = {}

    def _instance(agent_id: AgentId) -> Any:
        try:
            return payments_cls(
                agent_id,
                initial_balance=2000,
                balances=shared_balances,
                payments=shared_payments,
                escrows=shared_escrows,
            )
        except TypeError:
            try:
                return payments_cls(
                    agent_id,
                    initial_balance=2000,
                    balances=shared_balances,
                    payments=shared_payments,
                )
            except TypeError:
                return payments_cls(agent_id, initial_balance=2000)

    for triple in _TRIPLES:
        suffix = str(triple["suffix"])
        mode = str(triple["mode"])
        amount = int(triple["amount"])
        payee_bps = int(triple["payee_bps"])
        buyer_id = AgentId(f"buyer-{suffix}")
        seller_id = AgentId(f"seller-{suffix}")
        arbiter_id = AgentId(f"arbiter-{suffix}")
        ref = PaymentRef(f"e-{suffix}")

        agents[buyer_id] = BuyerAgent(
            buyer_id,
            payee=seller_id,
            arbiter=arbiter_id,
            amount=amount,
            ref=ref,
            mode=mode,
        )
        agents[seller_id] = SellerAgent(seller_id, ref=ref)
        agents[arbiter_id] = ArbiterAgent(
            arbiter_id,
            ref=ref,
            payee_bps=payee_bps,
            mode=mode,
        )

        for aid in (buyer_id, seller_id, arbiter_id):
            overrides[aid] = {"payments": _instance(aid)}

    plugins["_agent_plugins"] = overrides
    return agents
