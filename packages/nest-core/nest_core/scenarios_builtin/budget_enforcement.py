# SPDX-License-Identifier: Apache-2.0
"""Budget-enforcement scenario — one shared budget across many spending sources.

Persona: payments-risk engineer. A household authorizes a single monthly
restaurant budget, but the spending comes from several independent sources that
cannot see each other:

* ``human-card``     — a person paying on a credit card.
* ``meal-planner``   — an autonomous agent ordering weeknight dinners (card rail).
* ``travel-agent``   — a booking agent placing a reservation deposit (crypto rail).
* ``lunch-app``      — a subscription topping up a school lunch account (bank rail).

Each source has its **own money** (its own balance on its own rail) but they all
draw down **one shared budget** — modelled by passing every source's wallet the
same ``spent`` holder. Each files its purchase against the shared cap; a source
is refused once the *combined* spend would breach the cap, even though that
source spent little or nothing itself. That cross-source refusal is the whole
point: no single per-rail wallet can enforce it, because none sees the others.

This is a discriminating scenario, exactly like ``escrow_marketplace``:

* Under ``payments: budget_limited`` (with a shared budget) the source that tips
  the combined total over the cap is refused, and total confirmed spend stays
  within the cap. Both budget validators **pass**.
* Under ``payments: prepaid_credits`` (no budget, per-rail balances) every source
  pays from its own funds with nothing watching the total, so combined spend
  blows past the cap and no refusal is ever emitted. Both validators **fail** —
  the baseline lets an overspend through that only a shared ledger catches.

Trace line protocol (colon-delimited ``k=v``, matching
:func:`nest_core.validators._parse_budget_events`)::

    budget:cap:pool=<id>:cap=<int>
    budget:paid:pool=<id>:payer=<id>:payee=<id>:amount=<int>
    budget:refused:pool=<id>:payer=<id>:amount=<int>

Example::

    agents = budget_enforcement_factory(config, plugins)
"""

from __future__ import annotations

from typing import Any

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId, Money, PaymentRef

# The shared budget pool id carried in the trace.
_POOL_ID = "household-restaurant"
_DEFAULT_CAP = 1000
# The four spending sources and the purchase each makes this month. Combined
# they total 1050 (> 1000), so the last source to spend is refused — because of
# spend the others made, on rails it cannot see. Ticks are staggered so the
# order (and therefore who gets refused) is deterministic.
_DEFAULT_SOURCES: tuple[tuple[str, int], ...] = (
    ("human-card", 340),
    ("meal-planner", 280),
    ("travel-agent", 250),
    ("lunch-app", 180),
)
# Each source has ample balance on its own rail — only the shared budget can
# refuse a payment, never an empty wallet.
_SOURCE_BALANCE = 100_000


def _emit(fields: dict[str, str | int]) -> str:
    """Build a ``budget:<kind>:k=v:...`` broadcast payload.

    The colon-separated ``k=v`` form matches the parser in
    :func:`nest_core.validators._parse_budget_events`.

    Example::

        line = _emit({"kind": "paid", "pool": "p", "payer": "human-card", "amount": 340})
    """
    kind = str(fields.pop("kind"))
    body = ":".join(f"{k}={v}" for k, v in fields.items())
    return f"budget:{kind}:{body}" if body else f"budget:{kind}"


class BudgetSourceAgent(StateMachineAgent):
    """One spending source drawing down the shared household budget.

    Announces the shared pool cap on start, then makes a single purchase at its
    assigned tick. The wallet (shared budget) decides: a purchase that fits is
    broadcast as ``budget:paid``; one the shared cap refuses (a raised
    ``ValueError``) as ``budget:refused``. No value moves on a refusal.

    Example::

        src = BudgetSourceAgent(AgentId("human-card"), AgentId("m-0"), "pool", 1000, 340, 1)
    """

    def __init__(
        self,
        agent_id: AgentId,
        merchant: AgentId,
        pool_id: str,
        cap: int,
        amount: int,
        tick: int,
    ) -> None:
        self._id = agent_id
        self._merchant = merchant
        self._pool_id = pool_id
        self._cap = cap
        self._amount = amount
        self._tick = tick

    async def on_start(self, ctx: AgentContext) -> None:
        """Announce the shared cap, then schedule this source's single purchase.

        Example::

            await src.on_start(ctx)
        """
        await ctx.broadcast(
            _emit({"kind": "cap", "pool": self._pool_id, "cap": self._cap}).encode()
        )
        await ctx.schedule(float(self._tick), b"buy")

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Make the purchase, broadcasting paid or refused.

        Example::

            await src.on_message(ctx, src._id, b"buy")
        """
        if payload != b"buy":
            return
        payments = ctx.plugins["payments"]
        ref = PaymentRef(f"{self._id}-buy")
        try:
            await payments.pay(self._merchant, Money(amount=self._amount), ref)
        except ValueError:
            # The shared budget refused this purchase. No value moved.
            await ctx.broadcast(
                _emit(
                    {
                        "kind": "refused",
                        "pool": self._pool_id,
                        "payer": str(self._id),
                        "amount": self._amount,
                    }
                ).encode()
            )
            return
        await ctx.broadcast(
            _emit(
                {
                    "kind": "paid",
                    "pool": self._pool_id,
                    "payer": str(self._id),
                    "payee": str(self._merchant),
                    "amount": self._amount,
                }
            ).encode()
        )


class MerchantAgent(StateMachineAgent):
    """Receives a purchase; holds no logic. Present for roster completeness.

    Example::

        m = MerchantAgent(AgentId("merchant-0"))
    """

    def __init__(self, agent_id: AgentId) -> None:
        self._id = agent_id

    async def on_start(self, ctx: AgentContext) -> None:
        """No startup behaviour.

        Example::

            await m.on_start(ctx)
        """
        return

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Merchants receive no actionable messages.

        Example::

            await m.on_message(ctx, AgentId("human-card"), b"noop")
        """
        return


def budget_enforcement_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Build the spending sources, all sharing one budget and one ledger.

    Every source gets its own wallet instance (its own money on its own rail),
    but all wallets share one ``spent`` holder and one ``balances`` ledger — so
    the budget is a single pool the sources collectively draw down. A plugin
    without a ``spent``/``budget`` kwarg (e.g. ``prepaid_credits``) falls back to
    a budget-less wallet, which is what makes the scenario discriminate: only the
    shared-budget plugin refuses the source that tips the combined total over.

    Example::

        agents = budget_enforcement_factory(config, plugins)
    """
    payments_cls = plugins["payments"]
    cap = int(config.task.config.get("cap", _DEFAULT_CAP))

    # One shared spend counter + one shared money ledger across every source.
    shared_spent: dict[str, int] = {"value": 0}
    shared_balances: dict[AgentId, int] = {}
    shared_payments: dict[PaymentRef, Any] = {}

    def _instance(agent_id: AgentId) -> Any:
        try:
            return payments_cls(
                agent_id,
                initial_balance=_SOURCE_BALANCE,
                budget=cap,
                balances=shared_balances,
                payments=shared_payments,
                spent=shared_spent,
            )
        except TypeError:
            try:
                return payments_cls(
                    agent_id,
                    initial_balance=_SOURCE_BALANCE,
                    balances=shared_balances,
                    payments=shared_payments,
                )
            except TypeError:
                return payments_cls(agent_id, initial_balance=_SOURCE_BALANCE)

    agents: dict[AgentId, StateMachineAgent] = {}
    overrides: dict[AgentId, dict[str, Any]] = {}
    for i, (name, amount) in enumerate(_DEFAULT_SOURCES):
        source_id = AgentId(name)
        merchant_id = AgentId(f"merchant-{i}")
        agents[source_id] = BudgetSourceAgent(
            source_id, merchant_id, _POOL_ID, cap, amount, tick=i + 1
        )
        agents[merchant_id] = MerchantAgent(merchant_id)
        overrides[source_id] = {"payments": _instance(source_id)}

    plugins["_agent_plugins"] = overrides
    return agents
