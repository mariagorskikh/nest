# SPDX-License-Identifier: Apache-2.0
"""Split-settlement scenario -- a content marketplace with revenue sharing.

Twelve agents: three buyers, eight contributors, and one platform.  Each buyer
runs several rounds; every round pays for a content bundle and fans the payment
out 80/20 -- 80% shared between two contributors, 20% to the platform -- through
the ``split_settlement`` plugin.  For every settlement the buyer broadcasts two
structured events the validators read:

* ``split:opened:ref=..:payer=..:weights=payee~weight;...`` -- the *declared*
  weights, locked at open time;
* ``split:settled:ref=..:amount=..:alloc=payee~credit;...`` -- the *actual*
  per-payee credits the plugin produced.

The two ``split_settlement`` validators cross-check those broadcasts: credits
must sum to the amount (no penny-shaving) and must equal the largest-remainder
allocation of the declared weights (no weight tampering).  The round amounts are
deliberately indivisible by the weight total (``777``, ``1001``) so the dust
distribution -- the exact place a naive splitter leaks value -- is exercised in
the trace itself.

If the configured payments plugin lacks ``open_split`` (e.g. the default
``prepaid_credits``), each buyer falls back to a single ``pay()`` and emits no
``split:*`` events, which the validators report as "no split lifecycle observed"
-- the adversarial discrimination the charter requires.

Example::

    agents = split_settlement_factory(config, plugins)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId, Money, PaymentRef

_PLATFORM = AgentId("platform-0")
_CONTRIB_BPS = 40  # each of the two contributors: 40 + 40 = 80% to contributors
_PLATFORM_BPS = 20  # 20% to the platform
_BUYER_BALANCE = 5000


@dataclass
class _Job:
    """One round's settlement: the ref, the locked weights, and the amount.

    Example::

        job = _Job(
            buyer=AgentId("buyer-0"),
            ref=PaymentRef("split-buyer-0-0"),
            payees=_split("contrib-0", "contrib-1"),
            amount=1000,
        )
    """

    buyer: AgentId
    ref: PaymentRef
    payees: tuple[tuple[AgentId, int], ...]
    amount: int


def _split(c1: str, c2: str) -> tuple[tuple[AgentId, int], ...]:
    """Build an 80/20 weight vector: two contributors plus the platform."""
    return (
        (AgentId(c1), _CONTRIB_BPS),
        (AgentId(c2), _CONTRIB_BPS),
        (_PLATFORM, _PLATFORM_BPS),
    )


# buyer -> list of (contributor_a, contributor_b, amount) per round. Amounts mix
# an evenly divisible case (1000) with two indivisible cases (777 -> two dust
# units split across the contributors, 1001 -> one dust unit that a stable
# tie-break must award to the lexicographically smaller contributor).
_PLAN: dict[str, list[tuple[str, str, int]]] = {
    "buyer-0": [
        ("contrib-0", "contrib-1", 1000),
        ("contrib-2", "contrib-3", 777),
        ("contrib-4", "contrib-5", 1001),
    ],
    "buyer-1": [
        ("contrib-6", "contrib-7", 1000),
        ("contrib-0", "contrib-2", 777),
        ("contrib-4", "contrib-6", 1001),
    ],
    "buyer-2": [
        ("contrib-1", "contrib-3", 1000),
        ("contrib-5", "contrib-7", 777),
        ("contrib-0", "contrib-1", 1001),
    ],
}


def _emit_opened(job: _Job) -> bytes:
    """Serialize the declared weights as a ``split:opened`` broadcast payload."""
    weights = ";".join(f"{payee}~{weight}" for payee, weight in job.payees)
    return f"split:opened:ref={job.ref}:payer={job.buyer}:weights={weights}".encode()


def _emit_settled(ref: PaymentRef, amount: int, allocations: list[tuple[str, int]]) -> bytes:
    """Serialize the actual per-payee credits as a ``split:settled`` broadcast."""
    alloc = ";".join(f"{payee}~{credit}" for payee, credit in allocations)
    return f"split:settled:ref={ref}:amount={amount}:alloc={alloc}".encode()


class BuyerAgent(StateMachineAgent):
    """Pays for content each round and fans the payment out 80/20.

    Owns the payer-side ``split_settlement`` instance; contributors and the
    platform are passive credit sinks sharing the same ledger.

    Example::

        agent = BuyerAgent(AgentId("buyer-0"), jobs=[])
    """

    def __init__(self, agent_id: AgentId, jobs: list[_Job]) -> None:
        """Bind the buyer to its id and its per-round settlement plan."""
        self._id = agent_id
        self._jobs = jobs

    async def on_start(self, ctx: AgentContext) -> None:
        """Schedule one ``run:<index>`` wakeup per job, one logical tick apart."""
        for index in range(len(self._jobs)):
            await ctx.schedule(float(index + 1), f"run:{index}".encode())

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Open, broadcast, and settle the scheduled job's fan-out payment."""
        text = payload.decode("utf-8", errors="replace")
        if not text.startswith("run:"):
            return
        job = self._jobs[int(text.split(":", 1)[1])]
        payments = ctx.plugins["payments"]
        if not hasattr(payments, "open_split"):
            # Reference plugin without fan-out: settle to the lead contributor with
            # a plain pay() and emit no split:* events, which the validators flag.
            await payments.pay(job.payees[0][0], Money(amount=job.amount), job.ref)
            return
        await payments.open_split(job.payees, job.ref)
        await ctx.broadcast(_emit_opened(job))
        receipts = await payments.settle_split(job.ref, Money(amount=job.amount))
        allocations = [(str(r.payee), int(r.amount.amount)) for r in receipts]
        await ctx.broadcast(_emit_settled(job.ref, job.amount, allocations))


def split_settlement_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Build the 12 agents and give every buyer a payer instance on one ledger.

    The three buyers share a single ``balances`` + ``contracts`` ledger, so
    conservation is a whole-marketplace property, not a per-buyer one.
    Contributors and the platform are passive: they never call the plugin, they
    only receive credits, so they need no instance of their own.

    Example::

        agents = split_settlement_factory(config, plugins)
    """
    payments_cls = plugins["payments"]
    shared_balances: dict[AgentId, int] = {}
    shared_contracts: dict[PaymentRef, Any] = {}

    def _buyer_instance(agent_id: AgentId) -> Any:
        try:
            return payments_cls(
                agent_id,
                initial_balance=_BUYER_BALANCE,
                balances=shared_balances,
                contracts=shared_contracts,
            )
        except TypeError:
            # Reference plugins (e.g. prepaid_credits) take ``payments`` not
            # ``contracts``; fall back so the discrimination run still boots.
            try:
                return payments_cls(
                    agent_id,
                    initial_balance=_BUYER_BALANCE,
                    balances=shared_balances,
                )
            except TypeError:
                return payments_cls(agent_id, initial_balance=_BUYER_BALANCE)

    agents: dict[AgentId, StateMachineAgent] = {}
    overrides: dict[AgentId, dict[str, Any]] = {}

    for buyer_name, rounds in _PLAN.items():
        buyer_id = AgentId(buyer_name)
        jobs = [
            _Job(
                buyer=buyer_id,
                ref=PaymentRef(f"{buyer_name}-r{index}"),
                payees=_split(c1, c2),
                amount=amount,
            )
            for index, (c1, c2, amount) in enumerate(rounds)
        ]
        agents[buyer_id] = BuyerAgent(buyer_id, jobs)
        overrides[buyer_id] = {"payments": _buyer_instance(buyer_id)}

    for index in range(8):
        agents[AgentId(f"contrib-{index}")] = StateMachineAgent()
    agents[_PLATFORM] = StateMachineAgent()

    plugins["_agent_plugins"] = overrides
    return agents
