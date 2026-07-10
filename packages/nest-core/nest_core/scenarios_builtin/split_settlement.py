# SPDX-License-Identifier: Apache-2.0
"""Split-settlement scenario -- a content marketplace with revenue sharing.

Twelve agents: three buyers, eight contributors, and one platform.  Each buyer
runs several rounds; every round pays for a content bundle and fans the payment
out 80/20 -- 80% shared between two contributors, 20% to the platform -- through
the ``split_settlement`` plugin.  For every settlement the buyer broadcasts two
payer-side structured events the validators read:

* ``split:opened:ref=..:payer=..:weights=payee~weight;...`` -- the *declared*
  weights, locked at open time;
* ``split:settled:ref=..:amount=..:alloc=payee~credit;...`` -- the *actual*
  per-payee credits the plugin *reported* in its receipts.

Both of those are the payer's own account of what happened.  So each payee is a
separate agent holding a *read-only view* of the shared ledger, and after every
settlement it observes it broadcasts a third, payee-side event:

* ``split:observed:ref=..:payee=..:balance=..`` -- the payee's *current
  shared-ledger balance*, the ground truth the payer cannot forge.

The three ``split_settlement`` validators cross-check those broadcasts: credits
must sum to the amount (no penny-shaving), must equal the largest-remainder
allocation of the declared weights (no weight tampering), and each payee's
attested balance *delta* between consecutive settlements must equal the credit
the payer reported to it (no ledger skimming behind honest-looking receipts).
The round amounts are deliberately indivisible by the weight total (``777``,
``1001``) so the dust distribution -- the exact place a naive splitter leaks
value -- is exercised in the trace itself.

Settlements are scheduled one-per-tick (each ``(buyer, round)`` lands on its own
distinct tick) so that a payee credited by several settlements observes exactly
one credit between consecutive attestations; the balance delta is then a clean,
per-settlement quantity the ledger-attestation validator can check.  Scheduling
is a pure function of ``(buyer, round)`` -- no wall clock, no RNG -- so the trace
is byte-identical for a given seed.

If the configured payments plugin lacks ``open_split`` (e.g. the default
``prepaid_credits``), each buyer falls back to a single ``pay()`` and emits no
``split:*`` events, which the validators report as "no split lifecycle observed"
-- the adversarial discrimination the charter requires.

Example::

    agents = split_settlement_factory(config, plugins)
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId, Money, PaymentRef

_PLATFORM = AgentId("platform-0")
_CONTRIB_WEIGHT = 40  # each of the two contributors: 40 + 40 = 80% to contributors
_PLATFORM_WEIGHT = 20  # 20% to the platform
_BUYER_BALANCE = 5000
_ROUND_TICK_SPACING = 3  # buyers per round; one settlement per tick, no collisions


@dataclass
class _Job:
    """One round's settlement: the ref, the locked weights, the amount, and its tick.

    ``tick`` is the settlement's own dedicated logical tick.  Every ``(buyer,
    round)`` gets a distinct tick so no two settlements collide, which keeps each
    payee's per-settlement balance delta observable and unambiguous.

    Example::

        job = _Job(
            buyer=AgentId("buyer-0"),
            ref=PaymentRef("split-buyer-0-0"),
            payees=_split("contrib-0", "contrib-1"),
            amount=1000,
            tick=1,
        )
    """

    buyer: AgentId
    ref: PaymentRef
    payees: tuple[tuple[AgentId, int], ...]
    amount: int
    tick: int


def _split(c1: str, c2: str) -> tuple[tuple[AgentId, int], ...]:
    """Build an 80/20 weight vector: two contributors plus the platform."""
    return (
        (AgentId(c1), _CONTRIB_WEIGHT),
        (AgentId(c2), _CONTRIB_WEIGHT),
        (_PLATFORM, _PLATFORM_WEIGHT),
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


def _emit_observed(ref: str, payee: AgentId, balance: int) -> bytes:
    """Serialize a payee's current shared-ledger balance as ``split:observed``."""
    return f"split:observed:ref={ref}:payee={payee}:balance={balance}".encode()


def _settled_ref_and_payees(text: str) -> tuple[str, list[str]] | None:
    """Extract ``(ref, [payee, ...])`` from a ``split:settled`` broadcast payload.

    Returns ``None`` if the payload is not a settled event.  The payee list is the
    names in the ``alloc`` field, in declared order -- used by a payee to decide
    whether a settlement concerned it and which reference to attest against.

    Example::

        ref, payees = _settled_ref_and_payees(
            "split:settled:ref=r0:amount=1000:alloc=contrib-0~400;platform-0~200"
        )
        assert ref == "r0" and payees == ["contrib-0", "platform-0"]
    """
    if not text.startswith("split:settled:"):
        return None
    fields: dict[str, str] = {}
    for piece in text.split(":")[2:]:
        key, sep, value = piece.partition("=")
        if sep:
            fields[key] = value
    payees = [pair.partition("~")[0] for pair in fields.get("alloc", "").split(";") if "~" in pair]
    return fields.get("ref", ""), payees


class BuyerAgent(StateMachineAgent):
    """Pays for content each round and fans the payment out 80/20.

    Owns the payer-side ``split_settlement`` instance and broadcasts the
    ``split:opened`` / ``split:settled`` account of each round.  Contributors and
    the platform hold a read-only view of the same ledger and attest their
    balances back (see :class:`_PayeeObserverAgent`).

    Example::

        agent = BuyerAgent(AgentId("buyer-0"), jobs=[])
    """

    def __init__(self, agent_id: AgentId, jobs: list[_Job]) -> None:
        """Bind the buyer to its id and its per-round settlement plan."""
        self._id = agent_id
        self._jobs = jobs

    async def on_start(self, ctx: AgentContext) -> None:
        """Schedule one ``run:<index>`` wakeup per job at the job's dedicated tick.

        Each job carries its own distinct tick, so settlements never share a tick
        and every payee observes exactly one credit between attestations.
        """
        for index, job in enumerate(self._jobs):
            await ctx.schedule(float(job.tick), f"run:{index}".encode())

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


class _PayeeObserverAgent(StateMachineAgent):
    """A payee (contributor or platform) that attests its ledger balance.

    Holds a *read-only view* of the shared ledger -- it can never move funds,
    only observe them.  When it sees a ``split:settled`` broadcast that names it
    as a payee, it reads its current shared-ledger balance and broadcasts a
    ``split:observed`` attestation for that reference.  Because settlements are
    scheduled one-per-tick, the attestation reflects exactly the balance produced
    by that one settlement, so the ledger-attestation validator can turn the
    sequence of a payee's attestations into per-settlement deltas.

    The attestation is ledger truth, independent of the payer's self-reported
    receipts: a splitter that returns canonical receipts but credits the ledger
    short is caught here even though it fools the receipt-auditing validators.

    Example::

        agent = _PayeeObserverAgent(MappingProxyType({}))
    """

    def __init__(self, ledger: Mapping[AgentId, int]) -> None:
        """Bind the payee to a read-only view of the shared balance ledger."""
        self._ledger = ledger

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Attest this payee's current ledger balance for a settlement it is in."""
        text = payload.decode("utf-8", errors="replace")
        parsed = _settled_ref_and_payees(text)
        if parsed is None:
            return
        ref, payees = parsed
        me = str(ctx.agent_id)
        if me not in payees:
            return
        balance = self._ledger.get(ctx.agent_id, 0)
        await ctx.broadcast(_emit_observed(ref, ctx.agent_id, balance))


def split_settlement_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Build the 12 agents and give every buyer a payer instance on one ledger.

    The three buyers share a single ``balances`` + ``contracts`` ledger, so
    conservation is a whole-marketplace property, not a per-buyer one.
    Contributors and the platform never *move* funds -- they hold a read-only
    view of that same ledger and attest their own balances, so the settlement is
    audited against ledger truth and not only the payer's receipts.  Every
    ``(buyer, round)`` is scheduled on its own distinct tick so no two settlements
    collide and each payee's balance delta stays a clean per-settlement quantity.

    Example::

        agents = split_settlement_factory(config, plugins)
    """
    payments_cls = plugins["payments"]
    shared_balances: dict[AgentId, int] = {}
    shared_contracts: dict[PaymentRef, Any] = {}
    ledger_view: Mapping[AgentId, int] = MappingProxyType(shared_balances)

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

    for buyer_slot, (buyer_name, rounds) in enumerate(_PLAN.items()):
        buyer_id = AgentId(buyer_name)
        jobs = [
            _Job(
                buyer=buyer_id,
                ref=PaymentRef(f"{buyer_name}-r{index}"),
                payees=_split(c1, c2),
                amount=amount,
                # Distinct tick per (buyer, round): round-major, buyer-within-round.
                # With three buyers this maps the nine settlements onto ticks 1..9,
                # one settlement per tick, so no payee is credited twice in a tick.
                tick=index * _ROUND_TICK_SPACING + buyer_slot + 1,
            )
            for index, (c1, c2, amount) in enumerate(rounds)
        ]
        agents[buyer_id] = BuyerAgent(buyer_id, jobs)
        overrides[buyer_id] = {"payments": _buyer_instance(buyer_id)}

    for index in range(8):
        agents[AgentId(f"contrib-{index}")] = _PayeeObserverAgent(ledger_view)
    agents[_PLATFORM] = _PayeeObserverAgent(ledger_view)

    plugins["_agent_plugins"] = overrides
    return agents
