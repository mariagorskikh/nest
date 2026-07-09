# SPDX-License-Identifier: Apache-2.0
"""Weighted multi-payee fan-out settlement.

One atomic debit from a payer is fanned out to *N* payees by declared integer
weights.  A split's weights are locked when the contract is *opened* and are
immutable through settlement, so the amount every payee receives is a pure,
deterministic function of ``(weights, amount)`` that an auditor can recompute
without trusting the plugin.

Exact conservation is guaranteed by the largest-remainder (Hamilton) method:
``sum(allocations) == amount`` for every settlement, with the indivisible
remainder ("dust") handed to the payees holding the largest fractional parts and
a stable tie-break by payee id.  Money is integer credits end to end -- there
are no floats anywhere on the settlement path, so no allocation can silently
create or destroy value through rounding.

This is the fan-out counterpart to the other reference payment plugins:
``prepaid_credits`` moves one debit to one payee, ``escrow`` conditions a single
payee's payout on delivery, ``streaming`` meters one payee per tick.  None of
them splits a single debit across many payees; this plugin does, atomically.

Example::

    pay = SplitSettlement(AgentId("buyer"), initial_balance=1000)
    receipts = await pay.split_pay(
        [(AgentId("author"), 8), (AgentId("platform"), 2)],
        Money(amount=1001),
        PaymentRef("round-1"),
    )
    assert sum(r.amount.amount for r in receipts) == 1001  # nothing created or lost
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from nest_core.types import (
    AgentId,
    Money,
    PaymentRef,
    PaymentStatus,
    Quote,
    Receipt,
    ServiceRef,
)

_STATE_OPEN = "OPEN"
_STATE_SETTLED = "SETTLED"
_STATE_REFUNDED = "REFUNDED"


class SplitError(ValueError):
    """Raised on any split-settlement validation, authorization, or state error.

    Example::

        try:
            await pay.settle_split(PaymentRef("missing"), Money(amount=10))
        except SplitError as exc:
            print(exc)
    """


def allocate_by_weight(
    amount: int,
    weights: Sequence[tuple[AgentId, int]],
) -> list[tuple[AgentId, int]]:
    """Split ``amount`` across ``weights`` by the largest-remainder method.

    Returns one ``(payee, credit)`` pair per entry in ``weights``, in the same
    order.  The result conserves value exactly -- ``sum(credit) == amount`` --
    and is deterministic: each payee first receives the floor of its exact quota
    ``amount * weight / total_weight``, then the indivisible remainder is handed
    out one unit at a time to the payees with the largest fractional part,
    breaking ties by payee id (then original index).  The outcome therefore never
    depends on dict iteration order or floating-point rounding.

    Args:
        amount: Non-negative integer amount to distribute.
        weights: Non-empty sequence of ``(payee, weight)`` with ``weight > 0``.

    Returns:
        A list of ``(payee, credit)`` pairs whose credits sum to ``amount``.

    Raises:
        SplitError: If ``weights`` is empty, ``amount`` is negative, or any
            weight is not a positive integer.

    Example::

        alloc = allocate_by_weight(
            1001, [(AgentId("a"), 3), (AgentId("b"), 1), (AgentId("c"), 1)]
        )
        assert alloc == [(AgentId("a"), 601), (AgentId("b"), 200), (AgentId("c"), 200)]
        assert sum(credit for _, credit in alloc) == 1001
    """
    if not weights:
        raise SplitError("split must name at least one payee")
    if amount < 0:
        msg = f"amount must be non-negative: {amount}"
        raise SplitError(msg)
    total = 0
    for _, weight in weights:
        if weight <= 0:
            msg = f"weight must be a positive integer: {weight}"
            raise SplitError(msg)
        total += weight
    base: list[int] = []
    ranking: list[tuple[int, str, int]] = []
    for index, (payee, weight) in enumerate(weights):
        scaled = amount * weight
        base.append(scaled // total)
        ranking.append((scaled % total, str(payee), index))
    dust = amount - sum(base)
    # Largest remainder first; ties broken by payee id then index for a total,
    # reproducible order.  ``dust`` is in ``[0, len(weights) - 1]`` by construction.
    ranking.sort(key=lambda item: (-item[0], item[1], item[2]))
    for rank in range(dust):
        base[ranking[rank][2]] += 1
    return [(weights[i][0], base[i]) for i in range(len(weights))]


@dataclass
class SplitContract:
    """A fan-out settlement whose weights are fixed at open time.

    ``payees`` is a tuple of ``(payee, weight)`` locked at :meth:`open_split` and
    never mutated afterwards -- opening a contract before settling it is exactly
    what makes the weights un-renegotiable mid-flight.  The mutable fields record
    how the contract was resolved: ``state`` walks ``OPEN -> SETTLED`` (or
    ``SETTLED -> REFUNDED``), and ``settled_amount`` / ``allocations`` capture the
    conserved payout.

    Example::

        contract = SplitContract(
            ref=PaymentRef("r1"),
            payer=AgentId("buyer"),
            payees=((AgentId("author"), 8), (AgentId("platform"), 2)),
            total_weight=10,
        )
        assert contract.state == "OPEN"
    """

    ref: PaymentRef
    payer: AgentId
    payees: tuple[tuple[AgentId, int], ...]
    total_weight: int
    state: str = _STATE_OPEN
    settled_amount: int | None = None
    allocations: tuple[tuple[AgentId, int], ...] | None = None


class SplitSettlement:
    """Atomic weighted fan-out settlement on top of a debit-credit ledger.

    A payer opens a contract naming ``(payee, weight)`` pairs, then settles it for
    a concrete amount.  Settlement debits the payer once and credits every payee
    its largest-remainder share in a single atomic step: either every payee is
    paid and the books balance, or nothing moves and a :class:`SplitError` is
    raised.  Weights are locked at open, so the allocation is a pure function of
    the opened contract and the settled amount.

    The shared ``balances`` / ``contracts`` dicts mirror the ``prepaid_credits``
    and ``escrow`` idiom, so a scenario can hand the same ledger to every agent
    while each holds its own instance keyed by ``agent_id``.  Only the contract's
    payer may settle or refund it.

    Satisfies the ``Payments`` protocol: ``pay(to, amount, ref)`` is the
    degenerate single-payee split (one payee at weight 1), so existing one-shot
    callers keep working.

    Example::

        pay = SplitSettlement(AgentId("buyer"), initial_balance=1000)
        await pay.open_split(
            [(AgentId("author"), 8), (AgentId("platform"), 2)],
            PaymentRef("round-1"),
        )
        receipts = await pay.settle_split(PaymentRef("round-1"), Money(amount=1000))
        assert [r.amount.amount for r in receipts] == [800, 200]
    """

    def __init__(
        self,
        agent_id: AgentId,
        initial_balance: int = 1000,
        balances: dict[AgentId, int] | None = None,
        contracts: dict[PaymentRef, SplitContract] | None = None,
    ) -> None:
        self._agent_id = agent_id
        self._balances = balances if balances is not None else {}
        self._balances.setdefault(agent_id, initial_balance)
        self._contracts = contracts if contracts is not None else {}

    # -- read helpers ----------------------------------------------------

    def balance(self, agent: AgentId) -> int:
        """Return an agent's credit balance.

        Example::

            bal = pay.balance(AgentId("buyer"))
        """
        return self._balances.get(agent, 0)

    def contract(self, ref: PaymentRef) -> SplitContract | None:
        """Return the contract for ``ref`` if one was opened.

        Example::

            contract = pay.contract(PaymentRef("round-1"))
            assert contract is not None and contract.total_weight == 10
        """
        return self._contracts.get(ref)

    def settlement(self, ref: PaymentRef) -> SplitContract | None:
        """Return the contract for ``ref`` only once it has been settled.

        The settled contract *is* the queryable settlement record: it carries the
        conserved ``settled_amount`` and the per-payee ``allocations``.

        Example::

            record = pay.settlement(PaymentRef("round-1"))
            assert record is not None and record.settled_amount == 1000
        """
        contract = self._contracts.get(ref)
        if contract is None or contract.state == _STATE_OPEN:
            return None
        return contract

    def receipts(self, ref: PaymentRef) -> list[Receipt]:
        """Rebuild the per-payee receipts for a settled contract.

        Deterministic and side-effect free -- the receipts are a view over the
        stored allocation, so querying them later yields the same objects as the
        :meth:`settle_split` return value.

        Example::

            for r in pay.receipts(PaymentRef("round-1")):
                print(r.payee, r.amount.amount)

        Raises:
            SplitError: If ``ref`` has no settled contract.
        """
        contract = self.settlement(ref)
        if contract is None or contract.allocations is None:
            msg = f"no settled split for reference: {ref}"
            raise SplitError(msg)
        return [
            Receipt(ref=ref, payer=contract.payer, payee=payee, amount=Money(amount=credit))
            for payee, credit in contract.allocations
        ]

    # -- Payments protocol ----------------------------------------------

    async def quote(self, service: ServiceRef) -> Quote:
        """Return a fixed quote for any service.

        Example::

            q = await pay.quote(ServiceRef("article-bundle"))
        """
        return Quote(service=service, price=Money(amount=10))

    async def pay(self, to: AgentId, amount: Money, ref: PaymentRef) -> Receipt:
        """Pay a single payee -- the degenerate one-payee, weight-1 split.

        Provided so the plugin satisfies the bare ``Payments`` protocol: a plain
        payment is just a fan-out to one payee, so it flows through the exact same
        conserved settlement path.

        Example::

            receipt = await pay.pay(AgentId("author"), Money(amount=50), PaymentRef("p1"))

        Raises:
            SplitError: If ``amount`` is not positive, ``ref`` is already used,
                ``to`` is the payer, or the payer's balance is insufficient.
        """
        receipts = await self.split_pay([(to, 1)], amount, ref)
        return receipts[0]

    async def verify_payment(self, ref: PaymentRef) -> PaymentStatus:
        """Map a contract's lifecycle state to a ``PaymentStatus``.

        Returns ``PENDING`` for an open contract, ``CONFIRMED`` once settled,
        ``REFUNDED`` after a refund, and ``FAILED`` for an unknown reference.

        Example::

            status = await pay.verify_payment(PaymentRef("round-1"))
        """
        contract = self._contracts.get(ref)
        if contract is None:
            return PaymentStatus.FAILED
        if contract.state == _STATE_SETTLED:
            return PaymentStatus.CONFIRMED
        if contract.state == _STATE_REFUNDED:
            return PaymentStatus.REFUNDED
        return PaymentStatus.PENDING

    async def refund(self, ref: PaymentRef) -> None:
        """Reverse a settled fan-out, returning every allocation to the payer.

        Payer-only.  Each payee is debited exactly what it was credited and the
        payer is made whole for the full settled amount.  Atomic: if any payee no
        longer holds its share, nothing moves.

        Example::

            await pay.refund(PaymentRef("round-1"))

        Raises:
            SplitError: If the contract is missing, the caller is not the payer,
                the contract is not settled, or a payee's balance is short.
        """
        contract = self._require_contract(ref)
        if self._agent_id != contract.payer:
            msg = f"only payer {contract.payer} may refund split {ref}"
            raise SplitError(msg)
        if contract.state != _STATE_SETTLED or contract.allocations is None:
            msg = f"cannot refund split {ref} from state {contract.state}"
            raise SplitError(msg)
        for payee, credit in contract.allocations:
            if self._balances.get(payee, 0) < credit:
                msg = f"payee {payee} lacks {credit} to refund split {ref}"
                raise SplitError(msg)
        for payee, credit in contract.allocations:
            self._balances[payee] = self._balances.get(payee, 0) - credit
        self._balances[contract.payer] = self._balances.get(contract.payer, 0) + (
            contract.settled_amount or 0
        )
        contract.state = _STATE_REFUNDED

    # -- split lifecycle -------------------------------------------------

    async def open_split(
        self,
        splits: Sequence[tuple[AgentId, int]],
        ref: PaymentRef,
        *,
        known_payees: frozenset[AgentId] | None = None,
    ) -> SplitContract:
        """Open a fan-out contract with weights locked for its lifetime.

        No funds move at open; the contract records the immutable weight vector
        that :meth:`settle_split` will later honor.  Rejects the settlement
        hazards a naive splitter ignores: an empty payee set, a non-positive
        weight, a payee that repeats, and the payer paying itself.  When
        ``known_payees`` is supplied, any payee outside that roster is rejected --
        identity validation is the registry layer's job, so this hook is opt-in
        rather than an invented in-layer directory.

        Example::

            contract = await pay.open_split(
                [(AgentId("author"), 8), (AgentId("platform"), 2)],
                PaymentRef("round-1"),
            )
            assert contract.total_weight == 10

        Raises:
            SplitError: On an empty split, a non-positive weight, a duplicate or
                self payee, an unknown payee (when ``known_payees`` is given), or a
                reused reference.
        """
        if ref in self._contracts:
            msg = f"reference already used: {ref}"
            raise SplitError(msg)
        payees = tuple((payee, weight) for payee, weight in splits)
        if not payees:
            raise SplitError("split must name at least one payee")
        seen: set[AgentId] = set()
        total_weight = 0
        for payee, weight in payees:
            if weight <= 0:
                msg = f"weight must be a positive integer: {weight}"
                raise SplitError(msg)
            if payee == self._agent_id:
                msg = f"payer {self._agent_id} may not be a payee of its own split"
                raise SplitError(msg)
            if payee in seen:
                msg = f"duplicate payee in split: {payee}"
                raise SplitError(msg)
            if known_payees is not None and payee not in known_payees:
                msg = f"unknown payee: {payee}"
                raise SplitError(msg)
            seen.add(payee)
            total_weight += weight
        contract = SplitContract(
            ref=ref,
            payer=self._agent_id,
            payees=payees,
            total_weight=total_weight,
        )
        self._contracts[ref] = contract
        return contract

    async def settle_split(self, ref: PaymentRef, amount: Money) -> list[Receipt]:
        """Atomically fan ``amount`` out to an open contract's payees.

        Payer-only, single-shot.  Computes the largest-remainder allocation from
        the locked weights, re-checks conservation before any credit is applied,
        then debits the payer once and credits every payee in one pass.  If the
        payer's balance is short, nothing moves.

        Example::

            receipts = await pay.settle_split(PaymentRef("round-1"), Money(amount=1000))
            assert sum(r.amount.amount for r in receipts) == 1000

        Raises:
            SplitError: If the contract is missing, the caller is not the payer,
                the contract is already settled, the amount is not positive, or
                the payer's balance is insufficient.
        """
        contract = self._require_contract(ref)
        if self._agent_id != contract.payer:
            msg = f"only payer {contract.payer} may settle split {ref}"
            raise SplitError(msg)
        if contract.state != _STATE_OPEN:
            msg = f"split {ref} already {contract.state}"
            raise SplitError(msg)
        if amount.amount <= 0:
            msg = f"settlement amount must be positive: {amount.amount}"
            raise SplitError(msg)
        allocations = allocate_by_weight(amount.amount, contract.payees)
        credited = sum(credit for _, credit in allocations)
        if credited != amount.amount:
            # Unreachable given ``allocate_by_weight``; re-checked here so no money
            # is ever moved on a split that does not balance to the last credit.
            msg = f"conservation violated: credited {credited} != debited {amount.amount}"
            raise SplitError(msg)
        payer_balance = self._balances.get(self._agent_id, 0)
        if payer_balance < amount.amount:
            msg = f"insufficient balance: {payer_balance} < {amount.amount}"
            raise SplitError(msg)
        self._balances[self._agent_id] = payer_balance - amount.amount
        for payee, credit in allocations:
            if credit:
                self._balances[payee] = self._balances.get(payee, 0) + credit
        contract.state = _STATE_SETTLED
        contract.settled_amount = amount.amount
        contract.allocations = tuple(allocations)
        return [
            Receipt(ref=ref, payer=contract.payer, payee=payee, amount=Money(amount=credit))
            for payee, credit in allocations
        ]

    async def split_pay(
        self,
        splits: Sequence[tuple[AgentId, int]],
        amount: Money,
        ref: PaymentRef,
    ) -> list[Receipt]:
        """Open and settle a fan-out in one call.

        Convenience for callers that do not need to inspect the contract between
        open and settle.  Unlike the two-phase form -- where a failed
        :meth:`settle_split` leaves the contract ``OPEN`` for a retry after the
        payer tops up -- ``split_pay`` is all-or-nothing: if settlement fails, the
        just-opened contract is rolled back so no ``OPEN`` husk and no consumed
        reference are left behind.

        Example::

            receipts = await pay.split_pay(
                [(AgentId("author"), 8), (AgentId("platform"), 2)],
                Money(amount=1000),
                PaymentRef("round-1"),
            )

        Raises:
            SplitError: For any reason :meth:`open_split` or :meth:`settle_split`
                would raise.
        """
        await self.open_split(splits, ref)
        try:
            return await self.settle_split(ref, amount)
        except SplitError:
            # open_split rejects a reused ref before creating anything, so the
            # contract under ``ref`` was created by this call and is safe to drop.
            self._contracts.pop(ref, None)
            raise

    # -- private ---------------------------------------------------------

    def _require_contract(self, ref: PaymentRef) -> SplitContract:
        contract = self._contracts.get(ref)
        if contract is None:
            msg = f"no split for reference: {ref}"
            raise SplitError(msg)
        return contract
