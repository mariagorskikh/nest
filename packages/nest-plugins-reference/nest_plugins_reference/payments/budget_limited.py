# SPDX-License-Identifier: Apache-2.0
"""Budget-limited payments plugin — a prepaid ledger with a cumulative spend cap.

Persona: **payments-risk engineer.** The control here exists because an
autonomous agent that can move money is a spending-risk surface — whether it is
merely over-eager, prompt-injected, or driven by a hostile counterparty. A
balance check is not a budget: it only asks "are there funds?", never "is this
authorized?". This plugin adds the missing authorization control.

Unlike a plain balance check, the budget caps *total* spend over the plugin's
lifetime: an agent with plenty of balance still cannot spend past its authorized
budget. ``pay()`` refuses (raises) a payment that would push cumulative spend
over the budget, *before* any value moves; ``remaining()`` reports the headroom
an agent should check before an autonomous purchase.

Threat model (each denied, and pinned by tests):

* **Overspend by attrition** — many small payments that individually fit but
  cumulatively breach the cap. Denied: the cap is checked against *cumulative*
  spend, not the single amount.
* **Currency confusion** — a payment declared in a different currency to slip
  past a cap tracked in another. Denied: a mismatched currency is rejected, not
  summed and not treated as free headroom.
* **Refund-replay inflation** — refunding to reclaim budget headroom, then
  replaying the refund to inflate it further. Denied: a refund releases exactly
  the charged amount once; a second refund of the same reference raises.

Example::

    payments = BudgetLimitedPayments(AgentId("a1"), initial_balance=1000, budget=100)
    await payments.pay(AgentId("a2"), Money(amount=60), PaymentRef("p1"))
    payments.remaining()  # 40
    await payments.pay(AgentId("a2"), Money(amount=60), PaymentRef("p2"))  # raises: over budget
"""

from __future__ import annotations

from nest_core.types import (
    AgentId,
    Money,
    PaymentRef,
    PaymentStatus,
    Quote,
    Receipt,
    ServiceRef,
)


class BudgetLimitedPayments:
    """Prepaid debit/credit ledger that also enforces a cumulative spend budget.

    The budget is single-currency: payments in a different currency are rejected
    rather than silently summed, mirroring the rule that amounts are never added
    across currencies.

    The budget can be **shared** across several wallets by passing the same
    mutable ``spent`` holder to each: every source then draws down one common
    cap, so one source is refused because of spend the others made — the
    cross-source enforcement no single per-wallet cap can do.

    Example::

        pay = BudgetLimitedPayments(AgentId("a1"), initial_balance=1000, budget=100)
        receipt = await pay.pay(AgentId("a2"), Money(amount=50), PaymentRef("p1"))
    """

    def __init__(
        self,
        agent_id: AgentId,
        initial_balance: int = 1000,
        budget: int = 1000,
        currency: str = "credits",
        balances: dict[AgentId, int] | None = None,
        payments: dict[PaymentRef, Receipt] | None = None,
        spent: dict[str, int] | None = None,
    ) -> None:
        if budget < 0:
            msg = f"Budget must be non-negative: {budget}"
            raise ValueError(msg)
        self._agent_id = agent_id
        self._budget = budget
        self._currency = currency
        # Cumulative spend lives in a shared, mutable holder so multiple wallets
        # can draw down one common budget. Own holder by default (per-wallet cap).
        self._spent_holder = spent if spent is not None else {"value": 0}
        self._spent_holder.setdefault("value", 0)
        self._balances = balances if balances is not None else {}
        self._balances.setdefault(agent_id, initial_balance)
        self._payments = payments if payments is not None else {}
        self._charged: dict[PaymentRef, int] = {}

    @property
    def _spent(self) -> int:
        """Cumulative spend against the (possibly shared) budget."""
        return self._spent_holder["value"]

    @_spent.setter
    def _spent(self, value: int) -> None:
        self._spent_holder["value"] = value

    def balance(self, agent: AgentId) -> int:
        """Check an agent's balance.

        Example::

            bal = pay.balance(AgentId("a1"))
        """
        return self._balances.get(agent, 0)

    def spent(self) -> int:
        """Return cumulative confirmed spend counted against the budget.

        Example::

            total = pay.spent()
        """
        return self._spent

    def remaining(self) -> int:
        """Return budget headroom left (never negative).

        Example::

            left = pay.remaining()
        """
        return max(0, self._budget - self._spent)

    def within_budget(self, amount: Money) -> bool:
        """Return whether paying ``amount`` would stay within budget and currency.

        Example::

            ok = pay.within_budget(Money(amount=40))
        """
        if amount.currency != self._currency:
            return False
        return self._spent + amount.amount <= self._budget

    async def quote(self, service: ServiceRef) -> Quote:
        """Return a fixed quote for any service.

        Example::

            q = await pay.quote(ServiceRef("svc"))
        """
        return Quote(service=service, price=Money(amount=10, currency=self._currency))

    async def pay(self, to: AgentId, amount: Money, ref: PaymentRef) -> Receipt:
        """Execute a payment, refusing anything over the remaining budget.

        Raises ``ValueError`` for a non-positive amount, a currency mismatch, a
        duplicate reference, a budget overrun, or insufficient balance — the
        budget is checked before any value moves.

        Example::

            receipt = await pay.pay(AgentId("a2"), Money(amount=50), PaymentRef("p1"))
        """
        if amount.amount <= 0:
            msg = f"Payment amount must be positive: {amount.amount}"
            raise ValueError(msg)
        if amount.currency != self._currency:
            msg = f"Currency mismatch: {amount.currency} != {self._currency}"
            raise ValueError(msg)
        if ref in self._payments:
            msg = f"Duplicate payment reference: {ref}"
            raise ValueError(msg)
        if self._spent + amount.amount > self._budget:
            msg = (
                f"Budget exceeded: {self._spent} + {amount.amount} > {self._budget} "
                f"({self._currency})"
            )
            raise ValueError(msg)

        payer_balance = self._balances.get(self._agent_id, 0)
        if payer_balance < amount.amount:
            msg = f"Insufficient balance: {payer_balance} < {amount.amount}"
            raise ValueError(msg)

        self._balances[self._agent_id] = payer_balance - amount.amount
        self._balances[to] = self._balances.get(to, 0) + amount.amount
        self._spent += amount.amount

        receipt = Receipt(ref=ref, payer=self._agent_id, payee=to, amount=amount)
        self._payments[ref] = receipt
        self._charged[ref] = amount.amount
        return receipt

    async def verify_payment(self, ref: PaymentRef) -> PaymentStatus:
        """Verify a payment status by reference.

        Example::

            status = await pay.verify_payment(PaymentRef("p1"))
        """
        if ref in self._payments:
            return PaymentStatus.CONFIRMED
        return PaymentStatus.FAILED

    async def refund(self, ref: PaymentRef) -> None:
        """Refund a payment and release its amount back into the budget.

        Example::

            await pay.refund(PaymentRef("p1"))
        """
        receipt = self._payments.get(ref)
        if receipt is None:
            msg = f"Payment not found: {ref}"
            raise ValueError(msg)

        payee_balance = self._balances.get(receipt.payee, 0)
        if payee_balance < receipt.amount.amount:
            msg = (
                f"Insufficient balance for refund: {receipt.payee} has "
                f"{payee_balance}, needs {receipt.amount.amount}"
            )
            raise ValueError(msg)

        self._balances[receipt.payee] = payee_balance - receipt.amount.amount
        self._balances[receipt.payer] = self._balances.get(receipt.payer, 0) + receipt.amount.amount
        self._spent -= self._charged.pop(ref, receipt.amount.amount)
        del self._payments[ref]
