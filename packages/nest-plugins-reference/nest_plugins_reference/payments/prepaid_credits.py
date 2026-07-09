# SPDX-License-Identifier: Apache-2.0
"""Prepaid credits payment plugin — simple debit/credit ledger.
Example::
    payments = PrepaidCredits(AgentId("a1"), initial_balance=1000)
    receipt = await payments.pay(AgentId("a2"), Money(amount=50), PaymentRef("p1"))
"""

from __future__ import annotations

import threading

from nest_core.types import (
    AgentId,
    Money,
    PaymentRef,
    PaymentStatus,
    Quote,
    Receipt,
    ServiceRef,
)


class PrepaidCredits:
    """Simple debit/credit ledger for payments.
    Example::
        pay = PrepaidCredits(AgentId("a1"), initial_balance=1000)
        receipt = await pay.pay(AgentId("a2"), Money(amount=50), PaymentRef("p1"))
    """

    def __init__(
        self,
        agent_id: AgentId,
        initial_balance: int = 1000,
        balances: dict[AgentId, int] | None = None,
        payments: dict[PaymentRef, Receipt] | None = None,
    ) -> None:
        self._agent_id = agent_id
        self._balances = balances if balances is not None else {}
        self._balances.setdefault(agent_id, initial_balance)
        self._payments = payments if payments is not None else {}
        self._lock = threading.Lock()

    def balance(self, agent: AgentId) -> int:
        """Check an agent's balance.
        Example::
            bal = pay.balance(AgentId("a1"))
        """
        return self._balances.get(agent, 0)

    async def quote(self, service: ServiceRef) -> Quote:
        """Return a fixed quote for any service.
        Example::
            q = await pay.quote(ServiceRef("svc"))
        """
        return Quote(service=service, price=Money(amount=10))

    async def pay(self, to: AgentId, amount: Money, ref: PaymentRef) -> Receipt:
        """Execute a payment from this agent to another.
        Example::
            receipt = await pay.pay(AgentId("a2"), Money(amount=50), PaymentRef("p1"))
        """
        if amount.amount <= 0:
            msg = f"Payment amount must be positive: {amount.amount}"
            raise ValueError(msg)
        with self._lock:
            if ref in self._payments:
                msg = f"Duplicate payment reference: {ref}"
                raise ValueError(msg)
            payer_balance = self._balances.get(self._agent_id, 0)
            if payer_balance < amount.amount:
                msg = f"Insufficient balance: {payer_balance} < {amount.amount}"
                raise ValueError(msg)
            self._balances[self._agent_id] = payer_balance - amount.amount
            self._balances[to] = self._balances.get(to, 0) + amount.amount
            receipt = Receipt(ref=ref, payer=self._agent_id, payee=to, amount=amount)
            self._payments[ref] = receipt
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
        """Refund a payment.
        Example::
            await pay.refund(PaymentRef("p1"))
        """
        receipt = self._payments.get(ref)
        if receipt is None:
            msg = f"Payment not found: {ref}"
            raise ValueError(msg)
        with self._lock:
            payee_balance = self._balances.get(receipt.payee, 0)
            if payee_balance < receipt.amount.amount:
                msg = (
                    f"Insufficient balance for refund: {receipt.payee} has "
                    f"{payee_balance}, needs {receipt.amount.amount}"
                )
                raise ValueError(msg)
            self._balances[receipt.payee] = payee_balance - receipt.amount.amount
            payer = receipt.payer
            self._balances[payer] = self._balances.get(payer, 0) + receipt.amount.amount
            del self._payments[ref]
