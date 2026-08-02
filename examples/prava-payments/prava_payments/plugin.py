# SPDX-License-Identifier: Apache-2.0
"""Prava payments-layer plugin for Nanda Town.

Implements the ``Payments`` protocol (quote / pay / verify_payment / refund) and
settles through the Prava rail (offline mock by default, real sandbox with keys).
A Senso-backed trust gate refuses payments to unverified agents -- the required
failure case that the default ``prepaid_credits`` plugin does not model.

Registered via entry point as ``payments: prava`` (see pyproject.toml), so any
scenario selects it with ``layers: { payments: prava }``.

Example::

    pay = PravaPayments(AgentId("buyer"))
    receipt = await pay.pay(AgentId("merchant"), Money(amount=399), PaymentRef("r1"))
"""

from __future__ import annotations

from nest_sdk import (
    AgentId,
    Money,
    PaymentRef,
    PaymentStatus,
    Quote,
    Receipt,
    ServiceRef,
)

from prava_payments.prava_client import PravaClient
from prava_payments.trust import TrustGate, TrustRefusedError


class PravaPayments:
    """Agent-to-agent payments over the Prava rail, gated by Senso trust.

    Keeps a deterministic local ledger for simulation and mirrors each settlement
    and refund through Prava (offline mock unless ``PRAVA_LIVE=1``).

    Example::

        pay = PravaPayments(AgentId("buyer"))
        receipt = await pay.pay(AgentId("merchant"), Money(amount=399), PaymentRef("r1"))
    """

    def __init__(
        self,
        agent_id: AgentId,
        initial_balance: int = 1000,
        *,
        prava: PravaClient | None = None,
        trust: TrustGate | None = None,
        balances: dict[AgentId, int] | None = None,
    ) -> None:
        self._agent_id = agent_id
        self._balances: dict[AgentId, int] = balances if balances is not None else {}
        self._balances.setdefault(agent_id, initial_balance)
        self._payments: dict[PaymentRef, Receipt] = {}
        self._refunded: set[PaymentRef] = set()
        self._prava = prava or PravaClient()
        # Open by default so baseline scenarios run; pass an allowlist / Senso to enforce.
        self._trust = trust or TrustGate()

    def balance(self, agent: AgentId) -> int:
        """Return an agent's current ledger balance.

        Example::

            bal = pay.balance(AgentId("buyer"))
        """
        return self._balances.get(agent, 0)

    async def quote(self, service: ServiceRef) -> Quote:
        """Return a fixed quote for any service.

        Example::

            q = await pay.quote(ServiceRef("prints"))
        """
        return Quote(service=service, price=Money(amount=10))

    async def pay(self, to: AgentId, amount: Money, ref: PaymentRef) -> Receipt:
        """Pay another agent, refusing unverified payees at the trust gate.

        Example::

            receipt = await pay.pay(AgentId("merchant"), Money(amount=399), PaymentRef("r1"))
        """
        if amount.amount <= 0:
            msg = f"Payment amount must be positive: {amount.amount}"
            raise ValueError(msg)
        if ref in self._payments:
            msg = f"Duplicate payment reference: {ref}"
            raise ValueError(msg)

        # Senso trust gate: refuse to issue a Prava token to an unverified counterparty.
        if not self._trust.is_verified(to):
            msg = f"Payee {to} failed Senso verification; Prava token refused"
            raise TrustRefusedError(msg)

        payer_balance = self._balances.get(self._agent_id, 0)
        if payer_balance < amount.amount:
            msg = f"Insufficient balance: {payer_balance} < {amount.amount}"
            raise ValueError(msg)

        # Settle through Prava (offline mock unless PRAVA_LIVE=1).
        await self._prava.settle(
            payer=str(self._agent_id),
            payee=str(to),
            amount=amount.amount,
            currency=amount.currency,
            ref=str(ref),
        )

        self._balances[self._agent_id] = payer_balance - amount.amount
        self._balances[to] = self._balances.get(to, 0) + amount.amount
        receipt = Receipt(ref=ref, payer=self._agent_id, payee=to, amount=amount)
        self._payments[ref] = receipt
        return receipt

    async def verify_payment(self, ref: PaymentRef) -> PaymentStatus:
        """Return the status of a payment by reference.

        Example::

            status = await pay.verify_payment(PaymentRef("r1"))
        """
        if ref in self._refunded:
            return PaymentStatus.REFUNDED
        if ref in self._payments:
            return PaymentStatus.CONFIRMED
        return PaymentStatus.FAILED

    async def refund(self, ref: PaymentRef) -> None:
        """Refund a settled payment, reversing the ledger entry.

        Example::

            await pay.refund(PaymentRef("r1"))
        """
        receipt = self._payments.get(ref)
        if receipt is None:
            msg = f"Payment not found: {ref}"
            raise ValueError(msg)

        payee_balance = self._balances.get(receipt.payee, 0)
        if payee_balance < receipt.amount.amount:
            msg = f"Insufficient balance for refund: {receipt.payee} has {payee_balance}"
            raise ValueError(msg)

        self._balances[receipt.payee] = payee_balance - receipt.amount.amount
        payer_balance = self._balances.get(receipt.payer, 0)
        self._balances[receipt.payer] = payer_balance + receipt.amount.amount
        await self._prava.refund(str(ref))
        del self._payments[ref]
        self._refunded.add(ref)
