# SPDX-License-Identifier: Apache-2.0
"""Escrow payments plugin — conditional, arbitrated, multi-party value transfer.

Extends the prepaid-credit ledger with a three-phase escrow protocol:

    FUNDED -> DELIVERED -> RELEASED            (happy path)
    FUNDED -> DELIVERED -> DISPUTED -> ARBITRATED   (contested path)
    FUNDED -> REFUNDED                         (payer recalls before delivery)

Funds are debited from the payer at ``open_escrow`` and held by the vault
until the payer signs ``release`` (full payout to payee), the payer signs
``dispute`` and the named arbiter signs ``arbitrate`` (basis-point split),
or the payer signs ``refund`` while the work is still undelivered.

Authorization is enforced by ``self._agent_id``: only the role-holding
agent's plugin instance can advance the state. The shared ``escrows``
dict mirrors the shared ``balances`` dict used by ``prepaid_credits`` and
``streaming``, so a scenario can hand the same vault to all three roles.

Satisfies the ``Payments`` protocol; ``pay()`` is a one-call shortcut
that opens and releases an escrow in a single step (no arbiter, no
delivery proof) so existing Payments callers still work.

Example::

    payments = EscrowPayments(AgentId("buyer"), initial_balance=1000)
    handle = await payments.open_escrow(
        payee=AgentId("seller"),
        arbiter=AgentId("arbiter"),
        amount=Money(amount=250),
        ref=PaymentRef("job-1"),
    )
    # ... later, on the payee's instance (sharing the same balances + escrows dicts) ...
    await payee_payments.deliver(PaymentRef("job-1"), proof="sha256:cafe")
    # ... back on the buyer's instance ...
    receipt = await payments.release(PaymentRef("job-1"))
"""

from __future__ import annotations

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

_BPS_DENOM = 10_000


class EscrowError(ValueError):
    """Raised on any escrow state-machine or authorization violation.

    Example::

        try:
            await payments.release(PaymentRef("x"))
        except EscrowError as e:
            print(e)
    """


@dataclass
class EscrowHandle:
    """Per-escrow state held by the shared vault.

    Example::

        handle = EscrowHandle(
            ref=PaymentRef("job-1"),
            payer=AgentId("buyer"),
            payee=AgentId("seller"),
            arbiter=AgentId("arbiter"),
            amount=250,
            state="FUNDED",
        )
    """

    ref: PaymentRef
    payer: AgentId
    payee: AgentId
    arbiter: AgentId
    amount: int
    state: str
    proof: str | None = None
    dispute_reason: str | None = None
    payee_bps_paid: int | None = None
    rationale: str | None = None


class EscrowPayments:
    """Conditional, arbitrated escrow on top of a debit-credit ledger.

    Three roles per escrow, named at ``open_escrow`` time and bound to
    agent ids:

    * **payer** — funds the vault; can ``release``, ``dispute``, or
      ``refund`` (only while still ``FUNDED``).
    * **payee** — can ``deliver`` against the open escrow once.
    * **arbiter** — can ``arbitrate`` only after the payer disputes;
      issues a basis-point split (``payee_bps`` in ``[0, 10000]``) that
      decides how much of the locked amount each side receives.

    Every transition checks ``self._agent_id`` against the role the
    transition is reserved for; calling out of role raises
    :class:`EscrowError`. Calling out of state (e.g. releasing an
    escrow that has not been delivered) also raises.

    The plugin satisfies the ``Payments`` protocol. ``pay()`` is a
    one-call shortcut that opens and releases an escrow in a single
    step so existing Payments callers continue to work; ``refund()``
    only succeeds on escrows that are still ``FUNDED``.

    Example::

        payments = EscrowPayments(AgentId("buyer"), initial_balance=1000)
        handle = await payments.open_escrow(
            payee=AgentId("seller"),
            arbiter=AgentId("arbiter"),
            amount=Money(amount=250),
            ref=PaymentRef("job-1"),
        )
        assert handle.state == "FUNDED"
    """

    def __init__(
        self,
        agent_id: AgentId,
        initial_balance: int = 1000,
        balances: dict[AgentId, int] | None = None,
        payments: dict[PaymentRef, Receipt] | None = None,
        escrows: dict[PaymentRef, EscrowHandle] | None = None,
    ) -> None:
        self._agent_id = agent_id
        self._balances = balances if balances is not None else {}
        self._balances.setdefault(agent_id, initial_balance)
        self._payments = payments if payments is not None else {}
        self._escrows = escrows if escrows is not None else {}

    # -- read helpers ----------------------------------------------------

    def balance(self, agent: AgentId) -> int:
        """Return an agent's balance.

        Example::

            bal = payments.balance(AgentId("buyer"))
        """
        return self._balances.get(agent, 0)

    def escrow(self, ref: PaymentRef) -> EscrowHandle | None:
        """Return the escrow handle for ``ref`` if it exists.

        Example::

            handle = payments.escrow(PaymentRef("job-1"))
            assert handle is not None and handle.state == "FUNDED"
        """
        return self._escrows.get(ref)

    # -- escrow lifecycle ------------------------------------------------

    async def open_escrow(
        self,
        payee: AgentId,
        arbiter: AgentId,
        amount: Money,
        ref: PaymentRef,
    ) -> EscrowHandle:
        """Lock ``amount`` in a new escrow vault. Only the payer may call.

        The payer's balance is debited immediately; the funds are held
        by the vault until ``release``, ``arbitrate``, or ``refund``.

        Example::

            handle = await payments.open_escrow(
                payee=AgentId("seller"),
                arbiter=AgentId("arbiter"),
                amount=Money(amount=250),
                ref=PaymentRef("job-1"),
            )

        Raises:
            EscrowError: If amount is not positive, ``ref`` already used,
                payer's balance is insufficient, or arbiter equals payer
                or payee.
        """
        if amount.amount <= 0:
            msg = f"escrow amount must be positive: {amount.amount}"
            raise EscrowError(msg)
        if ref in self._payments or ref in self._escrows:
            msg = f"reference already used: {ref}"
            raise EscrowError(msg)
        if arbiter == self._agent_id or arbiter == payee:
            msg = "arbiter must be distinct from payer and payee"
            raise EscrowError(msg)

        payer_balance = self._balances.get(self._agent_id, 0)
        if payer_balance < amount.amount:
            msg = f"insufficient balance to fund escrow: {payer_balance} < {amount.amount}"
            raise EscrowError(msg)

        self._balances[self._agent_id] = payer_balance - amount.amount
        handle = EscrowHandle(
            ref=ref,
            payer=self._agent_id,
            payee=payee,
            arbiter=arbiter,
            amount=amount.amount,
            state="FUNDED",
        )
        self._escrows[ref] = handle
        return handle

    async def deliver(self, ref: PaymentRef, proof: str) -> EscrowHandle:
        """Attach a delivery proof to ``ref``. Only the named payee may call.

        ``proof`` is opaque to the plugin (a content hash, URL, or
        signed receipt). The payer reads it off-band and decides to
        ``release`` or ``dispute``.

        Example::

            handle = await payee_payments.deliver(
                PaymentRef("job-1"),
                proof="sha256:cafe",
            )
            assert handle.state == "DELIVERED"

        Raises:
            EscrowError: If escrow does not exist, caller is not the
                payee, or state is not ``FUNDED``.
        """
        handle = self._require_escrow(ref)
        if self._agent_id != handle.payee:
            msg = f"only payee {handle.payee} may deliver escrow {ref}"
            raise EscrowError(msg)
        if handle.state != "FUNDED":
            msg = f"cannot deliver escrow {ref} from state {handle.state}"
            raise EscrowError(msg)
        handle.proof = proof
        handle.state = "DELIVERED"
        return handle

    async def release(self, ref: PaymentRef) -> Receipt:
        """Pay out the full escrow amount to the payee. Payer-only.

        Example::

            receipt = await payments.release(PaymentRef("job-1"))
            assert receipt.amount.amount == 250

        Raises:
            EscrowError: If escrow does not exist, caller is not the
                payer, or state is not ``DELIVERED``.
        """
        handle = self._require_escrow(ref)
        if self._agent_id != handle.payer:
            msg = f"only payer {handle.payer} may release escrow {ref}"
            raise EscrowError(msg)
        if handle.state != "DELIVERED":
            msg = f"cannot release escrow {ref} from state {handle.state}"
            raise EscrowError(msg)
        self._balances[handle.payee] = self._balances.get(handle.payee, 0) + handle.amount
        handle.state = "RELEASED"
        handle.payee_bps_paid = _BPS_DENOM
        receipt = Receipt(
            ref=ref,
            payer=handle.payer,
            payee=handle.payee,
            amount=Money(amount=handle.amount),
        )
        self._payments[ref] = receipt
        return receipt

    async def dispute(self, ref: PaymentRef, reason: str) -> EscrowHandle:
        """Contest the delivery. Payer-only; transitions to ``DISPUTED``.

        Once disputed the payer can no longer ``release`` -- only the
        named arbiter can resolve, via :meth:`arbitrate`.

        Example::

            handle = await payments.dispute(
                PaymentRef("job-1"),
                reason="transcript missing last 4 minutes",
            )

        Raises:
            EscrowError: If escrow does not exist, caller is not the
                payer, or state is not ``DELIVERED``.
        """
        handle = self._require_escrow(ref)
        if self._agent_id != handle.payer:
            msg = f"only payer {handle.payer} may dispute escrow {ref}"
            raise EscrowError(msg)
        if handle.state != "DELIVERED":
            msg = f"cannot dispute escrow {ref} from state {handle.state}"
            raise EscrowError(msg)
        handle.state = "DISPUTED"
        handle.dispute_reason = reason
        return handle

    async def arbitrate(
        self,
        ref: PaymentRef,
        payee_bps: int,
        rationale: str,
    ) -> Receipt:
        """Resolve a disputed escrow with a basis-point payout split.

        ``payee_bps`` is the payee's share in basis points ``[0, 10000]``.
        The payee receives ``amount * payee_bps / 10000``; the payer is
        credited the remainder. Settlement is atomic.

        Example::

            receipt = await arbiter_payments.arbitrate(
                PaymentRef("job-1"),
                payee_bps=6000,
                rationale="approx 60% usable",
            )

        Raises:
            EscrowError: If escrow does not exist, caller is not the
                named arbiter, state is not ``DISPUTED``, or
                ``payee_bps`` is outside ``[0, 10000]``.
        """
        handle = self._require_escrow(ref)
        if self._agent_id != handle.arbiter:
            msg = f"only arbiter {handle.arbiter} may arbitrate escrow {ref}"
            raise EscrowError(msg)
        if handle.state != "DISPUTED":
            msg = f"cannot arbitrate escrow {ref} from state {handle.state}"
            raise EscrowError(msg)
        if not 0 <= payee_bps <= _BPS_DENOM:
            msg = f"payee_bps must be in [0, {_BPS_DENOM}]: {payee_bps}"
            raise EscrowError(msg)

        to_payee = handle.amount * payee_bps // _BPS_DENOM
        to_payer = handle.amount - to_payee
        if to_payee:
            self._balances[handle.payee] = self._balances.get(handle.payee, 0) + to_payee
        if to_payer:
            self._balances[handle.payer] = self._balances.get(handle.payer, 0) + to_payer
        handle.state = "ARBITRATED"
        handle.payee_bps_paid = payee_bps
        handle.rationale = rationale
        receipt = Receipt(
            ref=ref,
            payer=handle.payer,
            payee=handle.payee,
            amount=Money(amount=to_payee),
        )
        self._payments[ref] = receipt
        return receipt

    # -- Payments protocol -----------------------------------------------

    async def quote(self, service: ServiceRef) -> Quote:
        """Return a fixed quote for any service.

        Example::

            q = await payments.quote(ServiceRef("svc"))
        """
        return Quote(service=service, price=Money(amount=10))

    async def pay(self, to: AgentId, amount: Money, ref: PaymentRef) -> Receipt:
        """Open and release an escrow in one call (no arbiter, no proof).

        Provided so the plugin satisfies the bare ``Payments`` protocol.
        The escrow's ``arbiter`` is set to the recipient as a sentinel;
        the escrow is auto-released before any third party can act, so
        the arbiter never matters.

        Example::

            receipt = await payments.pay(
                AgentId("seller"),
                Money(amount=50),
                PaymentRef("p1"),
            )

        Raises:
            EscrowError: If amount is not positive, ``ref`` already used,
                or payer balance is insufficient.
        """
        if amount.amount <= 0:
            msg = f"payment amount must be positive: {amount.amount}"
            raise EscrowError(msg)
        if ref in self._payments or ref in self._escrows:
            msg = f"reference already used: {ref}"
            raise EscrowError(msg)
        payer_balance = self._balances.get(self._agent_id, 0)
        if payer_balance < amount.amount:
            msg = f"insufficient balance: {payer_balance} < {amount.amount}"
            raise EscrowError(msg)
        self._balances[self._agent_id] = payer_balance - amount.amount
        self._balances[to] = self._balances.get(to, 0) + amount.amount
        receipt = Receipt(ref=ref, payer=self._agent_id, payee=to, amount=amount)
        self._payments[ref] = receipt
        return receipt

    async def verify_payment(self, ref: PaymentRef) -> PaymentStatus:
        """Map escrow/payment state to a ``PaymentStatus``.

        Returns ``CONFIRMED`` once an escrow reaches ``RELEASED`` or
        ``ARBITRATED`` (or for any straight ``pay()`` receipt), and
        ``PENDING`` while an escrow is mid-flight.

        Example::

            status = await payments.verify_payment(PaymentRef("job-1"))
        """
        if ref in self._payments and ref not in self._escrows:
            return PaymentStatus.CONFIRMED
        handle = self._escrows.get(ref)
        if handle is None:
            return PaymentStatus.FAILED
        if handle.state in ("RELEASED", "ARBITRATED"):
            return PaymentStatus.CONFIRMED
        if handle.state == "REFUNDED":
            return PaymentStatus.FAILED
        return PaymentStatus.PENDING

    async def refund(self, ref: PaymentRef) -> None:
        """Recall funds from an escrow that has not been delivered. Payer-only.

        Only succeeds while the escrow is still ``FUNDED`` (the payee
        has not posted a delivery proof yet). After delivery, the
        payer must either ``release`` or ``dispute``; ``refund`` is no
        longer available.

        Example::

            await payments.refund(PaymentRef("job-1"))

        Raises:
            EscrowError: If escrow does not exist, caller is not the
                payer, or state is not ``FUNDED``.
        """
        handle = self._escrows.get(ref)
        if handle is None:
            msg = f"escrow not found: {ref}"
            raise EscrowError(msg)
        if self._agent_id != handle.payer:
            msg = f"only payer {handle.payer} may refund escrow {ref}"
            raise EscrowError(msg)
        if handle.state != "FUNDED":
            msg = f"cannot refund escrow {ref} from state {handle.state}"
            raise EscrowError(msg)
        self._balances[handle.payer] = self._balances.get(handle.payer, 0) + handle.amount
        handle.state = "REFUNDED"

    # -- private ---------------------------------------------------------

    def _require_escrow(self, ref: PaymentRef) -> EscrowHandle:
        handle = self._escrows.get(ref)
        if handle is None:
            msg = f"escrow not found: {ref}"
            raise EscrowError(msg)
        return handle
