# SPDX-License-Identifier: Apache-2.0
"""Tests for the escrow payments plugin.

Covers happy path, dispute path with arbitration, refund, role-bound authz,
state-machine guards, the ``Payments`` protocol shortcut, and conservation.
"""

from __future__ import annotations

import pytest
from nest_core.types import AgentId, Money, PaymentRef, PaymentStatus, ServiceRef
from nest_plugins_reference.payments.escrow import (
    EscrowError,
    EscrowPayments,
)


def _triple(
    initial_payer: int = 1000,
    initial_payee: int = 0,
    initial_arbiter: int = 0,
) -> tuple[EscrowPayments, EscrowPayments, EscrowPayments]:
    """Build payer/payee/arbiter plugin instances sharing one vault.

    The shared ``balances``/``payments``/``escrows`` dicts mirror the
    pattern used by ``prepaid_credits`` and ``streaming``: each agent
    has its own plugin instance, but they all see the same ledger.
    """
    balances: dict[AgentId, int] = {
        AgentId("payer"): initial_payer,
        AgentId("payee"): initial_payee,
        AgentId("arbiter"): initial_arbiter,
    }
    payments: dict[PaymentRef, object] = {}
    escrows: dict[PaymentRef, object] = {}
    payer = EscrowPayments(
        AgentId("payer"),
        balances=balances,
        payments=payments,  # type: ignore[arg-type]
        escrows=escrows,  # type: ignore[arg-type]
    )
    payee = EscrowPayments(
        AgentId("payee"),
        balances=balances,
        payments=payments,  # type: ignore[arg-type]
        escrows=escrows,  # type: ignore[arg-type]
    )
    arbiter = EscrowPayments(
        AgentId("arbiter"),
        balances=balances,
        payments=payments,  # type: ignore[arg-type]
        escrows=escrows,  # type: ignore[arg-type]
    )
    return payer, payee, arbiter


class TestInit:
    """Construction and balance bookkeeping."""

    def test_default_balance(self) -> None:
        p = EscrowPayments(AgentId("a1"), initial_balance=500)
        assert p.balance(AgentId("a1")) == 500
        assert p.balance(AgentId("a2")) == 0

    def test_shared_balances_override_initial(self) -> None:
        balances = {AgentId("a1"): 1234}
        p = EscrowPayments(AgentId("a1"), initial_balance=999, balances=balances)
        # initial_balance is only applied via setdefault; explicit pre-seed wins
        assert p.balance(AgentId("a1")) == 1234


class TestOpenEscrow:
    """``open_escrow`` -- payer-only, debits immediately."""

    @pytest.mark.asyncio
    async def test_open_escrow_debits_payer_and_funds_vault(self) -> None:
        payer, payee, _ = _triple()
        handle = await payer.open_escrow(
            payee=AgentId("payee"),
            arbiter=AgentId("arbiter"),
            amount=Money(amount=250),
            ref=PaymentRef("job-1"),
        )
        assert handle.state == "FUNDED"
        assert handle.amount == 250
        assert handle.payer == AgentId("payer")
        assert handle.payee == AgentId("payee")
        assert handle.arbiter == AgentId("arbiter")
        assert payer.balance(AgentId("payer")) == 750
        # Funds are held by the vault, NOT yet credited to the payee.
        assert payee.balance(AgentId("payee")) == 0

    @pytest.mark.asyncio
    async def test_open_escrow_zero_amount_raises(self) -> None:
        payer, _, _ = _triple()
        with pytest.raises(EscrowError, match="positive"):
            await payer.open_escrow(
                payee=AgentId("payee"),
                arbiter=AgentId("arbiter"),
                amount=Money(amount=0),
                ref=PaymentRef("job-1"),
            )

    @pytest.mark.asyncio
    async def test_open_escrow_duplicate_ref_raises(self) -> None:
        payer, _, _ = _triple()
        await payer.open_escrow(
            payee=AgentId("payee"),
            arbiter=AgentId("arbiter"),
            amount=Money(amount=100),
            ref=PaymentRef("job-1"),
        )
        with pytest.raises(EscrowError, match="already used"):
            await payer.open_escrow(
                payee=AgentId("payee"),
                arbiter=AgentId("arbiter"),
                amount=Money(amount=100),
                ref=PaymentRef("job-1"),
            )

    @pytest.mark.asyncio
    async def test_open_escrow_insufficient_balance_raises(self) -> None:
        payer, _, _ = _triple(initial_payer=100)
        with pytest.raises(EscrowError, match="insufficient balance"):
            await payer.open_escrow(
                payee=AgentId("payee"),
                arbiter=AgentId("arbiter"),
                amount=Money(amount=200),
                ref=PaymentRef("job-1"),
            )

    @pytest.mark.asyncio
    async def test_arbiter_must_be_distinct_from_payer(self) -> None:
        payer, _, _ = _triple()
        with pytest.raises(EscrowError, match="distinct"):
            await payer.open_escrow(
                payee=AgentId("payee"),
                arbiter=AgentId("payer"),  # invalid
                amount=Money(amount=100),
                ref=PaymentRef("job-1"),
            )

    @pytest.mark.asyncio
    async def test_arbiter_must_be_distinct_from_payee(self) -> None:
        payer, _, _ = _triple()
        with pytest.raises(EscrowError, match="distinct"):
            await payer.open_escrow(
                payee=AgentId("payee"),
                arbiter=AgentId("payee"),  # invalid
                amount=Money(amount=100),
                ref=PaymentRef("job-1"),
            )


class TestDeliver:
    """``deliver`` -- payee-only, only valid from FUNDED."""

    @pytest.mark.asyncio
    async def test_deliver_happy(self) -> None:
        payer, payee, _ = _triple()
        await payer.open_escrow(
            payee=AgentId("payee"),
            arbiter=AgentId("arbiter"),
            amount=Money(amount=250),
            ref=PaymentRef("job-1"),
        )
        handle = await payee.deliver(PaymentRef("job-1"), proof="sha256:cafe")
        assert handle.state == "DELIVERED"
        assert handle.proof == "sha256:cafe"

    @pytest.mark.asyncio
    async def test_deliver_by_non_payee_raises(self) -> None:
        payer, _, arbiter = _triple()
        await payer.open_escrow(
            payee=AgentId("payee"),
            arbiter=AgentId("arbiter"),
            amount=Money(amount=100),
            ref=PaymentRef("job-1"),
        )
        with pytest.raises(EscrowError, match="only payee"):
            await arbiter.deliver(PaymentRef("job-1"), proof="x")
        with pytest.raises(EscrowError, match="only payee"):
            await payer.deliver(PaymentRef("job-1"), proof="x")

    @pytest.mark.asyncio
    async def test_deliver_missing_escrow_raises(self) -> None:
        _, payee, _ = _triple()
        with pytest.raises(EscrowError, match="not found"):
            await payee.deliver(PaymentRef("nope"), proof="x")

    @pytest.mark.asyncio
    async def test_deliver_twice_raises(self) -> None:
        payer, payee, _ = _triple()
        await payer.open_escrow(
            payee=AgentId("payee"),
            arbiter=AgentId("arbiter"),
            amount=Money(amount=100),
            ref=PaymentRef("job-1"),
        )
        await payee.deliver(PaymentRef("job-1"), proof="x")
        with pytest.raises(EscrowError, match="DELIVERED"):
            await payee.deliver(PaymentRef("job-1"), proof="y")


class TestRelease:
    """``release`` -- payer-only, only valid from DELIVERED."""

    @pytest.mark.asyncio
    async def test_release_happy_credits_payee(self) -> None:
        payer, payee, _ = _triple()
        await payer.open_escrow(
            payee=AgentId("payee"),
            arbiter=AgentId("arbiter"),
            amount=Money(amount=250),
            ref=PaymentRef("job-1"),
        )
        await payee.deliver(PaymentRef("job-1"), proof="x")
        receipt = await payer.release(PaymentRef("job-1"))
        assert receipt.amount.amount == 250
        assert receipt.payee == AgentId("payee")
        assert payer.balance(AgentId("payee")) == 250
        assert payer.balance(AgentId("payer")) == 750
        h = payer.escrow(PaymentRef("job-1"))
        assert h is not None
        assert h.state == "RELEASED"

    @pytest.mark.asyncio
    async def test_release_by_non_payer_raises(self) -> None:
        payer, payee, arbiter = _triple()
        await payer.open_escrow(
            payee=AgentId("payee"),
            arbiter=AgentId("arbiter"),
            amount=Money(amount=100),
            ref=PaymentRef("job-1"),
        )
        await payee.deliver(PaymentRef("job-1"), proof="x")
        with pytest.raises(EscrowError, match="only payer"):
            await payee.release(PaymentRef("job-1"))
        with pytest.raises(EscrowError, match="only payer"):
            await arbiter.release(PaymentRef("job-1"))

    @pytest.mark.asyncio
    async def test_release_before_delivery_raises(self) -> None:
        payer, _, _ = _triple()
        await payer.open_escrow(
            payee=AgentId("payee"),
            arbiter=AgentId("arbiter"),
            amount=Money(amount=100),
            ref=PaymentRef("job-1"),
        )
        with pytest.raises(EscrowError, match="FUNDED"):
            await payer.release(PaymentRef("job-1"))


class TestDisputeAndArbitrate:
    """``dispute`` and ``arbitrate`` -- bps splits, role-bound, range-checked."""

    @pytest.mark.asyncio
    async def test_dispute_then_arbitrate_partial(self) -> None:
        payer, payee, arbiter = _triple()
        await payer.open_escrow(
            payee=AgentId("payee"),
            arbiter=AgentId("arbiter"),
            amount=Money(amount=1000),
            ref=PaymentRef("job-1"),
        )
        await payee.deliver(PaymentRef("job-1"), proof="partial")
        await payer.dispute(PaymentRef("job-1"), reason="incomplete")
        receipt = await arbiter.arbitrate(
            PaymentRef("job-1"),
            payee_bps=3000,
            rationale="approx 30% usable",
        )
        # 30% to payee, 70% back to payer
        assert receipt.amount.amount == 300
        assert payer.balance(AgentId("payee")) == 300
        assert payer.balance(AgentId("payer")) == 700  # 1000 - 1000 + 700

    @pytest.mark.asyncio
    async def test_arbitrate_zero_pays_back_payer(self) -> None:
        payer, payee, arbiter = _triple()
        await payer.open_escrow(
            payee=AgentId("payee"),
            arbiter=AgentId("arbiter"),
            amount=Money(amount=500),
            ref=PaymentRef("job-1"),
        )
        await payee.deliver(PaymentRef("job-1"), proof="garbage")
        await payer.dispute(PaymentRef("job-1"), reason="all wrong")
        await arbiter.arbitrate(PaymentRef("job-1"), payee_bps=0, rationale="zero credit")
        assert payer.balance(AgentId("payee")) == 0
        assert payer.balance(AgentId("payer")) == 1000  # fully refunded

    @pytest.mark.asyncio
    async def test_arbitrate_full_pays_payee(self) -> None:
        payer, payee, arbiter = _triple()
        await payer.open_escrow(
            payee=AgentId("payee"),
            arbiter=AgentId("arbiter"),
            amount=Money(amount=500),
            ref=PaymentRef("job-1"),
        )
        await payee.deliver(PaymentRef("job-1"), proof="ok")
        await payer.dispute(PaymentRef("job-1"), reason="actually fine")
        await arbiter.arbitrate(PaymentRef("job-1"), payee_bps=10000, rationale="full credit")
        assert payer.balance(AgentId("payee")) == 500
        assert payer.balance(AgentId("payer")) == 500

    @pytest.mark.asyncio
    async def test_dispute_by_non_payer_raises(self) -> None:
        payer, payee, arbiter = _triple()
        await payer.open_escrow(
            payee=AgentId("payee"),
            arbiter=AgentId("arbiter"),
            amount=Money(amount=100),
            ref=PaymentRef("job-1"),
        )
        await payee.deliver(PaymentRef("job-1"), proof="x")
        with pytest.raises(EscrowError, match="only payer"):
            await payee.dispute(PaymentRef("job-1"), reason="x")
        with pytest.raises(EscrowError, match="only payer"):
            await arbiter.dispute(PaymentRef("job-1"), reason="x")

    @pytest.mark.asyncio
    async def test_arbitrate_by_non_arbiter_raises(self) -> None:
        payer, payee, _ = _triple()
        await payer.open_escrow(
            payee=AgentId("payee"),
            arbiter=AgentId("arbiter"),
            amount=Money(amount=100),
            ref=PaymentRef("job-1"),
        )
        await payee.deliver(PaymentRef("job-1"), proof="x")
        await payer.dispute(PaymentRef("job-1"), reason="x")
        with pytest.raises(EscrowError, match="only arbiter"):
            await payer.arbitrate(PaymentRef("job-1"), payee_bps=5000, rationale="x")
        with pytest.raises(EscrowError, match="only arbiter"):
            await payee.arbitrate(PaymentRef("job-1"), payee_bps=5000, rationale="x")

    @pytest.mark.asyncio
    async def test_arbitrate_without_dispute_raises(self) -> None:
        payer, payee, arbiter = _triple()
        await payer.open_escrow(
            payee=AgentId("payee"),
            arbiter=AgentId("arbiter"),
            amount=Money(amount=100),
            ref=PaymentRef("job-1"),
        )
        await payee.deliver(PaymentRef("job-1"), proof="x")
        with pytest.raises(EscrowError, match="DELIVERED"):
            await arbiter.arbitrate(PaymentRef("job-1"), payee_bps=5000, rationale="x")

    @pytest.mark.parametrize("bad_bps", [-1, 10001, 999999])
    @pytest.mark.asyncio
    async def test_arbitrate_out_of_range_bps_raises(self, bad_bps: int) -> None:
        payer, payee, arbiter = _triple()
        await payer.open_escrow(
            payee=AgentId("payee"),
            arbiter=AgentId("arbiter"),
            amount=Money(amount=100),
            ref=PaymentRef("job-1"),
        )
        await payee.deliver(PaymentRef("job-1"), proof="x")
        await payer.dispute(PaymentRef("job-1"), reason="x")
        with pytest.raises(EscrowError, match=r"\[0, 10000\]"):
            await arbiter.arbitrate(PaymentRef("job-1"), payee_bps=bad_bps, rationale="x")

    @pytest.mark.asyncio
    async def test_release_blocked_after_dispute(self) -> None:
        payer, payee, _ = _triple()
        await payer.open_escrow(
            payee=AgentId("payee"),
            arbiter=AgentId("arbiter"),
            amount=Money(amount=100),
            ref=PaymentRef("job-1"),
        )
        await payee.deliver(PaymentRef("job-1"), proof="x")
        await payer.dispute(PaymentRef("job-1"), reason="x")
        with pytest.raises(EscrowError, match="DISPUTED"):
            await payer.release(PaymentRef("job-1"))


class TestRefund:
    """``refund`` is payer-only and only allowed while still ``FUNDED``."""

    @pytest.mark.asyncio
    async def test_refund_credits_payer_back(self) -> None:
        payer, _, _ = _triple()
        await payer.open_escrow(
            payee=AgentId("payee"),
            arbiter=AgentId("arbiter"),
            amount=Money(amount=250),
            ref=PaymentRef("job-1"),
        )
        assert payer.balance(AgentId("payer")) == 750
        await payer.refund(PaymentRef("job-1"))
        assert payer.balance(AgentId("payer")) == 1000
        h = payer.escrow(PaymentRef("job-1"))
        assert h is not None and h.state == "REFUNDED"

    @pytest.mark.asyncio
    async def test_refund_after_delivery_raises(self) -> None:
        payer, payee, _ = _triple()
        await payer.open_escrow(
            payee=AgentId("payee"),
            arbiter=AgentId("arbiter"),
            amount=Money(amount=100),
            ref=PaymentRef("job-1"),
        )
        await payee.deliver(PaymentRef("job-1"), proof="x")
        with pytest.raises(EscrowError, match="DELIVERED"):
            await payer.refund(PaymentRef("job-1"))

    @pytest.mark.asyncio
    async def test_refund_by_non_payer_raises(self) -> None:
        payer, payee, _ = _triple()
        await payer.open_escrow(
            payee=AgentId("payee"),
            arbiter=AgentId("arbiter"),
            amount=Money(amount=100),
            ref=PaymentRef("job-1"),
        )
        with pytest.raises(EscrowError, match="only payer"):
            await payee.refund(PaymentRef("job-1"))


class TestPaymentsProtocol:
    """``pay``/``verify_payment``/``quote`` so existing Payments callers work."""

    @pytest.mark.asyncio
    async def test_pay_shortcut_credits_immediately(self) -> None:
        payer, payee, _ = _triple()
        receipt = await payer.pay(AgentId("payee"), Money(amount=50), PaymentRef("p1"))
        assert receipt.amount.amount == 50
        assert payer.balance(AgentId("payer")) == 950
        assert payee.balance(AgentId("payee")) == 50

    @pytest.mark.asyncio
    async def test_pay_duplicate_ref_raises(self) -> None:
        payer, _, _ = _triple()
        await payer.pay(AgentId("payee"), Money(amount=10), PaymentRef("p1"))
        with pytest.raises(EscrowError, match="already used"):
            await payer.pay(AgentId("payee"), Money(amount=10), PaymentRef("p1"))

    @pytest.mark.asyncio
    async def test_pay_collides_with_escrow_ref(self) -> None:
        payer, _, _ = _triple()
        await payer.open_escrow(
            payee=AgentId("payee"),
            arbiter=AgentId("arbiter"),
            amount=Money(amount=10),
            ref=PaymentRef("p1"),
        )
        with pytest.raises(EscrowError, match="already used"):
            await payer.pay(AgentId("payee"), Money(amount=5), PaymentRef("p1"))

    @pytest.mark.asyncio
    async def test_verify_payment_states(self) -> None:
        payer, payee, arbiter = _triple()
        # 1. Unknown ref -> FAILED
        assert await payer.verify_payment(PaymentRef("nope")) == PaymentStatus.FAILED

        # 2. Funded but not delivered -> PENDING
        await payer.open_escrow(
            payee=AgentId("payee"),
            arbiter=AgentId("arbiter"),
            amount=Money(amount=100),
            ref=PaymentRef("e1"),
        )
        assert await payer.verify_payment(PaymentRef("e1")) == PaymentStatus.PENDING

        # 3. Released -> CONFIRMED
        await payee.deliver(PaymentRef("e1"), proof="x")
        await payer.release(PaymentRef("e1"))
        assert await payer.verify_payment(PaymentRef("e1")) == PaymentStatus.CONFIRMED

        # 4. Refunded -> FAILED
        await payer.open_escrow(
            payee=AgentId("payee"),
            arbiter=AgentId("arbiter"),
            amount=Money(amount=50),
            ref=PaymentRef("e2"),
        )
        await payer.refund(PaymentRef("e2"))
        assert await payer.verify_payment(PaymentRef("e2")) == PaymentStatus.FAILED

        # 5. Arbitrated -> CONFIRMED
        await payer.open_escrow(
            payee=AgentId("payee"),
            arbiter=AgentId("arbiter"),
            amount=Money(amount=200),
            ref=PaymentRef("e3"),
        )
        await payee.deliver(PaymentRef("e3"), proof="x")
        await payer.dispute(PaymentRef("e3"), reason="x")
        await arbiter.arbitrate(PaymentRef("e3"), payee_bps=4000, rationale="x")
        assert await payer.verify_payment(PaymentRef("e3")) == PaymentStatus.CONFIRMED

        # 6. Pure pay() (no escrow row) -> CONFIRMED
        await payer.pay(AgentId("payee"), Money(amount=10), PaymentRef("e4"))
        assert await payer.verify_payment(PaymentRef("e4")) == PaymentStatus.CONFIRMED

    @pytest.mark.asyncio
    async def test_quote(self) -> None:
        payer, _, _ = _triple()
        q = await payer.quote(ServiceRef("svc"))
        assert q.service == ServiceRef("svc")
        assert q.price.amount == 10

    @pytest.mark.asyncio
    async def test_refund_protocol_call_on_unknown_raises(self) -> None:
        payer, _, _ = _triple()
        with pytest.raises(EscrowError, match="not found"):
            await payer.refund(PaymentRef("nope"))


class TestConservation:
    """Funds are conserved across every terminal state."""

    @pytest.mark.asyncio
    async def test_conservation_release(self) -> None:
        payer, payee, _ = _triple()
        total_before = (
            payer.balance(AgentId("payer"))
            + payer.balance(AgentId("payee"))
            + payer.balance(AgentId("arbiter"))
        )
        await payer.open_escrow(
            payee=AgentId("payee"),
            arbiter=AgentId("arbiter"),
            amount=Money(amount=400),
            ref=PaymentRef("e1"),
        )
        await payee.deliver(PaymentRef("e1"), proof="x")
        await payer.release(PaymentRef("e1"))
        total_after = (
            payer.balance(AgentId("payer"))
            + payer.balance(AgentId("payee"))
            + payer.balance(AgentId("arbiter"))
        )
        assert total_before == total_after

    @pytest.mark.parametrize("bps", [0, 1, 1234, 5000, 9999, 10000])
    @pytest.mark.asyncio
    async def test_conservation_arbitrate(self, bps: int) -> None:
        payer, payee, arbiter = _triple()
        total_before = (
            payer.balance(AgentId("payer"))
            + payer.balance(AgentId("payee"))
            + payer.balance(AgentId("arbiter"))
        )
        await payer.open_escrow(
            payee=AgentId("payee"),
            arbiter=AgentId("arbiter"),
            amount=Money(amount=777),
            ref=PaymentRef("e1"),
        )
        await payee.deliver(PaymentRef("e1"), proof="x")
        await payer.dispute(PaymentRef("e1"), reason="x")
        await arbiter.arbitrate(PaymentRef("e1"), payee_bps=bps, rationale="x")
        total_after = (
            payer.balance(AgentId("payer"))
            + payer.balance(AgentId("payee"))
            + payer.balance(AgentId("arbiter"))
        )
        assert total_before == total_after

    @pytest.mark.asyncio
    async def test_conservation_refund(self) -> None:
        payer, _, _ = _triple()
        total_before = payer.balance(AgentId("payer"))
        await payer.open_escrow(
            payee=AgentId("payee"),
            arbiter=AgentId("arbiter"),
            amount=Money(amount=600),
            ref=PaymentRef("e1"),
        )
        await payer.refund(PaymentRef("e1"))
        assert payer.balance(AgentId("payer")) == total_before
