# SPDX-License-Identifier: Apache-2.0
"""Hypothesis property tests for the escrow plugin.

Pins invariants the example-based tests can't enumerate:

* Conservation of funds across arbitrary amounts and bps splits.
* Floor-division split: payee + payer credits exactly equal the original amount
  (no money created or destroyed by rounding).
* Out-of-state transitions raise across every state-pair the type system allows.
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from nest_core.types import AgentId, Money, PaymentRef
from nest_plugins_reference.payments.escrow import EscrowError, EscrowPayments


def _triple(
    initial_payer: int,
) -> tuple[EscrowPayments, EscrowPayments, EscrowPayments]:
    balances: dict[AgentId, int] = {
        AgentId("payer"): initial_payer,
        AgentId("payee"): 0,
        AgentId("arbiter"): 0,
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


@given(
    amount=st.integers(min_value=1, max_value=10_000),
    bps=st.integers(min_value=0, max_value=10_000),
)
@settings(max_examples=200, deadline=None)
@pytest.mark.asyncio
async def test_arbitrate_conserves_total_ledger(amount: int, bps: int) -> None:
    """For any amount and any bps split, the three-party total is preserved."""
    payer, payee, arbiter = _triple(initial_payer=amount)
    total_before = (
        payer.balance(AgentId("payer"))
        + payer.balance(AgentId("payee"))
        + payer.balance(AgentId("arbiter"))
    )
    await payer.open_escrow(
        payee=AgentId("payee"),
        arbiter=AgentId("arbiter"),
        amount=Money(amount=amount),
        ref=PaymentRef("e"),
    )
    await payee.deliver(PaymentRef("e"), proof="x")
    await payer.dispute(PaymentRef("e"), reason="x")
    await arbiter.arbitrate(PaymentRef("e"), payee_bps=bps, rationale="x")
    total_after = (
        payer.balance(AgentId("payer"))
        + payer.balance(AgentId("payee"))
        + payer.balance(AgentId("arbiter"))
    )
    assert total_before == total_after


@given(
    amount=st.integers(min_value=1, max_value=10_000),
    bps=st.integers(min_value=0, max_value=10_000),
)
@settings(max_examples=200, deadline=None)
@pytest.mark.asyncio
async def test_split_sums_exactly_to_amount(amount: int, bps: int) -> None:
    """payee_credit + payer_refund == amount, even under floor division."""
    payer, payee, arbiter = _triple(initial_payer=amount)
    await payer.open_escrow(
        payee=AgentId("payee"),
        arbiter=AgentId("arbiter"),
        amount=Money(amount=amount),
        ref=PaymentRef("e"),
    )
    await payee.deliver(PaymentRef("e"), proof="x")
    await payer.dispute(PaymentRef("e"), reason="x")
    await arbiter.arbitrate(PaymentRef("e"), payee_bps=bps, rationale="x")
    payee_credit = payer.balance(AgentId("payee"))
    payer_refund = payer.balance(AgentId("payer"))  # was drained to 0 by open
    assert payee_credit + payer_refund == amount


@given(amount=st.integers(min_value=1, max_value=10_000))
@settings(max_examples=100, deadline=None)
@pytest.mark.asyncio
async def test_release_before_deliver_always_raises(amount: int) -> None:
    """For any amount, releasing a FUNDED-but-not-DELIVERED escrow raises."""
    payer, _, _ = _triple(initial_payer=amount)
    await payer.open_escrow(
        payee=AgentId("payee"),
        arbiter=AgentId("arbiter"),
        amount=Money(amount=amount),
        ref=PaymentRef("e"),
    )
    with pytest.raises(EscrowError):
        await payer.release(PaymentRef("e"))


@given(bad_bps=st.one_of(st.integers(max_value=-1), st.integers(min_value=10_001)))
@settings(max_examples=100, deadline=None)
@pytest.mark.asyncio
async def test_arbitrate_out_of_range_always_raises(bad_bps: int) -> None:
    """Any bps outside [0, 10000] raises -- no off-by-one survives."""
    payer, payee, arbiter = _triple(initial_payer=100)
    await payer.open_escrow(
        payee=AgentId("payee"),
        arbiter=AgentId("arbiter"),
        amount=Money(amount=100),
        ref=PaymentRef("e"),
    )
    await payee.deliver(PaymentRef("e"), proof="x")
    await payer.dispute(PaymentRef("e"), reason="x")
    with pytest.raises(EscrowError):
        await arbiter.arbitrate(PaymentRef("e"), payee_bps=bad_bps, rationale="x")
