# SPDX-License-Identifier: Apache-2.0
"""Tests for EMPIC-style escrow payments."""

from __future__ import annotations

import pytest
from nest_core.types import AgentId, Money, PaymentRef, PaymentStatus, ServiceRef
from nest_plugins_reference.payments.empic_escrow import (
    ESCROW_AGENT,
    EMPICEscrowPayments,
    PubsubTerms,
)


@pytest.fixture
def payments() -> EMPICEscrowPayments:
    """Create a consumer payment handle with deterministic balance."""
    return EMPICEscrowPayments(AgentId("consumer"), initial_balance=1000)


@pytest.mark.asyncio
async def test_generic_pay_confirms_immediately(payments: EMPICEscrowPayments) -> None:
    """Plain Payments.pay follows the generic immediate-settlement contract."""
    receipt = await payments.pay(AgentId("provider"), Money(amount=50), PaymentRef("generic-1"))

    assert receipt.amount.amount == 50
    assert payments.balance(AgentId("consumer")) == 950
    assert payments.balance(ESCROW_AGENT) == 0
    assert payments.balance(AgentId("provider")) == 50
    assert await payments.verify_payment(PaymentRef("generic-1")) is PaymentStatus.CONFIRMED


@pytest.mark.asyncio
async def test_pull_escrow_fulfills_after_accepted_delivery(
    payments: EMPICEscrowPayments,
) -> None:
    """Pull escrow releases funds only after accepted delivery evidence."""
    await payments.open_pull_escrow(
        AgentId("provider"),
        Money(amount=50),
        PaymentRef("pull-1"),
        service_id=ServiceRef("weather"),
    )

    assert payments.balance(AgentId("consumer")) == 950
    assert payments.balance(ESCROW_AGENT) == 50
    assert payments.balance(AgentId("provider")) == 0
    assert await payments.verify_payment(PaymentRef("pull-1")) is PaymentStatus.PENDING

    delivery = payments.record_delivery(
        PaymentRef("pull-1"),
        delivery_id="d1",
        service_id=ServiceRef("weather"),
        provider=AgentId("provider"),
        mode="pull",
        tick=1,
        accepted=True,
        data={"temperature_c": 20.0},
    )
    receipt = await payments.fulfill(PaymentRef("pull-1"), delivery)

    assert receipt.amount.amount == 50
    assert payments.balance(ESCROW_AGENT) == 0
    assert payments.balance(AgentId("provider")) == 50
    assert await payments.verify_payment(PaymentRef("pull-1")) is PaymentStatus.CONFIRMED


@pytest.mark.asyncio
async def test_pull_escrow_reject_refunds_consumer(payments: EMPICEscrowPayments) -> None:
    """Rejected pull delivery returns escrow to the consumer."""
    await payments.open_pull_escrow(
        AgentId("provider"),
        Money(amount=50),
        PaymentRef("pull-1"),
        service_id=ServiceRef("weather"),
    )
    payments.record_delivery(
        PaymentRef("pull-1"),
        delivery_id="d1",
        service_id=ServiceRef("weather"),
        provider=AgentId("provider"),
        mode="pull",
        tick=1,
        accepted=False,
        reason="missing field",
    )

    await payments.reject(PaymentRef("pull-1"), reason="missing field", data_ref="d1")

    assert payments.balance(AgentId("consumer")) == 1000
    assert payments.balance(AgentId("provider")) == 0
    assert payments.balance(ESCROW_AGENT) == 0
    assert await payments.verify_payment(PaymentRef("pull-1")) is PaymentStatus.REFUNDED


@pytest.mark.asyncio
async def test_pull_fulfill_rejects_mismatched_delivery(
    payments: EMPICEscrowPayments,
) -> None:
    """Accepted evidence must match the escrow payee and service."""
    await payments.open_pull_escrow(
        AgentId("provider"),
        Money(amount=50),
        PaymentRef("pull-1"),
        service_id=ServiceRef("weather"),
    )
    delivery = payments.record_delivery(
        PaymentRef("pull-1"),
        delivery_id="d1",
        service_id=ServiceRef("weather"),
        provider=AgentId("attacker"),
        mode="pull",
        tick=1,
        accepted=True,
    )

    with pytest.raises(ValueError, match="no acceptable delivery evidence"):
        await payments.fulfill(PaymentRef("pull-1"), delivery)

    assert payments.balance(ESCROW_AGENT) == 50
    assert payments.balance(AgentId("provider")) == 0


@pytest.mark.asyncio
async def test_pubsub_stream_bills_only_accepted_deliveries(
    payments: EMPICEscrowPayments,
) -> None:
    """Pubsub stream releases one tick for each accepted delivery."""
    await payments.open_stream(
        AgentId("provider"),
        rate_per_tick=10,
        max_total=40,
        ref=PaymentRef("stream-1"),
        service_id=ServiceRef("weather"),
    )
    assert payments.balance(AgentId("consumer")) == 960
    assert payments.balance(ESCROW_AGENT) == 40

    payments.record_delivery(
        PaymentRef("stream-1"),
        delivery_id="d1",
        service_id=ServiceRef("weather"),
        provider=AgentId("provider"),
        mode="pubsub",
        tick=1,
        accepted=True,
    )
    payments.record_delivery(
        PaymentRef("stream-1"),
        delivery_id="d2",
        service_id=ServiceRef("weather"),
        provider=AgentId("provider"),
        mode="pubsub",
        tick=2,
        accepted=False,
    )

    assert await payments.tick_stream(PaymentRef("stream-1"), 1)
    assert await payments.tick_stream(PaymentRef("stream-1"), 2)

    assert payments.balance(AgentId("provider")) == 10
    assert payments.balance(ESCROW_AGENT) == 30
    record = payments.payment_record(PaymentRef("stream-1"))
    assert record is not None
    assert record.released == 10


@pytest.mark.asyncio
async def test_pubsub_stream_does_not_bill_wrong_service(
    payments: EMPICEscrowPayments,
) -> None:
    """Accepted pubsub deliveries must match the stream service binding."""
    await payments.open_stream(
        AgentId("provider"),
        rate_per_tick=10,
        max_total=40,
        ref=PaymentRef("stream-1"),
        service_id=ServiceRef("weather"),
    )
    payments.record_delivery(
        PaymentRef("stream-1"),
        delivery_id="d1",
        service_id=ServiceRef("other-weather"),
        provider=AgentId("provider"),
        mode="pubsub",
        tick=1,
        accepted=True,
    )

    assert await payments.tick_stream(PaymentRef("stream-1"), 1)
    assert payments.balance(AgentId("provider")) == 0
    assert payments.balance(ESCROW_AGENT) == 40


@pytest.mark.asyncio
async def test_close_stream_refunds_unused_escrow(payments: EMPICEscrowPayments) -> None:
    """Closing a stream refunds all unspent escrow."""
    await payments.open_stream(
        AgentId("provider"),
        rate_per_tick=10,
        max_total=40,
        ref=PaymentRef("stream-1"),
    )
    payments.record_delivery(
        PaymentRef("stream-1"),
        delivery_id="d1",
        service_id=ServiceRef("weather"),
        provider=AgentId("provider"),
        mode="pubsub",
        tick=1,
        accepted=True,
    )
    await payments.tick_stream(PaymentRef("stream-1"), 1)
    receipt = await payments.close_stream(PaymentRef("stream-1"), current_tick=4)

    assert receipt.amount.amount == 10
    assert payments.balance(AgentId("consumer")) == 990
    assert payments.balance(AgentId("provider")) == 10
    assert payments.balance(ESCROW_AGENT) == 0
    assert await payments.verify_payment(PaymentRef("stream-1")) is PaymentStatus.CONFIRMED


@pytest.mark.asyncio
async def test_duplicate_refs_and_insufficient_balance(payments: EMPICEscrowPayments) -> None:
    """Duplicate references and over-budget escrow are rejected."""
    await payments.open_pull_escrow(AgentId("provider"), Money(amount=50), PaymentRef("pull-1"))

    with pytest.raises(ValueError, match="Duplicate"):
        await payments.open_stream(
            AgentId("provider"),
            rate_per_tick=10,
            max_total=20,
            ref=PaymentRef("pull-1"),
        )

    with pytest.raises(ValueError, match="Insufficient balance"):
        await payments.open_stream(
            AgentId("provider"),
            rate_per_tick=10,
            max_total=5000,
            ref=PaymentRef("stream-1"),
        )


def test_register_service_requires_pubsub_terms(payments: EMPICEscrowPayments) -> None:
    """Pubsub service metadata must carry pubsub terms."""
    with pytest.raises(ValueError, match="pubsub_terms"):
        payments.register_service(
            service_id=ServiceRef("weather"),
            provider=AgentId("provider"),
            price=Money(amount=10),
            delivery_modes=("pubsub",),
        )

    record = payments.register_service(
        service_id=ServiceRef("weather"),
        provider=AgentId("provider"),
        price=Money(amount=10),
        delivery_modes=("pull", "pubsub"),
        pubsub_terms=PubsubTerms(rate_per_tick=2, max_total=10, duration_ticks=5),
    )
    assert record.provider_did == "did:empic:sandbox:provider"
