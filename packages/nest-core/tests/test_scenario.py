# packages/nest-core/tests/test_scenario.py
import pytest
from nest_core.types import AgentId, Money, PaymentRef, PaymentStatus, ServiceRef
from nest_plugins_reference.payments.empic_escrow import EMPICEscrowPayments
from nest_core.validators import validate_empic_pubsub_billing_caps

@pytest.mark.asyncio
async def test_pay_generic_releases_immediately():
    """Test that pay() with service_id=None releases funds immediately."""
    payer = AgentId("payer")
    payee = AgentId("payee")
    payments = EMPICEscrowPayments(payer, initial_balance=1000)
    
    ref = PaymentRef("generic-1")
    # Generic scenario: no service_id provided
    receipt = await payments.pay(payee, Money(amount=50), ref)
    
    assert receipt.amount.amount == 50
    assert payments.balance(payer) == 950
    assert payments.balance(payee) == 50
    
    # Verify payment should be CONFIRMED immediately, not PENDING
    status = await payments.verify_payment(ref)
    assert status is PaymentStatus.CONFIRMED

@pytest.mark.asyncio
async def test_pay_escrow_timeout():
    """Test that pay() with service_id provided times out and refunds."""
    payer = AgentId("payer")
    payee = AgentId("payee")
    payments = EMPICEscrowPayments(payer, initial_balance=1000)
    
    ref = PaymentRef("escrow-1")
    service = ServiceRef("weather")
    
    # EMPIC-specific scenario: service_id is provided
    await payments.pay(payee, Money(amount=50), ref, service_id=service)
    assert payments.balance(payer) == 950
    assert payments.balance(payee) == 0
    
    status = await payments.verify_payment(ref)
    assert status is PaymentStatus.PENDING
    
    # Simulate time passing beyond timeout_ticks (default 100)
    payments._current_tick = 150
    
    # Verify payment should now auto-refund
    status = await payments.verify_payment(ref)
    assert status is PaymentStatus.REFUNDED
    
    # Funds should be returned to the payer
    assert payments.balance(payer) == 1000
    assert payments.balance(payee) == 0

def test_validate_empic_pubsub_billing_caps_omits_mode():
    """Test that validator catches billing cap violations even if mode is omitted."""
    events = [
        {
            "kind": "send",
            "msg": '{"type": "empic_audit", "event_type": "empic_stream_opened", "payment_ref": "stream-1", "rate_per_tick": 10, "max_total": 100}',
            "tick": 0
        },
        {
            "kind": "send",
            # The 'mode' field is intentionally omitted here to simulate the attack
            "msg": '{"type": "empic_audit", "event_type": "empic_escrow_released", "payment_ref": "stream-1", "amount": 50, "delivery_id": "d1"}',
            "tick": 1
        }
    ]
    
    results = validate_empic_pubsub_billing_caps(events)
    assert len(results) == 1
    # The validator must now FAIL because 50 > rate 10, regardless of the missing mode
    assert results[0].passed is False
    assert "release 50 > rate 10" in results[0].detail