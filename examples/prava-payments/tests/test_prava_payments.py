# SPDX-License-Identifier: Apache-2.0
"""Tests for the Prava payments plugin: happy path, trust-gate failure, validator.

Run:  pip install -e . && pytest -v
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest
from nest_sdk import AgentId, Money, PaymentRef, PaymentStatus
from prava_payments.plugin import PravaPayments
from prava_payments.trust import TrustGate, TrustRefusedError
from prava_payments.validator import validate_trust_gate

BUYER = AgentId("buyer")
MERCHANT = AgentId("printsmith")


def run(coro: Any) -> Any:
    """Run a coroutine to completion for the synchronous tests."""
    return asyncio.run(coro)


def test_pay_settles_and_confirms() -> None:
    """A payment moves funds and reports CONFIRMED."""
    pay = PravaPayments(BUYER, initial_balance=1000)
    receipt = run(pay.pay(MERCHANT, Money(amount=399), PaymentRef("r1")))

    assert receipt.payer == BUYER
    assert receipt.payee == MERCHANT
    assert receipt.amount.amount == 399
    assert run(pay.verify_payment(PaymentRef("r1"))) == PaymentStatus.CONFIRMED
    assert pay.balance(BUYER) == 601
    assert pay.balance(MERCHANT) == 399


def test_refund_restores_balance_and_status() -> None:
    """A refund reverses the ledger and reports REFUNDED."""
    pay = PravaPayments(BUYER, initial_balance=1000)
    run(pay.pay(MERCHANT, Money(amount=399), PaymentRef("r1")))
    run(pay.refund(PaymentRef("r1")))

    assert run(pay.verify_payment(PaymentRef("r1"))) == PaymentStatus.REFUNDED
    assert pay.balance(BUYER) == 1000
    assert pay.balance(MERCHANT) == 0


def test_unverified_payee_is_refused() -> None:
    """The Senso trust gate refuses an unverified payee and moves no funds."""
    gate = TrustGate(verified={"printsmith"})
    pay = PravaPayments(BUYER, initial_balance=1000, trust=gate)

    with pytest.raises(TrustRefusedError):
        run(pay.pay(AgentId("scammer"), Money(amount=100), PaymentRef("r2")))

    assert pay.balance(BUYER) == 1000
    assert run(pay.verify_payment(PaymentRef("r2"))) == PaymentStatus.FAILED


def test_verified_payee_passes_gate() -> None:
    """A verified payee passes the gate and settles normally."""
    gate = TrustGate(verified={"printsmith"})
    pay = PravaPayments(BUYER, initial_balance=1000, trust=gate)
    receipt = run(pay.pay(MERCHANT, Money(amount=199), PaymentRef("r3")))
    assert receipt.amount.amount == 199


def test_duplicate_reference_rejected() -> None:
    """A reused payment reference is rejected."""
    pay = PravaPayments(BUYER, initial_balance=1000)
    run(pay.pay(MERCHANT, Money(amount=50), PaymentRef("r1")))
    with pytest.raises(ValueError, match="Duplicate"):
        run(pay.pay(MERCHANT, Money(amount=50), PaymentRef("r1")))


def test_insufficient_balance_rejected() -> None:
    """A payment beyond the payer's balance is rejected."""
    pay = PravaPayments(BUYER, initial_balance=100)
    with pytest.raises(ValueError, match="Insufficient"):
        run(pay.pay(MERCHANT, Money(amount=399), PaymentRef("r4")))


def test_validator_flags_unverified_settlement(tmp_path: Path) -> None:
    """The adversarial validator FAILS a trace that settled to an unverified payee."""
    trace = tmp_path / "bad.jsonl"
    events = [
        {"agent": "buyer", "kind": "payment_confirmed", "payee": "scammer", "status": "CONFIRMED"},
    ]
    trace.write_text("\n".join(json.dumps(e) for e in events), encoding="utf-8")

    results = {r.name: r for r in validate_trust_gate(trace, verified={"printsmith"})}
    assert results["no_unverified_settlement"].passed is False


def test_validator_passes_gated_trace(tmp_path: Path) -> None:
    """The adversarial validator PASSES a trace where the gate held."""
    trace = tmp_path / "good.jsonl"
    events = [
        {"agent": "buyer", "kind": "payment_confirmed", "payee": "printsmith", "status": "OK"},
        {"agent": "buyer", "kind": "trust_refused", "payee": "scammer", "reason": "unverified"},
    ]
    trace.write_text("\n".join(json.dumps(e) for e in events), encoding="utf-8")

    assert all(r.passed for r in validate_trust_gate(trace, verified={"printsmith"}))
