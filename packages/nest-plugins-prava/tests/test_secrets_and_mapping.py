# SPDX-License-Identifier: Apache-2.0
"""Secret scrubbing + currency mapping tests."""

from __future__ import annotations

import json

import pytest
from nest_plugins_prava import PravaPayments
from nest_plugins_prava.client import MockPravaClient
from nest_plugins_prava.mapping import (
    agent_to_email,
    agent_to_user_id,
    credits_to_decimal_amount,
    decimal_amount_to_credits,
)
from nest_plugins_prava.plugin import reset_ledger_sidecars
from nest_plugins_prava.secrets import assert_no_secrets, contains_secret, redact
from nest_sdk import AgentId, Money, PaymentRef


@pytest.fixture(autouse=True)
def _clean_sidecars() -> None:  # pyright: ignore[reportUnusedFunction]
    reset_ledger_sidecars()


def test_credits_mapping_roundtrip() -> None:
    assert credits_to_decimal_amount(50) == "0.50"
    assert credits_to_decimal_amount(100) == "1.00"
    assert decimal_amount_to_credits("0.50") == 50
    assert agent_to_user_id(AgentId("buyer-0")).startswith("nanda-")
    assert "@" in agent_to_email(AgentId("buyer-0"))


def test_redact_strips_tokens() -> None:
    raw = {
        "session_token": "eyJhbGciOi...",
        "token": "4111111111111111",
        "dynamic_cvv": "123",
        "status": "completed",
        "nested": {"Authorization": "Bearer sk_test_abc123xyz"},
    }
    cleaned = redact(raw)
    blob = json.dumps(cleaned)
    assert "4111111111111111" not in blob
    assert "sk_test_abc123xyz" not in blob
    assert cleaned["status"] == "completed"
    assert contains_secret(raw) is True
    assert contains_secret(cleaned) is False


@pytest.mark.asyncio
async def test_no_secrets_in_receipt_or_public_view() -> None:
    pay = PravaPayments(AgentId("alice"), initial_balance=1000, client=MockPravaClient())
    receipt = await pay.pay(AgentId("bob"), Money(amount=12), PaymentRef("sec-1"))
    record = pay.payment_record(PaymentRef("sec-1"))
    assert record is not None
    blob = json.dumps({"receipt": receipt.model_dump(), "view": record.public_view()})
    assert "sk_test" not in blob
    assert "4111111111111111" not in blob
    assert "tok_mock" not in blob
    assert_no_secrets(record.public_view(), label="view")
