# SPDX-License-Identifier: Apache-2.0
"""Item 6 — secret leakage audit across receipts, views, exceptions, traces."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from nest_plugins_prava import PravaAuthError, PravaPayments
from nest_plugins_prava.client import MockPravaClient
from nest_plugins_prava.plugin import reset_ledger_sidecars
from nest_plugins_prava.secrets import assert_no_secrets, contains_secret, redact
from nest_sdk import AgentId, Money, PaymentRef

SECRET_PATTERNS = [
    re.compile(r"sk_(test|live)_[A-Za-z0-9]+"),
    re.compile(r"pk_(test|live)_[A-Za-z0-9]+"),
    re.compile(r"Bearer\s+\S+", re.I),
    re.compile(r"\b4[0-9]{12}(?:[0-9]{3})?\b"),  # test PAN shape
]


@pytest.fixture(autouse=True)
def _clean() -> None:  # pyright: ignore[reportUnusedFunction]
    reset_ledger_sidecars()


def _assert_clean(blob: str, label: str) -> None:
    for pat in SECRET_PATTERNS:
        m = pat.search(blob)
        assert m is None, f"Secret pattern {pat.pattern} found in {label}: {m.group(0)[:8]}..."


@pytest.mark.asyncio
async def test_no_secret_leak_in_receipt_record_exceptions() -> None:
    client = MockPravaClient()  # payment-result raw contains token+cvv internally
    pay = PravaPayments(AgentId("alice"), initial_balance=500, client=client)
    receipt = await pay.pay(AgentId("bob"), Money(amount=12), PaymentRef("sec-1"))
    record = pay.payment_record(PaymentRef("sec-1"))
    assert record is not None

    payload = {
        "receipt": receipt.model_dump(),
        "public_view": record.public_view(),
        "session_public": (
            {
                "session_id": record.session_id,
                "order_id": record.order_id,
            }
        ),
    }
    blob = json.dumps(payload)
    print(f"audit_blob_keys={list(payload.keys())} sample={blob[:200]}")
    _assert_clean(blob, "receipt/public_view")
    assert_no_secrets(record.public_view())
    assert "4111111111111111" not in blob
    assert "dynamic_cvv" not in blob or "***REDACTED***" in blob
    assert "tok_mock" not in blob


@pytest.mark.asyncio
async def test_auth_error_message_does_not_echo_api_key() -> None:
    # Simulate auth failure path through adapter.
    from nest_plugins_prava.client import MockPravaClient as M

    client = M(create_error=PravaAuthError("Invalid or missing API key", code="AUTH_1001"))
    pay = PravaPayments(AgentId("alice"), initial_balance=100, client=client)
    with pytest.raises(PravaAuthError) as ei:
        await pay.pay(AgentId("bob"), Money(amount=5), PaymentRef("sec-auth"))
    msg = str(ei.value)
    _assert_clean(msg, "auth exception")
    assert "sk_test_" not in msg
    print(f"auth_exception_clean={msg!r}")


def test_redact_repo_sensitive_shapes() -> None:
    dirty = {
        "authorization": "Bearer sk_test_abc123DEF",
        "api_key": "sk_live_zzz",
        "password": "hunter2",
        "token": "4111111111111111",
        "secret": "top",
        "ok": True,
    }
    cleaned = redact(dirty)
    blob = json.dumps(cleaned)
    _assert_clean(blob, "redacted-dict")
    assert contains_secret(cleaned) is False
    print(f"redacted={blob}")


@pytest.mark.asyncio
async def test_trace_file_from_pay_contains_no_secrets(tmp_path: Path) -> None:
    pay = PravaPayments(AgentId("alice"), initial_balance=100, client=MockPravaClient())
    receipt = await pay.pay(AgentId("bob"), Money(amount=7), PaymentRef("sec-trace"))
    record = pay.payment_record(PaymentRef("sec-trace"))
    assert record is not None
    trace_path = tmp_path / "trace.jsonl"
    line = json.dumps(
        {
            "event": "payment",
            "receipt": receipt.model_dump(),
            "record": record.public_view(),
        }
    )
    trace_path.write_text(line + "\n", encoding="utf-8")
    text = trace_path.read_text(encoding="utf-8")
    _assert_clean(text, "trace.jsonl")
    print(f"trace_bytes={len(text)} path={trace_path}")
