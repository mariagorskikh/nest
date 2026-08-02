# SPDX-License-Identifier: Apache-2.0
"""Hostile extreme-edge proofs for the five scenarios reviewers demand."""

from __future__ import annotations

import asyncio
import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

import httpx
import pytest
from nest_plugins_prava import (
    InvalidPaymentStateError,
    PravaDeclinedError,
    PravaPayments,
    PravaTimeoutError,
)
from nest_plugins_prava.client import HttpPravaClient, MockPravaClient
from nest_plugins_prava.errors import PravaApiError
from nest_plugins_prava.plugin import reset_ledger_sidecars
from nest_sdk import AgentId, Money, PaymentRef, PaymentStatus


@pytest.fixture(autouse=True)
def _clean() -> None:  # pyright: ignore[reportUnusedFunction]
    reset_ledger_sidecars()


# ---------------------------------------------------------------------------
# 1) Two-phase: local debit then Prava failure → IMMEDIATE budget restore
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_1_timeout_after_local_debit_rolls_back_budget() -> None:
    """Lock/debit locally, create_session times out → balance restored."""
    client = MockPravaClient(timeout_on="create_session")
    pay = PravaPayments(AgentId("alice"), initial_balance=100, client=client)
    assert pay.balance(AgentId("alice")) == 100

    with pytest.raises(PravaTimeoutError):
        await pay.pay(AgentId("bob"), Money(amount=40), PaymentRef("2pc-timeout"))

    # IMMEDIATE rollback — not "eventually", not deferred.
    assert pay.balance(AgentId("alice")) == 100
    assert pay.balance(AgentId("bob")) == 0
    assert await pay.verify_payment(PaymentRef("2pc-timeout")) is PaymentStatus.FAILED
    print(
        f"2PC timeout rollback: alice={pay.balance(AgentId('alice'))} "
        f"status={await pay.verify_payment(PaymentRef('2pc-timeout'))}"
    )


@pytest.mark.asyncio
async def test_1_http_500_after_local_debit_rolls_back_budget() -> None:
    """Same 2PC property against HttpPravaClient returning 500."""
    hits = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        hits["n"] += 1
        return httpx.Response(
            500, json={"error": {"code": "SESSION_CREATE_ERROR", "message": "boom"}}
        )

    http = HttpPravaClient(
        api_key="sk_test_dummy",
        transport=httpx.MockTransport(handler),
        max_retries=1,
    )
    pay = PravaPayments(AgentId("alice"), initial_balance=100, client=http)

    with pytest.raises(PravaApiError):
        await pay.pay(AgentId("bob"), Money(amount=40), PaymentRef("2pc-500"))

    assert pay.balance(AgentId("alice")) == 100
    assert hits["n"] >= 2  # retried, still no settle
    assert await pay.verify_payment(PaymentRef("2pc-500")) is PaymentStatus.FAILED
    print(f"2PC http500 rollback: alice=100 hits={hits['n']}")


# ---------------------------------------------------------------------------
# 2) True multi-thread same PaymentRef (ThreadPoolExecutor)
# ---------------------------------------------------------------------------


def test_2_threadpool_10_workers_same_payment_ref_single_rail_call() -> None:
    """10 OS threads hit the SAME PaymentRef at once."""
    balances: dict[AgentId, int] = {AgentId("alice"): 1000}
    payments: dict[PaymentRef, object] = {}
    client = MockPravaClient(latency_s=0.02)
    pay = PravaPayments(
        AgentId("alice"),
        initial_balance=0,
        balances=balances,
        payments=payments,
        client=client,
    )
    ref = PaymentRef("thread-same-ref")

    def worker() -> str:
        receipt = asyncio.run(pay.pay(AgentId("bob"), Money(amount=50), ref))
        return f"{receipt.ref}:{receipt.amount.amount}:{receipt.payee}"

    results: list[str] = []
    errors: list[BaseException] = []
    with ThreadPoolExecutor(max_workers=10) as pool:
        futs = [pool.submit(worker) for _ in range(10)]
        for fut in as_completed(futs):
            try:
                results.append(fut.result())
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

    print(
        f"threadpool same-ref: results={len(results)} errors={len(errors)} "
        f"unique={set(results)} create_lane_calls={client.call_count} "
        f"alice={pay.balance(AgentId('alice'))} bob={pay.balance(AgentId('bob'))}"
    )
    assert errors == []
    assert len(results) == 10
    assert set(results) == {"thread-same-ref:50:bob"}
    # Exactly one rail transaction: create + poll + report
    assert client.call_count == 3
    assert pay.balance(AgentId("alice")) == 950
    assert pay.balance(AgentId("bob")) == 50


# ---------------------------------------------------------------------------
# 3) Refund edge cases (declined + double refund)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_3_refund_declined_payment_rejected() -> None:
    client = MockPravaClient(decline_report=True)
    pay = PravaPayments(AgentId("alice"), initial_balance=100, client=client)
    with pytest.raises(PravaDeclinedError):
        await pay.pay(AgentId("bob"), Money(amount=20), PaymentRef("declined-1"))
    assert await pay.verify_payment(PaymentRef("declined-1")) is PaymentStatus.FAILED

    calls_before = client.call_count
    with pytest.raises(InvalidPaymentStateError) as ei:
        await pay.refund(PaymentRef("declined-1"))
    # No additional Prava calls for a rejected refund
    assert client.call_count == calls_before
    assert ei.value.code == "INVALID_STATE"
    print(f"refund declined: {type(ei.value).__name__} prava_calls_delta=0")


@pytest.mark.asyncio
async def test_3_refund_twice_idempotent_no_second_prava_call() -> None:
    """Honest behavior: 2nd refund is a local no-op — NOT AlreadyRefundedError,
    and NOT a second Prava refund request (refund rail is local-only)."""
    client = MockPravaClient()
    pay = PravaPayments(AgentId("alice"), initial_balance=100, client=client)
    await pay.pay(AgentId("bob"), Money(amount=20), PaymentRef("rf-double"))
    await pay.refund(PaymentRef("rf-double"))
    calls_after_first_refund = client.call_count
    bal = pay.balance(AgentId("alice"))

    # Second refund: no exception, no balance change, no new client calls
    await pay.refund(PaymentRef("rf-double"))
    assert pay.balance(AgentId("alice")) == bal == 100
    assert client.call_count == calls_after_first_refund
    assert await pay.verify_payment(PaymentRef("rf-double")) is PaymentStatus.REFUNDED
    print(
        f"refund twice: IDEMPOTENT_NO_OP calls_unchanged={client.call_count} "
        f"(no AlreadyRefundedError by design; no Prava refund API exists here)"
    )


# ---------------------------------------------------------------------------
# 4) Hybrid headless — prove it is mock completion, not webhook magic
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_4_hybrid_headless_uses_mock_lane_not_live_payment_result() -> None:
    """Hybrid: live create_session once, then get_payment_result/report hit MOCK."""
    live_paths: list[str] = []
    mock = MockPravaClient()

    def handler(request: httpx.Request) -> httpx.Response:
        live_paths.append(f"{request.method}:{request.url.path}")
        if request.url.path.endswith("/sessions") and request.method == "POST":
            return httpx.Response(
                201,
                json={
                    "session_id": "ses_LIVE_REAL_001",
                    "order_id": "ord_LIVE_REAL_001",
                    "session_token": "tok_LIVE_SECRET",
                    "expires_at": "2099-01-01T00:00:00Z",
                },
            )
        # If hybrid wrongly polled live payment-result, this 500 would break pay.
        return httpx.Response(500, json={"error": {"code": "SHOULD_NOT_HIT", "message": "x"}})

    http = HttpPravaClient(api_key="sk_test_dummy", transport=httpx.MockTransport(handler))
    from nest_plugins_prava.client import HybridPravaClient

    hybrid = HybridPravaClient(http, mock)
    pay = PravaPayments(AgentId("alice"), initial_balance=100, client=hybrid)
    receipt = await pay.pay(AgentId("bob"), Money(amount=10), PaymentRef("hybrid-proof"))
    rec = pay.payment_record(PaymentRef("hybrid-proof"))
    assert rec is not None

    print(
        f"hybrid live_paths={live_paths} session_id={rec.session_id} "
        f"mock_calls={mock.call_count} status={rec.status.value}"
    )
    # Live HTTP only used for create (+ maybe revoke on failure). Not for poll/report.
    assert any(p.endswith("/sessions") and p.startswith("POST") for p in live_paths)
    assert not any("payment-result" in p for p in live_paths)
    assert not any("report-status" in p for p in live_paths)
    # Evidence id is the LIVE session id; completion came from mock lane.
    assert rec.session_id == "ses_LIVE_REAL_001"
    assert mock.call_count >= 2  # mock create + poll (+ report)
    assert await pay.verify_payment(PaymentRef("hybrid-proof")) is PaymentStatus.CONFIRMED
    assert receipt.amount.amount == 10


# ---------------------------------------------------------------------------
# 5) Deep Receipt JSON regex — no sk_ / pk_ anywhere
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_5_receipt_json_regex_forbids_sk_or_pk_prefixes() -> None:
    # Poison the mock raw payload with credential-shaped strings; Receipt must stay clean.
    client = MockPravaClient()
    pay = PravaPayments(
        AgentId("alice"),
        initial_balance=100,
        client=client,
        api_key="sk_test_SHOULD_NEVER_APPEAR_IN_RECEIPT",
    )
    receipt = await pay.pay(AgentId("bob"), Money(amount=7), PaymentRef("sec-deep"))
    record = pay.payment_record(PaymentRef("sec-deep"))
    assert record is not None

    # Serialize exactly as a NANDA DB row might.
    db_row = {
        "receipt": receipt.model_dump(),
        "record_public": record.public_view(),
        "nested": {"meta": {"rail": "prava", "refs": [str(receipt.ref)]}},
    }
    blob = json.dumps(db_row)
    print(f"receipt_json={blob}")

    assert re.search(r"sk_", blob) is None, blob
    assert re.search(r"pk_", blob) is None, blob
    assert re.search(r"(?i)session_token", blob) is None or "***REDACTED***" in blob
    assert "tok_mock" not in blob
    assert "4111111111111111" not in blob
