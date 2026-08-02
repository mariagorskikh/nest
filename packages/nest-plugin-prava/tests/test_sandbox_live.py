# SPDX-License-Identifier: Apache-2.0
"""Live Prava sandbox tests. These move REAL sandbox money.

Skipped unless a Quartermaster console is reachable (see conftest).

Budget: the happy path consumes ONE sandbox charge and requires an
envelope the owner has already approved by passkey with cycle capacity
remaining. The failure test consumes ZERO transactions: the arbiter and
the router both refuse before any Prava call is made.

Run with::

    QUARTERMASTER_CONSOLE_URL=http://localhost:3000 pytest tests/test_sandbox_live.py -v
"""

from __future__ import annotations

import json
import pathlib
import uuid

import httpx
import pytest
from nest_core.types import AgentId, PaymentRef, PaymentStatus, ServiceRef

from nest_plugin_prava import PravaPaymentError, PravaPayments

EVIDENCE_PATH = pathlib.Path(__file__).resolve().parent.parent / "sandbox-evidence.json"


def _record_evidence(name: str, payload: dict[str, object]) -> None:
    """Append a verifiable record of what the sandbox actually did."""
    existing: dict[str, object] = {}
    if EVIDENCE_PATH.exists():
        existing = json.loads(EVIDENCE_PATH.read_text())
    existing[name] = payload
    EVIDENCE_PATH.write_text(json.dumps(existing, indent=2, sort_keys=True) + "\n")


def _has_open_envelope(console_url: str) -> bool:
    data = httpx.get(f"{console_url}/api/portfolio", timeout=10.0).json()
    return any(env.get("cycle") == "OPEN" for env in data.get("envelopes", []))


async def test_failure_case_policy_refusal_costs_nothing(live_console: str) -> None:
    """An over-cap quote is refused by the arbiter with no Prava call.

    This is the failure-handling criterion: the plugin surfaces the
    arbiter's verdict, clause path and human-readable detail, and the
    ledger records no spend.
    """
    payments = PravaPayments(AgentId("agent_a"), console_url=live_console)
    try:
        quote = await payments.quote(ServiceRef("gpu-compute-xl"))
        ref = PaymentRef(f"nanda-fail-{uuid.uuid4().hex[:10]}")

        with pytest.raises(PravaPaymentError) as exc:
            await payments.pay(AgentId("agent_b"), quote.price, ref)

        assert exc.value.code in {"POLICY_NEEDS_HUMAN", "POLICY_REFUSE"}
        assert exc.value.details.get("failingClausePath")
        assert await payments.verify_payment(ref) is PaymentStatus.FAILED

        _record_evidence(
            "failure_case",
            {
                "service": "gpu-compute-xl",
                "quoted_cents": quote.price.amount,
                "payment_ref": str(ref),
                "error_code": exc.value.code,
                "error_message": exc.value.message,
                "failing_clause_path": exc.value.details.get("failingClausePath"),
                "mandate_id": exc.value.details.get("mandateId"),
                "prava_transactions_consumed": 0,
            },
        )
    finally:
        await payments.aclose()


async def test_happy_path_settles_in_sandbox(live_console: str) -> None:
    """A within-policy quote settles against a pre-approved envelope.

    Requires an envelope with cycle capacity: the owner approves it ONCE,
    by passkey, before the simulation. Never faked.
    """
    if not _has_open_envelope(live_console):
        pytest.skip(
            "no envelope with cycle capacity; approve one by passkey first "
            "(pnpm tsx scripts/create-envelope.ts A)"
        )

    payments = PravaPayments(AgentId("agent_a"), console_url=live_console)
    try:
        quote = await payments.quote(ServiceRef("gpu-compute-small"))
        assert quote.price.currency == "USD"
        assert quote.price.amount > 0

        ref = PaymentRef(f"nanda-ok-{uuid.uuid4().hex[:10]}")
        receipt = await payments.pay(AgentId("agent_b"), quote.price, ref)

        assert receipt.ref == ref
        assert receipt.payee == AgentId("agent_b")
        assert receipt.amount.amount == quote.price.amount

        status = await payments.verify_payment(ref)
        assert status is PaymentStatus.CONFIRMED

        detail = httpx.get(
            f"{live_console}/api/nanda/payment", params={"ref": str(ref)}, timeout=30.0
        ).json()
        assert detail["ledgerConfirmed"] is True
        assert detail["transactionId"]

        _record_evidence(
            "happy_path",
            {
                "service": "gpu-compute-small",
                "payment_ref": str(ref),
                "amount_cents": receipt.amount.amount,
                "currency": receipt.amount.currency,
                "prava_transaction_id": detail["transactionId"],
                "merchant_ref": detail["merchantRef"],
                "envelope_id": detail["envelopeId"],
                "run_id": quote.metadata["run_id"],
                "quote_id": quote.metadata["quote_id"],
                "pricing_rule": quote.metadata["pricing_rule"],
                "environment": "SANDBOX",
                "prava_transactions_consumed": 1,
            },
        )
    finally:
        await payments.aclose()


async def test_refund_documented_as_unsupported(live_console: str) -> None:
    """The refund path is documented, not silently swallowed."""
    payments = PravaPayments(AgentId("agent_a"), console_url=live_console)
    try:
        with pytest.raises(PravaPaymentError) as exc:
            await payments.refund(PaymentRef("does-not-matter"))
        assert exc.value.code == "REFUND_NOT_SUPPORTED"
    finally:
        await payments.aclose()
