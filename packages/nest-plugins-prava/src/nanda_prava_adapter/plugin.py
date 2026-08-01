# SPDX-License-Identifier: Apache-2.0
"""NANDA Town payments plugin backed by Prava's Session REST API.

The adapter treats NANDA ``Money.amount`` values as minor currency units. It
keeps Prava's virtual card and CVV in one stack-local dictionary only long
enough to pass them to an injected merchant executor. It never logs, returns,
or stores those fields.

Example::

    payments = PravaPayments(AgentId("buyer-0"))
    quote = await payments.quote(ServiceRef("restock-demo"))
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from dataclasses import dataclass
from decimal import Decimal
from typing import TYPE_CHECKING, Protocol, cast
from urllib.error import HTTPError, URLError
from urllib.parse import quote as url_quote
from urllib.request import Request, urlopen

from nest_core.types import (
    AgentId,
    Money,
    PaymentRef,
    PaymentStatus,
    Quote,
    Receipt,
    ServiceRef,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

_SANDBOX_URL = "https://sandbox.api.prava.space"
_PRODUCTION_URL = "https://api.prava.space"
_SENSITIVE_FIELDS = ("token", "dynamic_cvv", "expiry_month", "expiry_year")


@dataclass(frozen=True)
class PayeeProfile:
    """Merchant and customer context required to create a Prava session.

    Example::

        profile = PayeeProfile(
            merchant_name="NANDA Seller",
            merchant_url="https://nandatown.projectnanda.org",
            merchant_country="US",
            user_id="buyer-0",
            user_email="buyer@example.com",
        )
    """

    merchant_name: str
    merchant_url: str
    merchant_country: str
    user_id: str
    user_email: str
    product_description: str = "NANDA Town agent service"


@dataclass(frozen=True)
class PravaSession:
    """Non-secret Prava session handoff data.

    Example::

        session = PravaSession("ses_1", "https://pay.prava.space/s/ses_1")
    """

    session_id: str
    approval_url: str


@dataclass(frozen=True)
class MerchantOutcome:
    """Terminal result returned by the merchant execution boundary.

    Example::

        outcome = MerchantOutcome(approved=True, authorization_code="demo")
    """

    approved: bool
    authorization_code: str | None = None
    response_code: str | None = None


class PravaTransport(Protocol):
    """Minimal Prava API transport used by the adapter.

    Example::

        transport: PravaTransport = PravaHTTPTransport()
    """

    def create_session(
        self, *, profile: PayeeProfile, amount: Money, payment_ref: PaymentRef
    ) -> PravaSession:
        """Create a short-lived Prava checkout session.

        Example::

            session = transport.create_session(profile=profile, amount=money, payment_ref=ref)
        """
        ...

    def payment_result(self, session_id: str) -> dict[str, object]:
        """Read the current Prava session result.

        Example::

            result = transport.payment_result("ses_1")
        """
        ...

    def report_status(
        self,
        *,
        session_id: str,
        transaction_ref: str,
        approved: bool,
        outcome: MerchantOutcome,
    ) -> None:
        """Report the merchant outcome to Prava.

        Example::

            transport.report_status(
                session_id="ses_1", transaction_ref="txn_1",
                approved=True, outcome=MerchantOutcome(True),
            )
        """
        ...

    def revoke_session(self, session_id: str) -> None:
        """Revoke an incomplete Prava session.

        Example::

            transport.revoke_session("ses_1")
        """
        ...


class MerchantExecutor(Protocol):
    """Consumes one-time Prava card material at a merchant boundary.

    Example::

        outcome = await executor.execute(credentials, amount, ref)
    """

    async def execute(
        self,
        credentials: dict[str, str],
        amount: Money,
        payment_ref: PaymentRef,
    ) -> MerchantOutcome:
        """Execute exactly one merchant checkout.

        Example::

            result = await executor.execute(credentials, Money(amount=100), PaymentRef("p1"))
        """
        ...


class RefundHandler(Protocol):
    """Merchant-owned refund boundary.

    Prava documents that refunds happen through the merchant and does not
    expose a separate refund API.

    Example::

        await handler.refund(receipt)
    """

    async def refund(self, receipt: Receipt) -> None:
        """Refund a confirmed merchant payment.

        Example::

            await handler.refund(receipt)
        """
        ...


@dataclass
class _PaymentRecord:
    payee: AgentId
    amount: Money
    session_id: str
    status: PaymentStatus = PaymentStatus.PENDING
    receipt: Receipt | None = None


class PravaAPIError(RuntimeError):
    """Sanitized Prava API failure.

    Example::

        raise PravaAPIError(401, "AUTH_1001", "Invalid API key")
    """

    def __init__(self, status_code: int, code: str, message: str) -> None:
        self.status_code = status_code
        self.code = code
        super().__init__(f"Prava API {status_code} {code}: {message}")


class PravaHTTPTransport:
    """Strict stdlib HTTP client for Prava's documented Session API.

    Example::

        transport = PravaHTTPTransport.from_environment()
    """

    def __init__(self, api_key: str, base_url: str, timeout_seconds: float = 20.0) -> None:
        normalized_url = base_url.rstrip("/")
        if api_key.startswith("sk_test_") and normalized_url != _SANDBOX_URL:
            raise ValueError("sandbox keys require the official Prava sandbox host")
        if api_key.startswith("sk_live_") and normalized_url != _PRODUCTION_URL:
            raise ValueError("live keys require the official Prava production host")
        if not api_key.startswith(("sk_test_", "sk_live_")):
            raise ValueError("Prava API key must use an sk_test_ or sk_live_ prefix")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self._api_key = api_key
        self._base_url = normalized_url
        self._timeout = timeout_seconds

    @classmethod
    def from_environment(cls) -> PravaHTTPTransport:
        """Construct a transport without exposing credentials.

        Example::

            transport = PravaHTTPTransport.from_environment()
        """
        api_key = os.environ.get("PRAVA_API_KEY", "").strip()
        base_url = (
            os.environ.get("PRAVA_API_URL", "").strip()
            or os.environ.get("PRAVA_SANDBOX_URL", "").strip()
        )
        if not api_key or not base_url:
            raise RuntimeError("PRAVA_API_KEY and PRAVA_API_URL are required")
        if api_key.startswith("sk_live_") and os.environ.get("PRAVA_PRODUCTION_ENABLED") != "1":
            raise RuntimeError("Prava production requires PRAVA_PRODUCTION_ENABLED=1")
        return cls(api_key, base_url)

    @staticmethod
    def _amount_string(amount: Money) -> str:
        if amount.amount <= 0:
            raise ValueError("payment amount must be positive")
        return format(Decimal(amount.amount) / Decimal(100), ".2f")

    def _request(
        self, method: str, path: str, payload: dict[str, object] | None = None
    ) -> dict[str, object]:
        data = json.dumps(payload).encode() if payload is not None else None
        headers = {"Authorization": f"Bearer {self._api_key}"}
        if payload is not None:
            headers["Content-Type"] = "application/json"
        request = Request(f"{self._base_url}{path}", data=data, headers=headers, method=method)
        try:
            with urlopen(request, timeout=self._timeout) as response:
                body = response.read().decode()
        except HTTPError as exc:
            try:
                decoded_error: object = json.loads(exc.read().decode())
                error_container = (
                    cast("dict[str, object]", decoded_error)
                    if isinstance(decoded_error, dict)
                    else {}
                )
                error_value = error_container.get("error", {})
                error = (
                    cast("dict[str, object]", error_value) if isinstance(error_value, dict) else {}
                )
            except (UnicodeDecodeError, json.JSONDecodeError):
                error = {}
            raise PravaAPIError(
                exc.code,
                str(error.get("code") or "HTTP_ERROR"),
                str(error.get("message") or "request failed"),
            ) from exc
        except (TimeoutError, URLError) as exc:
            raise RuntimeError("Prava API is unreachable") from exc
        try:
            decoded_result: object = json.loads(body)
        except json.JSONDecodeError as exc:
            raise RuntimeError("Prava returned invalid JSON") from exc
        if not isinstance(decoded_result, dict):
            raise RuntimeError("Prava returned an invalid response object")
        return cast("dict[str, object]", decoded_result)

    def create_session(
        self, *, profile: PayeeProfile, amount: Money, payment_ref: PaymentRef
    ) -> PravaSession:
        """Create a Prava standard-checkout session.

        Example::

            session = transport.create_session(profile=profile, amount=money, payment_ref=ref)
        """
        amount_string = self._amount_string(amount)
        result = self._request(
            "POST",
            "/v1/sessions",
            {
                "user_id": profile.user_id,
                "user_email": profile.user_email,
                "total_amount": amount_string,
                "currency": amount.currency.upper(),
                "integration_type": "full_checkout",
                "external_order_ref": str(payment_ref),
                "purchase_context": [
                    {
                        "merchant_details": {
                            "name": profile.merchant_name,
                            "url": profile.merchant_url,
                            "country_code_iso2": profile.merchant_country.upper(),
                        },
                        "product_details": [
                            {
                                "description": profile.product_description,
                                "unit_price": amount_string,
                                "quantity": 1,
                            }
                        ],
                        "effective_until_minutes": 15,
                    }
                ],
            },
        )
        session_id = result.get("session_id")
        approval_url = result.get("iframe_url")
        if not isinstance(session_id, str) or not isinstance(approval_url, str):
            raise RuntimeError("Prava session response omitted required fields")
        return PravaSession(session_id, approval_url)

    def payment_result(self, session_id: str) -> dict[str, object]:
        """Fetch a Prava payment result.

        Example::

            result = transport.payment_result("ses_1")
        """
        return self._request("GET", f"/v1/sessions/{url_quote(session_id, safe='')}/payment-result")

    def report_status(
        self,
        *,
        session_id: str,
        transaction_ref: str,
        approved: bool,
        outcome: MerchantOutcome,
    ) -> None:
        """Report a terminal merchant outcome to Prava.

        Example::

            transport.report_status(
                session_id="ses_1", transaction_ref="txn_1",
                approved=True, outcome=MerchantOutcome(True),
            )
        """
        payload: dict[str, object] = {
            "txn_ref_id": transaction_ref,
            "txn_status": "APPROVED" if approved else "DECLINED",
        }
        if outcome.authorization_code is not None:
            payload["authorization_code"] = outcome.authorization_code
        if outcome.response_code is not None:
            payload["response_code"] = outcome.response_code
        result = self._request(
            "POST", f"/v1/sessions/{url_quote(session_id, safe='')}/report-status", payload
        )
        if result.get("status") != "confirmed" or result.get("visa_confirmation") != "SUCCESS":
            raise RuntimeError("Prava did not confirm the merchant outcome")

    def revoke_session(self, session_id: str) -> None:
        """Revoke an incomplete session.

        Example::

            transport.revoke_session("ses_1")
        """
        result = self._request("POST", f"/v1/sessions/{url_quote(session_id, safe='')}/revoke")
        if result.get("success") is not True:
            raise RuntimeError("Prava did not confirm session revocation")


class PravaPayments:
    """NANDA payments plugin that requires explicit approval and merchant execution.

    Example::

        payments = PravaPayments(AgentId("buyer-0"), transport=fake_transport)
    """

    def __init__(
        self,
        agent_id: AgentId | str,
        initial_balance: int = 0,
        *,
        transport: PravaTransport | None = None,
        executor: MerchantExecutor | None = None,
        refund_handler: RefundHandler | None = None,
        payees: Mapping[AgentId, PayeeProfile] | None = None,
        services: Mapping[ServiceRef, Money] | None = None,
        approval_notifier: Callable[[str, str], None] | None = None,
        poll_interval_seconds: float = 1.0,
        poll_timeout_seconds: float = 840.0,
    ) -> None:
        del initial_balance
        if poll_interval_seconds < 0 or poll_timeout_seconds <= 0:
            raise ValueError("poll interval must be non-negative and timeout must be positive")
        self._agent_id = AgentId(str(agent_id))
        self._transport = transport or PravaHTTPTransport.from_environment()
        self._executor = executor
        self._refund_handler = refund_handler
        self._payees = dict(payees or {})
        self._services = dict(services or {})
        self._approval_notifier = approval_notifier
        self._poll_interval = poll_interval_seconds
        self._poll_timeout = poll_timeout_seconds
        self._payments: dict[PaymentRef, _PaymentRecord] = {}

    async def quote(self, service: ServiceRef) -> Quote:
        """Return a configured quote; unknown services fail closed.

        Example::

            quote = await payments.quote(ServiceRef("restock-demo"))
        """
        price = self._services.get(service)
        if price is None:
            raise ValueError(f"unknown service: {service}")
        return Quote(
            service=service,
            price=price,
            ttl_seconds=300,
            metadata={"provider": "prava", "approval_required": True},
        )

    @staticmethod
    def _line_item(result: dict[str, object]) -> tuple[str, dict[str, str]]:
        transactions = result.get("transactions")
        if not isinstance(transactions, list) or not transactions:
            raise RuntimeError("Prava result omitted its transaction")
        typed_transactions = cast("list[object]", transactions)
        transaction = typed_transactions[0]
        if not isinstance(transaction, dict):
            raise RuntimeError("Prava returned an invalid transaction")
        typed_transaction = cast("dict[str, object]", transaction)
        line_items = typed_transaction.get("line_items")
        if not isinstance(line_items, list) or not line_items:
            raise RuntimeError("Prava result omitted its line item")
        typed_line_items = cast("list[object]", line_items)
        line_item = typed_line_items[0]
        if not isinstance(line_item, dict):
            raise RuntimeError("Prava returned an invalid line item")
        typed_line_item = cast("dict[str, object]", line_item)
        transaction_ref = typed_line_item.get("txn_ref_id")
        if not isinstance(transaction_ref, str) or not transaction_ref:
            raise RuntimeError("Prava result omitted txn_ref_id")
        credentials: dict[str, str] = {}
        for field in _SENSITIVE_FIELDS:
            value = typed_line_item.get(field)
            if not isinstance(value, str) or not value:
                raise RuntimeError(f"Prava result omitted {field}")
            credentials[field] = value
        return transaction_ref, credentials

    async def _revoke_quietly(self, session_id: str) -> None:
        try:
            await asyncio.to_thread(self._transport.revoke_session, session_id)
        except Exception:
            return

    async def pay(self, to: AgentId, amount: Money, ref: PaymentRef) -> Receipt:
        """Create, authorize, and execute one idempotent Prava-backed payment.

        Example::

            receipt = await payments.pay(
                AgentId("seller-0"), Money(amount=100, currency="USD"), PaymentRef("p1")
            )
        """
        if amount.amount <= 0:
            raise ValueError("payment amount must be positive")
        existing = self._payments.get(ref)
        if existing is not None:
            if existing.payee != to or existing.amount != amount:
                raise ValueError("payment reference was already used with different terms")
            if existing.receipt is not None and existing.status == PaymentStatus.CONFIRMED:
                return existing.receipt
            raise ValueError(f"payment reference is already {existing.status.value}")
        profile = self._payees.get(to)
        if profile is None:
            raise ValueError(f"no Prava merchant profile configured for payee: {to}")
        if self._executor is None:
            raise RuntimeError(
                "a merchant executor is required; authorization alone is not payment"
            )

        session = await asyncio.to_thread(
            self._transport.create_session, profile=profile, amount=amount, payment_ref=ref
        )
        record = _PaymentRecord(to, amount, session.session_id)
        self._payments[ref] = record
        if self._approval_notifier is not None:
            self._approval_notifier(session.session_id, session.approval_url)

        deadline = time.monotonic() + self._poll_timeout
        try:
            while True:
                result = await asyncio.to_thread(self._transport.payment_result, session.session_id)
                status = str(result.get("status", "")).lower()
                if status == "awaiting_result":
                    transaction_ref, credentials = self._line_item(result)
                    try:
                        outcome = await self._executor.execute(credentials, amount, ref)
                    finally:
                        credentials.clear()
                    await asyncio.to_thread(
                        self._transport.report_status,
                        session_id=session.session_id,
                        transaction_ref=transaction_ref,
                        approved=outcome.approved,
                        outcome=outcome,
                    )
                    if not outcome.approved:
                        record.status = PaymentStatus.FAILED
                        raise RuntimeError("merchant declined the authorized payment")
                    receipt = Receipt(
                        ref=ref,
                        payer=self._agent_id,
                        payee=to,
                        amount=amount,
                        timestamp=time.time(),
                    )
                    record.status = PaymentStatus.CONFIRMED
                    record.receipt = receipt
                    return receipt
                if status == "completed":
                    record.status = PaymentStatus.CONFIRMED
                    receipt = Receipt(
                        ref=ref,
                        payer=self._agent_id,
                        payee=to,
                        amount=amount,
                        timestamp=time.time(),
                    )
                    record.receipt = receipt
                    return receipt
                if status == "failed":
                    record.status = PaymentStatus.FAILED
                    raise RuntimeError("Prava payment failed before merchant execution")
                if status not in {"pending"}:
                    raise RuntimeError(f"Prava returned unknown payment status: {status}")
                if time.monotonic() >= deadline:
                    raise TimeoutError("Prava approval timed out")
                await asyncio.sleep(self._poll_interval)
        except Exception:
            if record.status == PaymentStatus.PENDING:
                record.status = PaymentStatus.FAILED
                await self._revoke_quietly(session.session_id)
            raise

    async def verify_payment(self, ref: PaymentRef) -> PaymentStatus:
        """Verify a payment from local terminal state or Prava.

        Example::

            status = await payments.verify_payment(PaymentRef("p1"))
        """
        record = self._payments.get(ref)
        if record is None:
            return PaymentStatus.FAILED
        if record.status in {
            PaymentStatus.CONFIRMED,
            PaymentStatus.FAILED,
            PaymentStatus.REFUNDED,
        }:
            return record.status
        result = await asyncio.to_thread(self._transport.payment_result, record.session_id)
        remote_status = str(result.get("status", "")).lower()
        if remote_status == "completed":
            record.status = PaymentStatus.CONFIRMED
        elif remote_status == "failed":
            record.status = PaymentStatus.FAILED
        return record.status

    async def refund(self, ref: PaymentRef) -> None:
        """Delegate a refund to the merchant and record the result.

        Prava's official FAQ says it exposes no separate refund endpoint.

        Example::

            await payments.refund(PaymentRef("p1"))
        """
        record = self._payments.get(ref)
        if record is None or record.receipt is None:
            raise ValueError(f"confirmed payment not found: {ref}")
        if record.status == PaymentStatus.REFUNDED:
            return
        if record.status != PaymentStatus.CONFIRMED:
            raise ValueError(f"payment is not refundable: {record.status.value}")
        if self._refund_handler is None:
            raise NotImplementedError(
                "refunds must be configured through the destination merchant; "
                "Prava exposes no separate refund endpoint"
            )
        await self._refund_handler.refund(record.receipt)
        record.status = PaymentStatus.REFUNDED
