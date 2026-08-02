# SPDX-License-Identifier: Apache-2.0
"""Thin async Prava REST client with retries and timeouts.

This module provides a minimal HTTP client for the Prava Agentic Payments API.
It handles authentication, retries with exponential backoff, and maps API
errors to typed exceptions.

Example::

    async with PravaClient(secret_key="sk_test_...") as client:
        # Charge a mandate
        charge = await client.charge(
            mandate_id="mdt_123",
            amount=1250,  # cents
            reference="order-456",
        )
        print(f"Transaction: {charge.transaction_id}")

        # Report the charge outcome
        await client.report_charge(
            mandate_id="mdt_123",
            transaction_id=charge.transaction_id,
            outcome="APPROVED",
        )
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, cast

import httpx

from .errors import (
    AuthRequiredError,
    ChargeFailedError,
    NetworkTimeoutError,
    PravaError,
    ServerError,
    ThresholdExceededError,
    parse_error_response,
)

logger = logging.getLogger(__name__)

# Default configuration
DEFAULT_BASE_URL = "https://sandbox.api.prava.space"
DEFAULT_TIMEOUT_SECONDS = 30.0
DEFAULT_MAX_RETRIES = 2
DEFAULT_RETRY_BACKOFF_BASE = 1.0  # seconds


@dataclass
class ChargeResult:
    """Result of a charge operation.

    Attributes:
        transaction_id: Unique ID assigned by Prava.
        reference: The idempotency reference passed in the request.
        amount: Charged amount in cents.
        status: Current status (awaiting_result, completed, failed).
        is_duplicate: True if this was a deduplicated idempotent request.
        raw_response: Full API response (card data redacted).
    """

    transaction_id: str
    reference: str
    amount: int
    status: str
    is_duplicate: bool = False
    raw_response: dict[str, Any] = field(default_factory=lambda: {})


@dataclass
class MandateInfo:
    """Information about a mandate.

    Attributes:
        mandate_id: The mandate identifier.
        approved_amount: Maximum approved amount in cents.
        spent: Total amount charged so far in cents.
        remaining: Remaining balance in cents.
        charge_count: Number of charges made.
        status: Mandate status (active, paused, cancelled, expired).
        charges: List of charge records.
    """

    mandate_id: str
    approved_amount: int
    spent: int
    remaining: int
    charge_count: int
    status: str
    charges: list[dict[str, Any]] = field(default_factory=lambda: [])


def _redact_sensitive_data(data: dict[str, Any]) -> dict[str, Any]:
    """Redact sensitive card data from response.

    SECURITY: Card credentials must NEVER be logged or written to traces.

    Args:
        data: Raw API response.

    Returns:
        Copy with sensitive fields redacted.
    """
    sensitive_keys = {
        "cardNumber",
        "card_number",
        "pan",
        "cvv",
        "cvc",
        "expiry",
        "expiryDate",
        "expiry_date",
        "cardholderName",
        "cardholder_name",
        "token",
        "cardToken",
        "card_token",
    }

    sensitive_lower = {s.lower() for s in sensitive_keys}

    def redact_recursive(obj: Any) -> Any:
        if isinstance(obj, dict):
            result: dict[str, Any] = {}
            dict_obj = cast("dict[str, Any]", obj)
            for k, v in dict_obj.items():
                key = str(k)
                if key.lower() in sensitive_lower:
                    result[key] = "[REDACTED]"
                else:
                    result[key] = redact_recursive(v)
            return result
        elif isinstance(obj, list):
            list_obj = cast("list[Any]", obj)
            return [redact_recursive(item) for item in list_obj]
        return obj

    return redact_recursive(data)


class PravaClient:
    """Async HTTP client for the Prava Agentic Payments API.

    Handles authentication, retries with exponential backoff for transient
    failures, and maps API errors to typed exceptions.

    Example::

        client = PravaClient(secret_key="sk_test_...")
        try:
            charge = await client.charge("mdt_123", 1000, "ref_456")
        finally:
            await client.close()

        # Or use as async context manager:
        async with PravaClient(secret_key="sk_test_...") as client:
            charge = await client.charge("mdt_123", 1000, "ref_456")
    """

    def __init__(
        self,
        secret_key: str,
        base_url: str = DEFAULT_BASE_URL,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        max_retries: int = DEFAULT_MAX_RETRIES,
        retry_backoff_base: float = DEFAULT_RETRY_BACKOFF_BASE,
    ) -> None:
        """Initialize the Prava client.

        Args:
            secret_key: Prava API secret key (sk_test_... or sk_live_...).
            base_url: API base URL. Defaults to sandbox.
            timeout_seconds: Request timeout. Defaults to 30s.
            max_retries: Max retries for transient failures. Defaults to 2.
            retry_backoff_base: Base delay between retries. Defaults to 1s.
        """
        if not secret_key:
            raise AuthRequiredError("Prava secret key is required")

        self._secret_key = secret_key
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout_seconds
        self._max_retries = max_retries
        self._retry_backoff_base = retry_backoff_base

        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            headers={
                "Authorization": f"Bearer {secret_key}",
                "Content-Type": "application/json",
            },
            timeout=timeout_seconds,
        )

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()

    async def __aenter__(self) -> PravaClient:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()

    async def _request_with_retry(
        self,
        method: str,
        path: str,
        json: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Make an HTTP request with retry logic.

        Retries on:
        - Network timeouts
        - 5xx server errors
        - Connection errors

        Does NOT retry on:
        - 4xx client errors (these are deterministic failures)
        - Successful responses

        Args:
            method: HTTP method (GET, POST, etc.).
            path: API path (e.g., "/v1/mandates/{id}/charge").
            json: JSON body for POST/PUT requests.
            params: Query parameters for GET requests.

        Returns:
            Parsed JSON response.

        Raises:
            NetworkTimeoutError: After exhausting retries on timeout.
            ServerError: On 5xx errors after retries.
            PravaError: On 4xx client errors.
        """
        last_error: Exception | None = None

        for attempt in range(self._max_retries + 1):
            try:
                response = await self._client.request(
                    method=method,
                    url=path,
                    json=json,
                    params=params,
                )

                # Parse response
                try:
                    data: dict[str, Any] = response.json()
                except Exception:
                    data = {"raw": response.text}

                # Success
                if response.status_code in (200, 201, 204):
                    return _redact_sensitive_data(data)

                # Client errors - don't retry, raise immediately
                if 400 <= response.status_code < 500:
                    raise parse_error_response(response.status_code, data)

                # Server errors - may retry
                if response.status_code >= 500:
                    msg: str = str(data.get("message", "Server error"))
                    details: dict[str, Any] = data
                    last_error = ServerError(
                        status_code=response.status_code,
                        message=msg,
                        details=details,
                    )
                    if attempt < self._max_retries:
                        await self._backoff(attempt)
                        continue
                    raise last_error

            except httpx.TimeoutException as e:
                last_error = NetworkTimeoutError(
                    timeout_seconds=self._timeout,
                    retries=attempt,
                    details={"error": str(e)},
                )
                if attempt < self._max_retries:
                    logger.warning(f"Request timeout, retry {attempt + 1}/{self._max_retries}")
                    await self._backoff(attempt)
                    continue

            except httpx.RequestError as e:
                last_error = NetworkTimeoutError(
                    timeout_seconds=self._timeout,
                    retries=attempt,
                    details={"error": str(e), "type": type(e).__name__},
                )
                if attempt < self._max_retries:
                    logger.warning(f"Request error, retry {attempt + 1}/{self._max_retries}: {e}")
                    await self._backoff(attempt)
                    continue

            except PravaError:
                # Re-raise typed errors (don't wrap them)
                raise

        # Exhausted retries
        if last_error:
            raise last_error
        raise NetworkTimeoutError(timeout_seconds=self._timeout, retries=self._max_retries)

    async def _backoff(self, attempt: int) -> None:
        """Wait with exponential backoff."""
        delay = self._retry_backoff_base * (2**attempt)
        await asyncio.sleep(delay)

    # -------------------------------------------------------------------------
    # Mandate Operations
    # -------------------------------------------------------------------------

    async def get_mandate(self, mandate_id: str) -> MandateInfo:
        """Get information about a mandate.

        Args:
            mandate_id: The mandate identifier.

        Returns:
            MandateInfo with current state.

        Raises:
            MandateNotFoundError: If mandate doesn't exist.
        """
        data = await self._request_with_retry("GET", f"/v1/mandates/{mandate_id}")

        # Parse amounts (API returns strings like "100.00")
        approved_str = data.get("approvedAmount") or data.get("approved_amount") or "0"
        spent_str = data.get("spent") or "0"

        approved_cents = _parse_amount_to_cents(approved_str)
        spent_cents = _parse_amount_to_cents(spent_str)

        return MandateInfo(
            mandate_id=data.get("id") or data.get("mandateId") or mandate_id,
            approved_amount=approved_cents,
            spent=spent_cents,
            remaining=approved_cents - spent_cents,
            charge_count=data.get("chargeCount") or data.get("charge_count") or 0,
            status=data.get("status", "unknown"),
            charges=data.get("charges", []),
        )

    async def charge(
        self,
        mandate_id: str,
        amount: int,
        reference: str,
    ) -> ChargeResult:
        """Charge against a mandate.

        The reference parameter provides idempotency - the same reference will
        return the same transaction without double-charging.

        Args:
            mandate_id: The mandate to charge.
            amount: Amount in cents (e.g., 1250 for $12.50).
            reference: Unique idempotency reference (e.g., order ID).

        Returns:
            ChargeResult with transaction details.

        Raises:
            ThresholdExceededError: If charge exceeds mandate cap.
            MandateNotFoundError: If mandate doesn't exist.
            MandateNotActiveError: If mandate is cancelled/paused.
            DuplicateReferenceError: If reference was used (idempotent return).
        """
        # Convert cents to dollars string (Prava API expects "12.50" format)
        amount_str = f"{amount / 100:.2f}"

        data = await self._request_with_retry(
            "POST",
            f"/v1/mandates/{mandate_id}/charge",
            json={"amount": amount_str, "reference": reference},
        )

        # Check for failed status in response
        status = data.get("status", "unknown")
        if status == "failed":
            error_msg = data.get("errorMessage") or data.get("error_message") or "Charge failed"

            # Check for specific failure reasons
            if "threshold" in error_msg.lower() or "exceeds" in error_msg.lower():
                raise ThresholdExceededError(
                    approved_amount=_parse_amount_to_cents(data.get("approvedAmount", "0")),
                    requested_amount=amount,
                    spent_amount=_parse_amount_to_cents(data.get("spent", "0")),
                    details=data,
                )

            raise ChargeFailedError(
                transaction_id=data.get("transactionId") or data.get("transaction_id"),
                reason=error_msg,
                details=data,
            )

        # Check for duplicate/idempotent response
        is_duplicate = data.get("deduplicated") or data.get("is_duplicate", False)

        return ChargeResult(
            transaction_id=data.get("transactionId") or data.get("transaction_id") or "",
            reference=reference,
            amount=amount,
            status=status,
            is_duplicate=is_duplicate,
            raw_response=data,
        )

    async def report_charge(
        self,
        mandate_id: str,
        transaction_id: str,
        outcome: str = "APPROVED",
        authorization_code: str = "NEST_AUTO",
    ) -> dict[str, Any]:
        """Report the outcome of a charge to settle it.

        This must be called after a successful charge to complete the
        settlement with the card network.

        Args:
            mandate_id: The mandate ID.
            transaction_id: Transaction ID from the charge response.
            outcome: "APPROVED" or "DECLINED".
            authorization_code: Authorization code from processor.

        Returns:
            Report response data.
        """
        payload = {
            "txn_status": outcome,
            "txn_type": "PURCHASE",
            "authorization_code": authorization_code,
            "response_code": "00" if outcome == "APPROVED" else "05",
        }

        return await self._request_with_retry(
            "POST",
            f"/v1/mandates/{mandate_id}/charges/{transaction_id}/report",
            json=payload,
        )

    async def find_charge_by_reference(
        self,
        mandate_id: str,
        reference: str,
    ) -> dict[str, Any] | None:
        """Find a charge by its reference within a mandate.

        Args:
            mandate_id: The mandate to search in.
            reference: The charge reference to find.

        Returns:
            Charge data if found, None otherwise.
        """
        mandate = await self.get_mandate(mandate_id)

        for charge in mandate.charges:
            charge_ref = charge.get("reference") or charge.get("ref") or ""
            if charge_ref == reference:
                return charge

        return None


def _parse_amount_to_cents(amount_str: str | int | float) -> int:
    """Parse an amount string/number to cents.

    Args:
        amount_str: Amount like "12.50" or 12.50 or 1250.

    Returns:
        Amount in cents (integer).
    """
    if isinstance(amount_str, int):
        # If already an integer, assume it might be dollars or cents
        # Convention: if > 100, likely cents; otherwise dollars
        return amount_str if amount_str > 100 else amount_str * 100

    if isinstance(amount_str, float):
        return int(amount_str * 100)

    try:
        # Handle string like "12.50"
        value = float(str(amount_str).replace(",", ""))
        return int(value * 100)
    except ValueError:
        return 0
