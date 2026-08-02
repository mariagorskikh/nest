# SPDX-License-Identifier: Apache-2.0
"""Typed exceptions mapped from Prava API error codes.

This module defines a hierarchy of exceptions that map directly to Prava API
error responses. Each exception carries the original error code for programmatic
handling and a human-readable message.

Example::

    try:
        await client.charge(mandate_id, amount, reference)
    except ThresholdExceededError as e:
        # Handle cap enforcement - this is the "defense held" outcome
        print(f"Charge blocked: {e.message}")
    except MandateNotActiveError:
        # Mandate was cancelled or paused
        ...
"""

from __future__ import annotations

from typing import Any


class PravaError(Exception):
    """Base exception for all Prava API errors.

    Attributes:
        code: The Prava error code (e.g., "THRESHOLD_EXCEEDED").
        message: Human-readable error description.
        details: Optional additional error context from API response.

    Example::

        raise PravaError("UNKNOWN_ERROR", "An unexpected error occurred")
    """

    def __init__(
        self,
        code: str,
        message: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.code = code
        self.message = message
        self.details = details or {}
        super().__init__(f"[{code}] {message}")


class ThresholdExceededError(PravaError):
    """Charge amount exceeds the mandate's approved cap.

    This is the "defense held" outcome in the game - the consumer's spending
    limit successfully prevented an excessive charge.

    Example::

        # Mandate approved for $100, attempting to charge $150
        raise ThresholdExceededError(
            approved_amount=10000,  # cents
            requested_amount=15000,
            spent_amount=0,
        )
    """

    def __init__(
        self,
        approved_amount: int,
        requested_amount: int,
        spent_amount: int = 0,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.approved_amount = approved_amount
        self.requested_amount = requested_amount
        self.spent_amount = spent_amount
        remaining = approved_amount - spent_amount
        super().__init__(
            code="THRESHOLD_EXCEEDED",
            message=(
                f"Charge of {requested_amount} exceeds remaining cap of {remaining} "
                f"(approved: {approved_amount}, spent: {spent_amount})"
            ),
            details=details,
        )


class MandateNotActiveError(PravaError):
    """Mandate is not in an active state (cancelled, paused, or expired).

    Example::

        raise MandateNotActiveError("mdt_123", status="cancelled")
    """

    def __init__(
        self,
        mandate_id: str,
        status: str = "inactive",
        details: dict[str, Any] | None = None,
    ) -> None:
        self.mandate_id = mandate_id
        self.status = status
        super().__init__(
            code="MANDATE_NOT_ACTIVE",
            message=f"Mandate {mandate_id} is not active (status: {status})",
            details=details,
        )


class MandateMerchantNotAllowedError(PravaError):
    """Mandate scope restricts this merchant from charging.

    Occurs when mandate has `merchant_scope: "listed"` and the charging
    merchant is not in the allowed list.

    Example::

        raise MandateMerchantNotAllowedError("mdt_123", "merchant_xyz")
    """

    def __init__(
        self,
        mandate_id: str,
        merchant_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.mandate_id = mandate_id
        self.merchant_id = merchant_id
        merchant_info = f" (merchant: {merchant_id})" if merchant_id else ""
        super().__init__(
            code="MANDATE_MERCHANT_NOT_ALLOWED",
            message=f"Merchant not allowed to charge mandate {mandate_id}{merchant_info}",
            details=details,
        )


class MandateNotFoundError(PravaError):
    """Mandate does not exist.

    Example::

        raise MandateNotFoundError("mdt_nonexistent")
    """

    def __init__(
        self,
        mandate_id: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.mandate_id = mandate_id
        super().__init__(
            code="MANDATE_NOT_FOUND",
            message=f"Mandate not found: {mandate_id}",
            details=details,
        )


class AuthRequiredError(PravaError):
    """Authentication is required or credentials are invalid.

    Example::

        raise AuthRequiredError("Invalid or expired API key")
    """

    def __init__(
        self,
        message: str = "Authentication required",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            code="AUTH_REQUIRED",
            message=message,
            details=details,
        )


class NetworkTimeoutError(PravaError):
    """Request timed out after retries.

    Example::

        raise NetworkTimeoutError(timeout_seconds=30, retries=2)
    """

    def __init__(
        self,
        timeout_seconds: float,
        retries: int,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.timeout_seconds = timeout_seconds
        self.retries = retries
        super().__init__(
            code="NETWORK_TIMEOUT",
            message=f"Request timed out after {retries} retries (timeout: {timeout_seconds}s)",
            details=details,
        )


class ServerError(PravaError):
    """Prava server returned a 5xx error.

    Includes NO_TOKEN (500) and other internal server errors.

    Example::

        raise ServerError(status_code=500, message="Internal server error")
    """

    def __init__(
        self,
        status_code: int,
        message: str = "Server error",
        details: dict[str, Any] | None = None,
    ) -> None:
        self.status_code = status_code
        # NO_TOKEN is a specific 500 error code from Prava
        code = "NO_TOKEN" if "NO_TOKEN" in message.upper() else "SERVER_ERROR"
        super().__init__(
            code=code,
            message=f"HTTP {status_code}: {message}",
            details=details,
        )


class DuplicateReferenceError(PravaError):
    """Charge reference has already been used.

    Note: This may not be an error in idempotent scenarios - the original
    transaction is returned instead.

    Example::

        raise DuplicateReferenceError("ref_123", "txn_original")
    """

    def __init__(
        self,
        reference: str,
        original_transaction_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.reference = reference
        self.original_transaction_id = original_transaction_id
        super().__init__(
            code="DUPLICATE_REFERENCE",
            message=f"Reference already used: {reference}",
            details=details,
        )


class InvalidAmountError(PravaError):
    """Payment amount is invalid (zero, negative, or wrong format).

    Example::

        raise InvalidAmountError(-100)
    """

    def __init__(
        self,
        amount: int,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.amount = amount
        super().__init__(
            code="INVALID_AMOUNT",
            message=f"Invalid payment amount: {amount}",
            details=details,
        )


class ChargeFailedError(PravaError):
    """Charge was declined by the network or failed for other reasons.

    Example::

        raise ChargeFailedError("txn_123", "Card declined by issuer")
    """

    def __init__(
        self,
        transaction_id: str | None,
        reason: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.transaction_id = transaction_id
        self.reason = reason
        super().__init__(
            code="CHARGE_FAILED",
            message=f"Charge failed: {reason}",
            details=details,
        )


class PaymentNotFoundError(PravaError):
    """Payment reference not found (for verify/refund operations).

    Example::

        raise PaymentNotFoundError("pay_ref_123")
    """

    def __init__(
        self,
        reference: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.reference = reference
        super().__init__(
            code="PAYMENT_NOT_FOUND",
            message=f"Payment not found: {reference}",
            details=details,
        )


# Error code to exception class mapping for parsing API responses
ERROR_CODE_MAP: dict[str, type[PravaError]] = {
    "THRESHOLD_EXCEEDED": ThresholdExceededError,
    "MANDATE_NOT_FOUND": MandateNotFoundError,
    "MANDATE_NOT_ACTIVE": MandateNotActiveError,
    "MANDATE_MERCHANT_NOT_ALLOWED": MandateMerchantNotAllowedError,
    "AUTH_REQUIRED": AuthRequiredError,
    "DUPLICATE_REFERENCE": DuplicateReferenceError,
    "INVALID_AMOUNT": InvalidAmountError,
    "CHARGE_FAILED": ChargeFailedError,
    "PAYMENT_NOT_FOUND": PaymentNotFoundError,
    "NO_TOKEN": ServerError,
    "SERVER_ERROR": ServerError,
    "NETWORK_TIMEOUT": NetworkTimeoutError,
}


def parse_error_response(
    status_code: int,
    response_data: dict[str, Any],
) -> PravaError:
    """Parse an API error response into a typed exception.

    Args:
        status_code: HTTP status code.
        response_data: Parsed JSON response body.

    Returns:
        Appropriate PravaError subclass based on error code.

    Example::

        error = parse_error_response(400, {"errorCode": "THRESHOLD_EXCEEDED", ...})
        # Returns ThresholdExceededError instance
    """
    # Extract error info from response (Prava uses various field names)
    error_code = (
        response_data.get("errorCode")
        or response_data.get("error_code")
        or response_data.get("code")
        or ""
    )
    error_message = (
        response_data.get("errorMessage")
        or response_data.get("error_message")
        or response_data.get("message")
        or "Unknown error"
    )

    # Handle HTTP status codes
    if status_code == 401 or status_code == 403:
        return AuthRequiredError(message=error_message, details=response_data)

    if status_code == 404:
        # Could be mandate not found or payment not found
        if "mandate" in error_message.lower():
            mandate_id = response_data.get("mandateId") or response_data.get("mandate_id") or ""
            return MandateNotFoundError(mandate_id=mandate_id, details=response_data)
        return PaymentNotFoundError(reference="", details=response_data)

    if status_code >= 500:
        return ServerError(status_code=status_code, message=error_message, details=response_data)

    # Parse specific error codes
    error_code_upper = error_code.upper()

    if "THRESHOLD" in error_code_upper or "THRESHOLD" in error_message.upper():
        # Extract amounts if available
        return ThresholdExceededError(
            approved_amount=response_data.get("approvedAmount", 0),
            requested_amount=response_data.get("requestedAmount", 0),
            spent_amount=response_data.get("spent", 0),
            details=response_data,
        )

    if "NOT_ACTIVE" in error_code_upper or "INACTIVE" in error_message.upper():
        return MandateNotActiveError(
            mandate_id=response_data.get("mandateId", ""),
            status=response_data.get("status", "inactive"),
            details=response_data,
        )

    if "MERCHANT_NOT_ALLOWED" in error_code_upper or "MERCHANT" in error_message.upper():
        return MandateMerchantNotAllowedError(
            mandate_id=response_data.get("mandateId", ""),
            details=response_data,
        )

    if "NOT_FOUND" in error_code_upper:
        if "mandate" in error_message.lower():
            return MandateNotFoundError(
                mandate_id=response_data.get("mandateId", ""),
                details=response_data,
            )
        return PaymentNotFoundError(reference="", details=response_data)

    if "DUPLICATE" in error_code_upper:
        return DuplicateReferenceError(
            reference=response_data.get("reference", ""),
            original_transaction_id=response_data.get("transactionId"),
            details=response_data,
        )

    # Default to generic PravaError
    return PravaError(
        code=error_code or f"HTTP_{status_code}",
        message=error_message,
        details=response_data,
    )
