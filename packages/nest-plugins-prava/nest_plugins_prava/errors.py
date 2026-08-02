# SPDX-License-Identifier: Apache-2.0
"""Typed failure taxonomy for the Prava payments adapter.

Example::

    from nest_plugins_prava.errors import InsufficientFundsError
    raise InsufficientFundsError("balance=5 < amount=50")
"""

from __future__ import annotations


class PravaAdapterError(Exception):
    """Base error for all adapter failures surfaced to NANDA agents."""

    def __init__(
        self, message: str, *, code: str | None = None, response_id: str | None = None
    ) -> None:
        super().__init__(message)
        self.code = code
        self.response_id = response_id


class InsufficientFundsError(PravaAdapterError):
    """Local simulation budget is too low to attempt a Prava session."""


class DuplicatePaymentRefError(PravaAdapterError):
    """PaymentRef was reused with conflicting payee/amount."""


class PaymentNotFoundError(PravaAdapterError):
    """verify/refund referenced an unknown PaymentRef."""


class InvalidPaymentStateError(PravaAdapterError):
    """Operation is illegal for the payment's current state."""


class QuoteExpiredError(PravaAdapterError):
    """Caller tried to pay after the quote TTL elapsed."""


class PravaAuthError(PravaAdapterError):
    """Prava rejected credentials (AUTH_* / missing key)."""


class PravaTimeoutError(PravaAdapterError):
    """Prava HTTP call timed out after retries."""


class PravaSessionExpiredError(PravaAdapterError):
    """Session expired or was revoked (AUTH_1003 / AUTH_1004)."""


class PravaDeclinedError(PravaAdapterError):
    """Checkout completed but the charge was DECLINED."""


class PravaValidationError(PravaAdapterError):
    """Request failed schema/business validation (VAL_* / 400)."""


class PravaApiError(PravaAdapterError):
    """Unexpected Prava API failure (5xx / unknown codes)."""
