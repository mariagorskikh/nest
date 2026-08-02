# SPDX-License-Identifier: Apache-2.0
"""Prava payments plugin for nest.

This package provides a Payments protocol implementation backed by Prava's
Agentic Payments API with mandate-based authorization.

Example::

    from nest_plugins_prava import PravaPayments
    from nest_sdk import AgentId, Money, PaymentRef

    payments = PravaPayments(
        agent_id=AgentId("buyer-01"),
        mandate_map={AgentId("buyer-01"): "mdt_01ABCD..."},
        prava_secret_key="sk_test_...",  # or omit for mock mode
    )

    receipt = await payments.pay(
        to=AgentId("seller-01"),
        amount=Money(amount=1250, currency="USD"),
        ref=PaymentRef("order-123"),
    )
"""

from .client import ChargeResult, MandateInfo, PravaClient
from .errors import (
    AuthRequiredError,
    ChargeFailedError,
    DuplicateReferenceError,
    InvalidAmountError,
    MandateMerchantNotAllowedError,
    MandateNotActiveError,
    MandateNotFoundError,
    NetworkTimeoutError,
    PaymentNotFoundError,
    PravaError,
    ServerError,
    ThresholdExceededError,
    parse_error_response,
)
from .payments import MockCharge, MockMandate, PravaPayments

__all__ = [
    # Main plugin
    "PravaPayments",
    # Client
    "PravaClient",
    "ChargeResult",
    "MandateInfo",
    # Mock types (for testing)
    "MockCharge",
    "MockMandate",
    # Errors
    "PravaError",
    "ThresholdExceededError",
    "MandateNotActiveError",
    "MandateMerchantNotAllowedError",
    "MandateNotFoundError",
    "AuthRequiredError",
    "NetworkTimeoutError",
    "ServerError",
    "DuplicateReferenceError",
    "InvalidAmountError",
    "ChargeFailedError",
    "PaymentNotFoundError",
    "parse_error_response",
]
