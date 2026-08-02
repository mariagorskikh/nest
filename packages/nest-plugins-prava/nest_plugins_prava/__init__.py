# SPDX-License-Identifier: Apache-2.0
"""Prava payments adapter for Nanda Town.

Example::

    from nest_plugins_prava import PravaPayments
    from nest_sdk import AgentId

    payments = PravaPayments(AgentId("buyer"), initial_balance=1000)
"""

from __future__ import annotations

from nest_plugins_prava.errors import (
    DuplicatePaymentRefError,
    InsufficientFundsError,
    InvalidPaymentStateError,
    PaymentNotFoundError,
    PravaAdapterError,
    PravaAuthError,
    PravaDeclinedError,
    PravaSessionExpiredError,
    PravaTimeoutError,
    QuoteExpiredError,
)
from nest_plugins_prava.plugin import PravaPayments

__all__ = [
    "DuplicatePaymentRefError",
    "InsufficientFundsError",
    "InvalidPaymentStateError",
    "PaymentNotFoundError",
    "PravaAdapterError",
    "PravaAuthError",
    "PravaDeclinedError",
    "PravaPayments",
    "PravaSessionExpiredError",
    "PravaTimeoutError",
    "QuoteExpiredError",
]

__version__ = "0.1.0"
