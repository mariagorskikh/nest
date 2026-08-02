# SPDX-License-Identifier: Apache-2.0
"""Payment state machine records for the Prava adapter.

Example::

    from nest_plugins_prava.state import PaymentRecord, PaymentPhase
    record = PaymentRecord(ref=..., payer=..., payee=..., amount=...)
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from nest_sdk import AgentId, Money, PaymentRef, PaymentStatus, Receipt


class PaymentPhase(StrEnum):
    """Internal rail phase — finer grained than PaymentStatus."""

    INIT = "init"
    BUDGET_LOCKED = "budget_locked"
    SESSION_CREATED = "session_created"
    AWAITING_RESULT = "awaiting_result"
    REPORTED = "reported"
    CONFIRMED = "confirmed"
    FAILED = "failed"
    REFUNDED = "refunded"


@dataclass
class PaymentRecord:
    """Durable record for one PaymentRef across agent handles.

    Example::

        record.status  # PaymentStatus.PENDING
    """

    ref: PaymentRef
    payer: AgentId
    payee: AgentId
    amount: Money
    phase: PaymentPhase = PaymentPhase.INIT
    status: PaymentStatus = PaymentStatus.PENDING
    session_id: str | None = None
    order_id: str | None = None
    txn_ref_id: str | None = None
    response_id: str | None = None
    error_code: str | None = None
    error_message: str | None = None
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    locked_credits: int = 0

    def touch(self) -> None:
        """Update the last-modified timestamp."""
        self.updated_at = time.time()

    def to_receipt(self) -> Receipt:
        """Project a NANDA Receipt (never includes secrets).

        Example::

            receipt = record.to_receipt()
        """
        return Receipt(
            ref=self.ref,
            payer=self.payer,
            payee=self.payee,
            amount=self.amount,
            timestamp=self.created_at,
        )

    def public_view(self) -> dict[str, Any]:
        """Safe diagnostic dict for logs/tests — no tokens/keys.

        Example::

            view = record.public_view()
        """
        return {
            "ref": str(self.ref),
            "payer": str(self.payer),
            "payee": str(self.payee),
            "amount": self.amount.amount,
            "currency": self.amount.currency,
            "phase": self.phase.value,
            "status": self.status.value,
            "session_id": self.session_id,
            "order_id": self.order_id,
            "txn_ref_id": self.txn_ref_id,
            "response_id": self.response_id,
            "error_code": self.error_code,
            "error_message": self.error_message,
        }


@dataclass
class QuoteRecord:
    """Cached quote with absolute expiry."""

    service: str
    price_credits: int
    expires_at: float
    currency: str = "credits"
