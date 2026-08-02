# SPDX-License-Identifier: Apache-2.0
"""Error type for the Prava payments plugin.

Example::

    raise PravaPaymentError("POLICY_NEEDS_HUMAN", "amount $47.00 exceeds cap $40.00")
"""

from __future__ import annotations

from typing import Any


class PravaPaymentError(ValueError):
    """A payment could not be made, with the reason the arbiter gave.

    Subclasses :class:`ValueError` to match the reference payments plugins
    (``prepaid_credits`` raises ``ValueError``; ``escrow`` subclasses it),
    so existing scenarios catch it without modification.

    Example::

        try:
            await payments.pay(AgentId("agent_b"), Money(amount=7050), PaymentRef("p1"))
        except PravaPaymentError as exc:
            assert exc.code == "POLICY_NEEDS_HUMAN"
    """

    def __init__(
        self,
        code: str,
        message: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.details = details or {}
