# SPDX-License-Identifier: Apache-2.0
"""Currency and identity mapping between NANDA Town and Prava.

Example::

    from nest_plugins_prava.mapping import credits_to_decimal_amount
    assert credits_to_decimal_amount(50) == "0.50"
"""

from __future__ import annotations

from decimal import ROUND_HALF_UP, Decimal

from nest_sdk import AgentId

# Default: 1 credit == 1 US cent. Override via PravaPayments(credits_per_unit=...).
DEFAULT_CURRENCY = "USD"
DEFAULT_MERCHANT_NAME = "NANDA Town Marketplace"
DEFAULT_MERCHANT_URL = "https://nandatown.projectnanda.org"
DEFAULT_MERCHANT_COUNTRY = "US"


def credits_to_decimal_amount(credits: int, *, credits_per_unit: int = 100) -> str:
    """Convert integer credits into a Prava decimal amount string.

    Example::

        credits_to_decimal_amount(50)  # "0.50"
        credits_to_decimal_amount(100, credits_per_unit=100)  # "1.00"
    """
    if credits < 0:
        msg = f"credits must be non-negative, got {credits}"
        raise ValueError(msg)
    if credits_per_unit <= 0:
        msg = f"credits_per_unit must be positive, got {credits_per_unit}"
        raise ValueError(msg)
    amount = (Decimal(credits) / Decimal(credits_per_unit)).quantize(
        Decimal("0.01"), rounding=ROUND_HALF_UP
    )
    return f"{amount:.2f}"


def decimal_amount_to_credits(amount: str, *, credits_per_unit: int = 100) -> int:
    """Convert a Prava decimal amount string back to integer credits.

    Example::

        decimal_amount_to_credits("0.50")  # 50
    """
    value = Decimal(amount)
    credit_amount = (value * Decimal(credits_per_unit)).quantize(
        Decimal("1"), rounding=ROUND_HALF_UP
    )
    return int(credit_amount)


def agent_to_user_id(agent: AgentId) -> str:
    """Map a NANDA AgentId to a stable Prava user_id.

    Example::

        agent_to_user_id(AgentId("buyer-0"))  # "nanda-buyer-0"
    """
    raw = str(agent).strip()
    safe = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in raw)
    return f"nanda-{safe}"[:255]


def agent_to_email(agent: AgentId) -> str:
    """Derive a deterministic sandbox email for an agent.

    Example::

        agent_to_email(AgentId("buyer-0"))
    """
    user = agent_to_user_id(agent).replace("_", "-")
    return f"{user}@agents.nandatown.local"
