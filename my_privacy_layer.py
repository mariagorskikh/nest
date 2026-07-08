import logging
from typing import Any

from nest_sdk import AgentId, Privacy, Trust

logger = logging.getLogger(__name__)


class TrustGatedPrivacy(Privacy):
    """
    Layer 11: Implements 'Differential Fidelity' masking.
    Redacts or blurs sensitive message fields based on the
    recipient's reputation score from Layer 6.
    """

    def __init__(self, trust: Trust, thresholds: dict[str, float] | None = None):
        self.trust = trust
        # Default thresholds: >0.8 (Full), >0.4 (Blurred), <0.4 (Redacted)
        self.thresholds = thresholds or {"high": 0.8, "med": 0.4}

    async def mask(self, data: dict[str, Any], recipient: AgentId) -> dict[str, Any]:
        """Decision engine: Trust Score -> Privacy Policy"""
        score: Any = await self.trust.score(recipient)
        masked = data.copy()

        # Sensitive keys we want to protect
        sensitive_keys = ["location", "internal_id", "inventory_count"]

        for key in sensitive_keys:
            if key not in masked:
                continue

            if score >= self.thresholds["high"]:
                continue  # Full fidelity for trusted peers

            if score >= self.thresholds["med"]:
                # Medium Trust: Blur the data
                masked[key] = f"BLURRED_{masked[key]}_ZONE"
            else:
                # Low Trust: Full Redaction
                masked[key] = "REDACTED"

        return masked

    async def unmask(self, data: dict[str, Any], sender: AgentId) -> dict[str, Any]:
        return data  # Pass-through for receiving

    def __repr__(self) -> str:
        return f"<TrustGatedPrivacy(thresholds={self.thresholds})>"
