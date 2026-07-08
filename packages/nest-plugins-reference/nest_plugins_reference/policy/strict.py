# SPDX-License-Identifier: Apache-2.0
"""Strict reference policy for high-impact agent actions.

Example::

    policy = StrictPolicy()
    decision = await policy.decide(request, now=0.0)
"""

from __future__ import annotations

from nest_core.layers.policy import PolicyDecision, PolicyEffect, PolicyRequest

SENSITIVE_DATA_CLASSES = frozenset(
    {
        "pii.email",
        "pii.phone",
        "pii.address",
        "secret",
        "credential",
        "medical",
        "financial",
    }
)
"""Data classes that must not be published to public resources."""

PUBLIC_RESOURCES = frozenset({"web/public", "public_api", "external_web"})
"""Resources that leave the trusted town boundary."""

SAFE_READS = frozenset({("read", "catalog/public"), ("read", "docs/public")})
"""Low-risk reads allowed without additional approval."""

HIGH_IMPACT_ACTIONS = frozenset({"pay", "transfer", "delete"})
"""Actions that can spend, destroy, or change authority."""

DEFAULT_APPROVAL_THRESHOLD = 500
"""Spend threshold at which payment-like actions require approval."""


class StrictPolicy:
    """Small deterministic deny-by-default policy.

    The policy permits only declared low-risk reads, blocks sensitive data from
    public resources, requires approval for high-impact spend, and denies
    unknown actions.  The rules are intentionally simple so scenario validators
    can assert exact, replayable decisions.

    Example::

        policy = StrictPolicy(approval_threshold=1000)
    """

    def __init__(self, approval_threshold: int = DEFAULT_APPROVAL_THRESHOLD) -> None:
        self._approval_threshold = approval_threshold

    async def decide(self, request: PolicyRequest, *, now: float) -> PolicyDecision:
        """Return a deterministic decision for *request*.

        Example::

            decision = await policy.decide(request, now=5.0)
        """
        del now
        sensitive = sorted(set(request.data_classes) & SENSITIVE_DATA_CLASSES)
        if request.resource in PUBLIC_RESOURCES and sensitive:
            return PolicyDecision(
                effect=PolicyEffect.DENY,
                reason=f"public export contains sensitive data: {','.join(sensitive)}",
                rule_id="deny-sensitive-public-export",
                obligations=["remove_sensitive_data_or_use_private_channel"],
            )

        if request.action in {"pay", "transfer"}:
            amount = request.amount
            if amount is None:
                return PolicyDecision(
                    effect=PolicyEffect.APPROVAL_REQUIRED,
                    reason=f"{request.action} amount is unknown",
                    rule_id="approval-unknown-transfer-amount",
                    obligations=["declare_amount_before_autonomous_transfer"],
                )
            if amount > self._approval_threshold:
                return PolicyDecision(
                    effect=PolicyEffect.APPROVAL_REQUIRED,
                    reason=f"{request.action} amount {amount} exceeds approval threshold",
                    rule_id="approval-high-value-transfer",
                    obligations=["collect_human_or_owner_approval"],
                )
            return PolicyDecision(
                effect=PolicyEffect.PERMIT,
                reason="low-value transfer is within autonomous limit",
                rule_id="permit-low-value-transfer",
            )

        if request.action in HIGH_IMPACT_ACTIONS:
            return PolicyDecision(
                effect=PolicyEffect.APPROVAL_REQUIRED,
                reason=f"{request.action} is high impact",
                rule_id="approval-high-impact-action",
                obligations=["collect_human_or_owner_approval"],
            )

        if (request.action, request.resource) in SAFE_READS:
            return PolicyDecision(
                effect=PolicyEffect.PERMIT,
                reason="declared public read is allowed",
                rule_id="permit-safe-public-read",
            )

        return PolicyDecision(
            effect=PolicyEffect.DENY,
            reason=f"no rule permits {request.action} on {request.resource}",
            rule_id="deny-by-default",
        )
