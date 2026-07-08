# SPDX-License-Identifier: Apache-2.0
"""Permissive policy baseline used as a validator foil.

Example::

    policy = AllowAllPolicy()
    decision = await policy.decide(request, now=0.0)
"""

from __future__ import annotations

from nest_core.layers.policy import PolicyDecision, PolicyEffect, PolicyRequest


class AllowAllPolicy:
    """Permit every action.

    This is useful as a deliberately unsafe baseline: the policy scenario's
    validators should fail when this plugin is selected, proving that the checks
    catch more than message flow.

    Example::

        policy = AllowAllPolicy()
    """

    async def decide(self, request: PolicyRequest, *, now: float) -> PolicyDecision:
        """Return ``permit`` for every request.

        Example::

            decision = await policy.decide(request, now=1.0)
        """
        return PolicyDecision(
            effect=PolicyEffect.PERMIT,
            reason="baseline permits every request",
            rule_id="allow-all",
        )
