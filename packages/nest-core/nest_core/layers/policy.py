# SPDX-License-Identifier: Apache-2.0
"""Policy layer interface: deterministic action decisions for agent tools.

Agents need a small, replayable gate before they call tools, spend money, or
publish data outside the town.  A policy implementation receives a structured
request and returns one of three effects:

* ``permit`` -- the action may proceed.
* ``deny`` -- the action must not be attempted.
* ``approval_required`` -- the action is allowed only after an external approval.

The request is plain data and every decision takes ``now`` as a keyword-only
argument, so policy checks remain deterministic under simulator replay.

Example::

    request = PolicyRequest(actor=AgentId("a1"), action="read", resource="catalog/public")
    decision = await policy.decide(request, now=ctx.time)
"""

from __future__ import annotations

import enum
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, Field

from nest_core.types import AgentId


class PolicyEffect(enum.StrEnum):
    """Result of a policy decision.

    Example::

        effect = PolicyEffect.PERMIT
    """

    PERMIT = "permit"
    DENY = "deny"
    APPROVAL_REQUIRED = "approval_required"


class PolicyRequest(BaseModel):
    """A structured action an agent wants to perform.

    ``data_classes`` names the kinds of data leaving the agent, if any.  ``amount``
    captures high-impact spend or transfer operations.  ``metadata`` is reserved
    for policy-specific context while keeping the core interface stable.

    Example::

        req = PolicyRequest(
            actor=AgentId("researcher-0"),
            action="publish",
            resource="web/public",
            data_classes=["pii.email"],
        )
    """

    actor: AgentId
    action: str
    resource: str
    data_classes: list[str] = Field(default_factory=list)
    amount: int | None = None
    purpose: str = ""
    metadata: dict[str, str] = Field(default_factory=dict)


class PolicyDecision(BaseModel):
    """The replayable verdict for one :class:`PolicyRequest`.

    Example::

        decision = PolicyDecision(
            effect=PolicyEffect.DENY,
            reason="public export contains sensitive data",
            rule_id="deny-sensitive-public-export",
        )
    """

    effect: PolicyEffect
    reason: str
    rule_id: str
    obligations: list[str] = Field(default_factory=list)


@runtime_checkable
class Policy(Protocol):
    """Decision oracle for agent actions.

    Example::

        policy: Policy = StrictPolicy()
        decision = await policy.decide(request, now=ctx.time)
    """

    async def decide(self, request: PolicyRequest, *, now: float) -> PolicyDecision:
        """Return the policy decision for *request* at logical time *now*.

        Example::

            decision = await policy.decide(request, now=10.0)
        """
        ...
