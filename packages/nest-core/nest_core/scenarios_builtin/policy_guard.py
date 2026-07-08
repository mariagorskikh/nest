# SPDX-License-Identifier: Apache-2.0
"""Policy-guard scenario -- agents ask before risky actions.

The scenario injects five action requests into the configured ``policy`` layer:

* a safe public catalog read, which should be permitted;
* a public export containing sensitive data, which should be denied;
* a high-value payment, which should require approval;
* a payment with no declared amount, which should require approval;
* an undeclared administrative action, which should be denied by default.

Each request and decision is broadcast as canonical JSON so validators can check
the exact verdicts.  Running the same scenario with ``policy_plugin:
allow_all`` fails the adversarial validators, proving the checks distinguish a
real guard from a permissive placeholder.

Example::

    agents = policy_guard_factory(config, plugins)
"""

from __future__ import annotations

import json
from typing import Any

from nest_core.layers.policy import Policy, PolicyRequest
from nest_core.plugins import PluginRegistry
from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId

POLICY_TICK = b"POLICY_GUARD_EVAL"
"""Self-message payload that starts the policy evaluation."""

DEFAULT_POLICY_PLUGIN = "strict_rules"
"""Default policy plugin name for the policy guard scenario."""


class PolicyProbeAgent(StateMachineAgent):
    """Evaluate a fixed adversarial policy test set.

    Example::

        agent = PolicyProbeAgent(AgentId("auditor-0"), requests=[...])
    """

    def __init__(self, agent_id: AgentId, requests: list[tuple[str, PolicyRequest]]) -> None:
        self._id = agent_id
        self._requests = requests

    async def on_start(self, ctx: AgentContext) -> None:
        """Schedule the evaluation onto a non-zero deterministic tick.

        Example::

            await agent.on_start(ctx)
        """
        await ctx.schedule(1.0, POLICY_TICK)

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """On the evaluation tick, broadcast requests and policy decisions.

        Example::

            await agent.on_message(ctx, AgentId("auditor-0"), POLICY_TICK)
        """
        if sender != ctx.agent_id or payload != POLICY_TICK:
            return
        policy: Policy | None = ctx.plugins.get("policy")
        if policy is None:
            return
        for case_id, request in self._requests:
            await ctx.broadcast(_request_payload(case_id, request, ctx.time))
            decision = await policy.decide(request, now=ctx.time)
            await ctx.broadcast(
                _decision_payload(case_id, decision.model_dump(mode="json"), ctx.time)
            )


def _request_payload(case_id: str, request: PolicyRequest, now: float) -> bytes:
    """Return a canonical trace payload for a policy request.

    Example::

        payload = _request_payload("safe", request, 1.0)
    """
    obj: dict[str, Any] = {
        "policy": "request",
        "case": case_id,
        "request": request.model_dump(mode="json"),
        "ts": round(now, 6),
    }
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _decision_payload(case_id: str, decision: dict[str, Any], now: float) -> bytes:
    """Return a canonical trace payload for a policy decision.

    Example::

        payload = _decision_payload("safe", {"effect": "permit"}, 1.0)
    """
    obj: dict[str, Any] = {
        "policy": "decision",
        "case": case_id,
        "decision": decision,
        "ts": round(now, 6),
    }
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _default_requests(actor: AgentId) -> list[tuple[str, PolicyRequest]]:
    """Return the deterministic adversarial request set.

    Example::

        requests = _default_requests(AgentId("auditor-0"))
    """
    return [
        (
            "safe_public_read",
            PolicyRequest(
                actor=actor,
                action="read",
                resource="catalog/public",
                purpose="lookup public inventory",
            ),
        ),
        (
            "sensitive_public_export",
            PolicyRequest(
                actor=actor,
                action="publish",
                resource="web/public",
                data_classes=["pii.email"],
                purpose="post lead list to public web",
            ),
        ),
        (
            "high_value_payment",
            PolicyRequest(
                actor=actor,
                action="pay",
                resource="vendor/settlement",
                amount=900,
                purpose="settle large invoice",
            ),
        ),
        (
            "unknown_amount_payment",
            PolicyRequest(
                actor=actor,
                action="pay",
                resource="vendor/settlement",
                purpose="settle invoice without declared amount",
            ),
        ),
        (
            "unknown_admin_action",
            PolicyRequest(
                actor=actor,
                action="admin",
                resource="registry/root",
                purpose="change town root registry",
            ),
        ),
    ]


def policy_guard_factory(config: ScenarioConfig, plugins: dict[str, Any]) -> dict[AgentId, Any]:
    """Build the single-agent policy guard scenario.

    Example::

        agents = policy_guard_factory(config, plugins)
    """
    policy_name = str(config.task.config.get("policy_plugin", DEFAULT_POLICY_PLUGIN))
    policy_cls = PluginRegistry().resolve("policy", policy_name)
    plugins["policy"] = policy_cls()
    auditor = AgentId("policy-auditor-0")
    return {auditor: PolicyProbeAgent(auditor, _default_requests(auditor))}
