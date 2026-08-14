# SPDX-License-Identifier: Apache-2.0
"""Deterministic capability registration, discovery, and fulfillment baseline."""

from __future__ import annotations

import hashlib
from typing import Any, cast

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, ScenarioAgentContext, StateMachineAgent
from nest_core.types import AgentCard, AgentId, Query

_PROVIDER = AgentId("provider-0")
_REQUESTER = AgentId("requester-0")
_LOOKUP = b"lookup:sell"
_REQUEST = b"buy:widget:2"
_RESPONSE = b"sold:widget:2"
_REGISTRY_IMPLEMENTATION = "nest_plugins_reference.registry.in_memory.InMemoryRegistry"


def _digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


class CapabilityProviderAgent(StateMachineAgent):
    """Reference provider that registers and fulfills the frozen fixture."""

    async def on_start(self, ctx: AgentContext) -> None:
        scenario_ctx = cast("ScenarioAgentContext", ctx)
        registry = ctx.plugins["registry"]
        await registry.register(
            AgentCard(agent_id=ctx.agent_id, name="Capability Provider", capabilities=["sell"])
        )
        scenario_ctx.record_scenario_event(
            kind="test.registry.provider_registered",
            observer="town.capability-requester",
            subject=str(ctx.agent_id),
            data={
                "registry_implementation": _REGISTRY_IMPLEMENTATION,
                "card_agent_id": "provider-0",
                "capabilities": ["sell"],
            },
        )

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        if sender != _REQUESTER or payload != _REQUEST:
            return
        scenario_ctx = cast("ScenarioAgentContext", ctx)
        correlation_id = await scenario_ctx.send_with_correlation(sender, _RESPONSE)
        scenario_ctx.record_scenario_event(
            kind="test.message.response_routed",
            observer="town.capability-requester",
            subject=str(ctx.agent_id),
            attributes={
                "message_id": "message-002",
                "correlation_id": str(correlation_id),
                "request_digest": _digest(_REQUEST),
                "response_digest": _digest(_RESPONSE),
            },
            data={
                "sender_id": "provider-0",
                "recipient_id": "requester-0",
                "media_type": "text/plain; charset=utf-8",
                "text": "sold:widget:2",
                "payload_digest": _digest(_RESPONSE),
            },
        )


class CapabilityRequesterAgent(StateMachineAgent):
    """Reference requester that sends only after real Registry discovery."""

    async def on_start(self, ctx: AgentContext) -> None:
        await ctx.schedule(0, _LOOKUP)

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        if sender == ctx.agent_id and payload == _LOOKUP:
            await self._discover_and_request(ctx)
            return
        if sender == _PROVIDER:
            self._evaluate_response(ctx, payload)

    async def _discover_and_request(self, ctx: AgentContext) -> None:
        scenario_ctx = cast("ScenarioAgentContext", ctx)
        registry = ctx.plugins["registry"]
        cards = await registry.lookup(Query(capabilities=["sell"]))
        scenario_ctx.record_scenario_event(
            kind="test.registry.lookup_requested",
            observer="town.capability-requester",
            subject="provider-0",
            data={
                "registry_implementation": _REGISTRY_IMPLEMENTATION,
                "capabilities": ["sell"],
            },
        )
        returned = scenario_ctx.record_scenario_event(
            kind="test.registry.lookup_returned",
            observer="town.capability-requester",
            subject="provider-0",
            data={
                "registry_implementation": _REGISTRY_IMPLEMENTATION,
                "card_agent_ids": [str(card.agent_id) for card in cards],
            },
        )
        selected = next((card for card in cards if card.agent_id == _PROVIDER), None)
        if selected is None:
            return
        lookup_event_id = None if returned is None else returned.event_id
        if lookup_event_id is not None:
            scenario_ctx.record_scenario_event(
                kind="test.requester.provider_selected",
                observer="town.capability-requester",
                subject="provider-0",
                data={
                    "selected_agent_id": "provider-0",
                    "lookup_event_id": lookup_event_id,
                },
            )
        correlation_id = await scenario_ctx.send_with_correlation(selected.agent_id, _REQUEST)
        scenario_ctx.record_scenario_event(
            kind="test.message.request_routed",
            observer="town.capability-requester",
            subject="provider-0",
            attributes={
                "message_id": "message-001",
                "correlation_id": str(correlation_id),
                "request_digest": _digest(_REQUEST),
            },
            data={
                "sender_id": "requester-0",
                "recipient_id": "provider-0",
                "media_type": "text/plain; charset=utf-8",
                "text": "buy:widget:2",
                "payload_digest": _digest(_REQUEST),
            },
        )

    def _evaluate_response(self, ctx: AgentContext, payload: bytes) -> None:
        scenario_ctx = cast("ScenarioAgentContext", ctx)
        actual_digest = _digest(payload)
        expected_digest = _digest(_RESPONSE)
        scenario_ctx.record_scenario_event(
            kind="test.capability.result_evaluated",
            observer="town.profile-evaluator",
            subject="provider-0",
            attributes={
                "message_id": "message-002",
                "response_digest": actual_digest,
            },
            data={
                "evaluator_id": "nanda.agent.capability-fulfillment",
                "evaluator_version": "1",
                "verdict": "pass" if payload == _RESPONSE else "fail",
                "expected_response_digest": expected_digest,
                "actual_response_digest": actual_digest,
            },
        )


def capability_fulfillment_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create the exact deterministic requester and provider participants."""
    registry = plugins.get("registry")
    if isinstance(registry, type):
        plugins["registry"] = registry()
    return {
        _REQUESTER: CapabilityRequesterAgent(),
        _PROVIDER: CapabilityProviderAgent(),
    }
