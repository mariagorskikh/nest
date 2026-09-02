# SPDX-License-Identifier: Apache-2.0
"""Transport-neutral simulator participant controlled by one AgentDriver."""

from __future__ import annotations

import hashlib
import math
from collections.abc import Callable
from typing import Literal, cast

from pydantic import ValidationError

from nest_core.sim.agent import AgentContext, ScenarioAgentContext, StateMachineAgent
from nest_core.types import AgentCard, AgentId

from .capability_profile import CapabilityParticipant
from .driver import (
    AgentDriver,
    AgentDriverError,
    DriverCompatibilityError,
    DriverConfigurationError,
    DriverContractError,
    DriverFailureDisposition,
    DriverIncompleteError,
    TownDriverError,
)
from .ids import new_ulid
from .models import (
    ULID,
    DeclareCapabilityIntent,
    DriverMessage,
    DriverReadiness,
    DriverRequest,
    DriverResponse,
    MessageDriverObservation,
    SendToSenderIntent,
    StartDriverObservation,
    StopDriverObservation,
)
from .profile_codecs import BoundProfileCodec
from .profiles import (
    ResolvedTestProfile,
    capability_profile_document,
    capability_profile_reference,
)


def _logical_time(value: float) -> int:
    if not math.isfinite(value) or value < 0 or not value.is_integer():
        raise TownDriverError("INVALID_LOGICAL_TIME")
    return int(value)


def _request_digest(request: DriverRequest) -> str:
    return "sha256:" + hashlib.sha256(request.model_dump_json().encode()).hexdigest()


def _payload_digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _validate_response(
    request: DriverRequest,
    response: DriverResponse,
    adapter_instance_id: str,
    profile_codec: BoundProfileCodec,
) -> DriverResponse:
    try:
        validated = cast(
            "DriverResponse",
            profile_codec.validate_response(response.model_dump(mode="json")),
        )
    except (AttributeError, ValidationError, ValueError):
        raise DriverContractError("MALFORMED_RESPONSE") from None
    if validated.adapter_instance_id != adapter_instance_id:
        raise DriverIncompleteError("ADAPTER_INSTANCE_CHANGED")
    if (
        validated.run_id != request.run_id
        or validated.event_id != request.event_id
        or validated.sequence != request.sequence
        or validated.request_digest != _request_digest(request)
    ):
        raise DriverContractError("RESPONSE_MISMATCH")
    if validated.intent.kind not in request.observation.allowed_intents:
        raise DriverContractError("INTENT_NOT_ALLOWED")
    return validated


def _failure_disposition(error: AgentDriverError) -> str:
    if error.disposition == DriverFailureDisposition.CONTRACT:
        return "driver_contract"
    if error.disposition == DriverFailureDisposition.INCOMPLETE:
        return "incomplete"
    return "town"


class DrivenAgent(StateMachineAgent):
    """One profile-bound provider whose permitted actions come from an AgentDriver."""

    def __init__(
        self,
        *,
        driver: AgentDriver,
        run_id: ULID,
        resolved_profile: ResolvedTestProfile,
        readiness: DriverReadiness,
        event_id_factory: Callable[[], str] | None = None,
    ) -> None:
        self._driver = driver
        self._run_id = run_id
        self._resolved_profile = resolved_profile
        self._readiness = readiness
        self._event_id_factory = event_id_factory or new_ulid
        self._start_request: DriverRequest | None = None
        self._start_response: DriverResponse | None = None
        self._start_applied = False
        self._capability_declared = False
        self._message_request: DriverRequest | None = None
        self._message_response: DriverResponse | None = None
        self._message_applied = False
        self._admitted = False
        self._last_logical_time = 0
        self._stop_attempted = False
        self._driver_event_ids: set[str] = set()

    @property
    def admitted(self) -> bool:
        """Whether a valid start response bound the adapter to this run."""
        return self._admitted

    @property
    def logical_time_end(self) -> int:
        """Last validated integral Town logical time observed by this participant."""
        return self._last_logical_time

    def _new_driver_event_id(self) -> str:
        event_id = self._event_id_factory()
        if event_id in self._driver_event_ids:
            raise TownDriverError("EVENT_CONFLICT")
        self._driver_event_ids.add(event_id)
        return event_id

    async def on_start(self, ctx: AgentContext) -> None:
        """Admit the run and register only a capability declared by the driver."""
        profile = capability_profile_document(self._resolved_profile)
        if str(ctx.agent_id) != profile.scenario.subject_participant_id:
            raise TownDriverError("PARTICIPANT_MISMATCH")
        self._last_logical_time = _logical_time(ctx.time)
        request = self._start_request
        if request is None:
            request = DriverRequest(
                schema_version="town-agent-driver/1",
                run_id=self._run_id,
                event_id=self._new_driver_event_id(),
                sequence=0,
                participant=CapabilityParticipant(id="provider-0", role="provider"),
                profile=capability_profile_reference(self._resolved_profile),
                observation=StartDriverObservation(
                    kind="start",
                    logical_time=self._last_logical_time,
                    allowed_intents=["declare_capability", "none"],
                ),
            )
            self._start_request = request
        elif (
            request.observation.kind != "start"
            or request.observation.logical_time != self._last_logical_time
        ):
            raise TownDriverError("EVENT_CONFLICT")
        try:
            response = _validate_response(
                request,
                await self._driver.decide(request),
                self._readiness.ready.adapter_instance_id,
                self._resolved_profile.codec,
            )
            self._require_same_response(self._start_response, response)
        except (DriverConfigurationError, DriverCompatibilityError):
            raise
        except AgentDriverError as error:
            self._record_exchange_failure(ctx, stage="start", request=request, error=error)
            raise
        if self._start_applied:
            return
        self._start_response = response
        self._admitted = True
        scenario_ctx = cast("ScenarioAgentContext", ctx)
        scenario_ctx.record_scenario_event(
            kind="test.driver.run_admitted",
            observer="town.driven-agent",
            subject=str(ctx.agent_id),
            attributes={"request_digest": _request_digest(request)},
            data={
                "adapter_instance_id": self._readiness.ready.adapter_instance_id,
                "profile_digest": self._resolved_profile.reference.digest,
                "driver_sequence": 0,
                "intent_kind": response.intent.kind,
            },
        )
        if not isinstance(response.intent, DeclareCapabilityIntent):
            self._start_applied = True
            return
        registry = ctx.plugins["registry"]
        await registry.register(
            AgentCard(
                agent_id=ctx.agent_id,
                name="Driven Capability Provider",
                capabilities=["sell"],
            )
        )
        scenario_ctx.record_scenario_event(
            kind="test.registry.provider_registered",
            observer="town.driven-agent",
            subject=str(ctx.agent_id),
            data={
                "registry_implementation": (
                    "nest_plugins_reference.registry.in_memory.InMemoryRegistry"
                ),
                "card_agent_id": "provider-0",
                "capabilities": ["sell"],
            },
        )
        self._capability_declared = True
        self._start_applied = True

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Ask the driver for one intent, then apply it through simulator routing."""
        if not self._start_applied or not self._capability_declared:
            raise TownDriverError("START_REQUIRED")
        self._last_logical_time = _logical_time(ctx.time)
        if str(sender) != "requester-0" or payload != b"buy:widget:2":
            raise TownDriverError("MESSAGE_MISMATCH")
        request = self._message_request
        if request is None:
            request = DriverRequest(
                schema_version="town-agent-driver/1",
                run_id=self._run_id,
                event_id=self._new_driver_event_id(),
                sequence=1,
                participant=CapabilityParticipant(id="provider-0", role="provider"),
                profile=capability_profile_reference(self._resolved_profile),
                observation=MessageDriverObservation(
                    kind="message",
                    logical_time=self._last_logical_time,
                    allowed_intents=["send_to_sender", "none"],
                    message=DriverMessage(
                        id="message-001",
                        sender_id="requester-0",
                        media_type="text/plain; charset=utf-8",
                        text="buy:widget:2",
                    ),
                ),
            )
            self._message_request = request
        elif (
            request.observation.kind != "message"
            or request.observation.logical_time != self._last_logical_time
            or request.observation.message.sender_id != str(sender)
            or request.observation.message.text.encode("utf-8") != payload
        ):
            raise TownDriverError("EVENT_CONFLICT")
        try:
            response = _validate_response(
                request,
                await self._driver.decide(request),
                self._readiness.ready.adapter_instance_id,
                self._resolved_profile.codec,
            )
            self._require_same_response(self._message_response, response)
        except AgentDriverError as error:
            self._record_exchange_failure(ctx, stage="message", request=request, error=error)
            raise
        if self._message_applied:
            return
        self._message_response = response
        scenario_ctx = cast("ScenarioAgentContext", ctx)
        scenario_ctx.record_scenario_event(
            kind="test.driver.intent_returned",
            observer="town.driven-agent",
            subject=str(ctx.agent_id),
            attributes={
                "message_id": "message-001",
                "request_digest": _request_digest(request),
            },
            data={
                "adapter_instance_id": self._readiness.ready.adapter_instance_id,
                "driver_event_id": request.event_id,
                "driver_sequence": 1,
                "intent_kind": response.intent.kind,
            },
        )
        if not isinstance(response.intent, SendToSenderIntent):
            self._message_applied = True
            return
        routed = response.intent.text.encode("utf-8")
        correlation_id = await scenario_ctx.send_with_correlation(sender, routed)
        scenario_ctx.record_scenario_event(
            kind="test.message.response_routed",
            observer="town.driven-agent",
            subject=str(ctx.agent_id),
            attributes={
                "message_id": "message-002",
                "correlation_id": str(correlation_id),
                "request_digest": _payload_digest(payload),
                "response_digest": _payload_digest(routed),
            },
            data={
                "sender_id": "provider-0",
                "recipient_id": "requester-0",
                "media_type": "text/plain; charset=utf-8",
                "text": response.intent.text,
                "payload_digest": _payload_digest(routed),
            },
        )
        self._message_applied = True

    async def on_stop(self, ctx: AgentContext) -> None:
        """Capture terminal Town time without performing driver or transport I/O."""
        self._last_logical_time = _logical_time(ctx.time)

    async def best_effort_stop(
        self,
        reason: Literal["run_complete", "run_failed", "run_incomplete", "user_interrupted"],
    ) -> None:
        """Send the outer-owned stop observation once after successful admission."""
        if not self._admitted or self._stop_attempted:
            return
        self._stop_attempted = True
        sequence = 2 if self._message_request is not None else 1
        try:
            request = DriverRequest(
                schema_version="town-agent-driver/1",
                run_id=self._run_id,
                event_id=self._new_driver_event_id(),
                sequence=sequence,
                participant=CapabilityParticipant(id="provider-0", role="provider"),
                profile=capability_profile_reference(self._resolved_profile),
                observation=StopDriverObservation(
                    kind="stop",
                    logical_time=self._last_logical_time,
                    allowed_intents=["none"],
                    reason=reason,
                ),
            )
            _validate_response(
                request,
                await self._driver.decide(request),
                self._readiness.ready.adapter_instance_id,
                self._resolved_profile.codec,
            )
        except BaseException:
            return

    @staticmethod
    def _require_same_response(previous: DriverResponse | None, response: DriverResponse) -> None:
        if previous is not None and previous != response:
            raise DriverContractError("EVENT_CONFLICT")

    @staticmethod
    def _record_exchange_failure(
        ctx: AgentContext,
        *,
        stage: str,
        request: DriverRequest,
        error: AgentDriverError,
    ) -> None:
        scenario_ctx = cast("ScenarioAgentContext", ctx)
        scenario_ctx.record_scenario_event(
            kind="test.driver.exchange_failed",
            observer="town.driven-agent",
            subject=str(ctx.agent_id),
            attributes={"request_digest": _request_digest(request)},
            data={
                "stage": stage,
                "disposition": _failure_disposition(error),
                "error_code": error.code,
                "driver_event_id": request.event_id,
                "driver_sequence": request.sequence,
            },
        )
