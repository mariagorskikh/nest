# SPDX-License-Identifier: Apache-2.0
"""Capability-profile evidence payloads and its concrete observation codec."""

from __future__ import annotations

import hashlib
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator

from .contracts import (
    ULID,
    AdapterInstanceId,
    DiagnosticCode,
    Digest,
    SafeId,
    SafeText4096,
    StrictModel,
)
from .evidence import ObservationBase, TestObservationEnvelope


class CapabilityObservationBase(
    ObservationBase[
        Literal[
            "town.agent-test-runner",
            "town.capability-requester",
            "town.driven-agent",
            "town.profile-evaluator",
        ]
    ]
):
    """Capability profile's closed observer set."""


class RunAdmittedData(StrictModel):
    adapter_instance_id: AdapterInstanceId
    profile_digest: Digest
    driver_sequence: Literal[0]
    intent_kind: Literal["declare_capability", "none"]


class DriverExchangeFailedData(StrictModel):
    stage: Literal["readiness", "start", "message"]
    disposition: Literal["driver_contract", "incomplete", "town"]
    error_code: DiagnosticCode
    driver_event_id: ULID | None
    driver_sequence: int | None = Field(ge=0)


class ProviderRegisteredData(StrictModel):
    registry_implementation: Literal["nest_plugins_reference.registry.in_memory.InMemoryRegistry"]
    card_agent_id: Literal["provider-0"]
    capabilities: list[Literal["sell"]] = Field(min_length=1, max_length=1)


class LookupRequestedData(StrictModel):
    registry_implementation: Literal["nest_plugins_reference.registry.in_memory.InMemoryRegistry"]
    capabilities: list[Literal["sell"]] = Field(min_length=1, max_length=1)


class LookupReturnedData(StrictModel):
    registry_implementation: Literal["nest_plugins_reference.registry.in_memory.InMemoryRegistry"]
    card_agent_ids: list[SafeId] = Field(max_length=64)


class ProviderSelectedData(StrictModel):
    selected_agent_id: Literal["provider-0"]
    lookup_event_id: ULID


class RequestRoutedData(StrictModel):
    sender_id: Literal["requester-0"]
    recipient_id: Literal["provider-0"]
    media_type: Literal["text/plain; charset=utf-8"]
    text: Literal["buy:widget:2"]
    payload_digest: Digest

    @model_validator(mode="after")
    def _exact_payload_digest(self) -> RequestRoutedData:
        expected = "sha256:" + hashlib.sha256(self.text.encode("utf-8")).hexdigest()
        if self.payload_digest != expected:
            raise ValueError("payload_digest must match exact UTF-8 text")
        return self


class IntentReturnedData(StrictModel):
    adapter_instance_id: AdapterInstanceId
    driver_event_id: ULID
    driver_sequence: Literal[1]
    intent_kind: Literal["send_to_sender", "none"]


class ResponseRoutedData(StrictModel):
    sender_id: Literal["provider-0"]
    recipient_id: Literal["requester-0"]
    media_type: Literal["text/plain; charset=utf-8"]
    text: SafeText4096
    payload_digest: Digest

    @field_validator("text")
    @classmethod
    def _profile_message_byte_limit(cls, value: str) -> str:
        if len(value.encode("utf-8")) > 4096:
            raise ValueError("text exceeds the profile UTF-8 byte limit")
        return value

    @model_validator(mode="after")
    def _exact_payload_digest(self) -> ResponseRoutedData:
        expected = "sha256:" + hashlib.sha256(self.text.encode("utf-8")).hexdigest()
        if self.payload_digest != expected:
            raise ValueError("payload_digest must match exact UTF-8 text")
        return self


class ResultEvaluatedData(StrictModel):
    evaluator_id: Literal["nanda.agent.capability-fulfillment"]
    evaluator_version: Literal["1"]
    verdict: Literal["pass", "fail", "inconclusive"]
    expected_response_digest: Digest
    actual_response_digest: Digest | None


class RunAdmittedObservation(CapabilityObservationBase):
    kind: Literal["test.driver.run_admitted"]
    data: RunAdmittedData


class DriverExchangeFailedObservation(CapabilityObservationBase):
    kind: Literal["test.driver.exchange_failed"]
    data: DriverExchangeFailedData


class ProviderRegisteredObservation(CapabilityObservationBase):
    kind: Literal["test.registry.provider_registered"]
    data: ProviderRegisteredData


class LookupRequestedObservation(CapabilityObservationBase):
    kind: Literal["test.registry.lookup_requested"]
    data: LookupRequestedData


class LookupReturnedObservation(CapabilityObservationBase):
    kind: Literal["test.registry.lookup_returned"]
    data: LookupReturnedData


class ProviderSelectedObservation(CapabilityObservationBase):
    kind: Literal["test.requester.provider_selected"]
    data: ProviderSelectedData


class RequestRoutedObservation(CapabilityObservationBase):
    kind: Literal["test.message.request_routed"]
    data: RequestRoutedData


class IntentReturnedObservation(CapabilityObservationBase):
    kind: Literal["test.driver.intent_returned"]
    data: IntentReturnedData


class ResponseRoutedObservation(CapabilityObservationBase):
    kind: Literal["test.message.response_routed"]
    data: ResponseRoutedData


class ResultEvaluatedObservation(CapabilityObservationBase):
    kind: Literal["test.capability.result_evaluated"]
    data: ResultEvaluatedData


ObservationVariant = Annotated[
    RunAdmittedObservation
    | DriverExchangeFailedObservation
    | ProviderRegisteredObservation
    | LookupRequestedObservation
    | LookupReturnedObservation
    | ProviderSelectedObservation
    | RequestRoutedObservation
    | IntentReturnedObservation
    | ResponseRoutedObservation
    | ResultEvaluatedObservation,
    Field(discriminator="kind"),
]


class CapabilityTestObservation(TestObservationEnvelope[ObservationVariant]):
    """One discriminated, closed capability-profile trace observation."""

    __test__ = False
