# SPDX-License-Identifier: Apache-2.0
"""Profile-owned construction and serialization of agent-test observations."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import cast

from nest_core.sim.agent import ScenarioEventReceipt, ScenarioEventRequest

from .ids import new_ulid
from .models import ULID, ProfileReference, SafeId, TestObservation
from .profiles import ResolvedTestProfile, capability_profile_document

_OBSERVATION_ATTRIBUTES = frozenset(
    {
        "duration_ms",
        "message_id",
        "correlation_id",
        "request_digest",
        "response_digest",
    }
)


class AgentTestRuntime:
    """Run-scoped recorder for closed, profile-owned test observations."""

    def __init__(
        self,
        *,
        run_id: ULID,
        resolved_profile: ResolvedTestProfile,
        event_id_factory: Callable[[], str] | None = None,
        observed_at: Callable[[], datetime] | None = None,
    ) -> None:
        self.run_id = run_id
        profile_document = capability_profile_document(resolved_profile)
        self.subject_participant_id: SafeId = profile_document.scenario.subject_participant_id
        self.profile: ProfileReference = resolved_profile.reference
        self._codec = resolved_profile.codec
        self._event_id_factory = event_id_factory or new_ulid
        self._observed_at = observed_at or (lambda: datetime.now(UTC))
        self._observations: list[TestObservation] = []

    @property
    def observations(self) -> tuple[TestObservation, ...]:
        """Return validated observations in their global sequence order."""
        return tuple(self._observations)

    def record(self, request: ScenarioEventRequest) -> ScenarioEventReceipt:
        """Validate and sequence one generic request into a traceable observation."""
        attributes = dict(request.attributes)
        unknown_attributes = set(attributes) - _OBSERVATION_ATTRIBUTES
        if unknown_attributes:
            names = ", ".join(sorted(unknown_attributes))
            raise ValueError(f"unsupported agent-test observation attributes: {names}")
        observed_at = self._observed_at()
        if observed_at.tzinfo is None:
            raise ValueError("observed_at must be timezone-aware")
        timestamp = observed_at.astimezone(UTC).isoformat().replace("+00:00", "Z")
        observation = cast(
            "TestObservation",
            self._codec.validate_observation(
                {
                    "schema_version": "town.test-observation/1",
                    "seq": len(self._observations) + 1,
                    "event_id": self._event_id_factory(),
                    "run_id": self.run_id,
                    "kind": request.kind,
                    "logical_time": request.logical_time,
                    "observed_at": timestamp,
                    "duration_ms": attributes.get("duration_ms"),
                    "observer": request.observer,
                    "subject_participant_id": request.subject,
                    "message_id": attributes.get("message_id"),
                    "correlation_id": attributes.get("correlation_id"),
                    "request_digest": attributes.get("request_digest"),
                    "response_digest": attributes.get("response_digest"),
                    "data": dict(request.data),
                }
            ),
        )
        self._observations.append(observation)
        trace_record = observation.model_dump(mode="json")
        return ScenarioEventReceipt(
            event_id=observation.root.event_id,
            trace_record=trace_record,
        )
