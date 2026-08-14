# SPDX-License-Identifier: Apache-2.0
"""Pure evidence evaluation for the frozen capability-fulfillment profile."""

from __future__ import annotations

import hashlib
from collections.abc import Sequence

from .capability_evidence import CapabilityObservationBase
from .capability_profile import CAPABILITY_REQUIRED_CHECKS
from .models import (
    ULID,
    CheckResult,
    DriverExchangeFailedObservation,
    IntentReturnedObservation,
    LookupRequestedObservation,
    LookupReturnedObservation,
    ProviderRegisteredObservation,
    ProviderSelectedObservation,
    RequestRoutedObservation,
    ResponseRoutedObservation,
    ResultEvaluatedObservation,
    RunAdmittedObservation,
    TestObservation,
)
from .profiles import ResolvedTestProfile, capability_profile_document

_REQUIRED_CHECKS = CAPABILITY_REQUIRED_CHECKS
_OBSERVER_BY_KIND = {
    "test.driver.run_admitted": "town.driven-agent",
    "test.driver.exchange_failed": "town.driven-agent",
    "test.registry.provider_registered": "town.driven-agent",
    "test.driver.intent_returned": "town.driven-agent",
    "test.message.response_routed": "town.driven-agent",
    "test.registry.lookup_requested": "town.capability-requester",
    "test.registry.lookup_returned": "town.capability-requester",
    "test.requester.provider_selected": "town.capability-requester",
    "test.message.request_routed": "town.capability-requester",
    "test.capability.result_evaluated": "town.profile-evaluator",
}


def _single[TEvent: CapabilityObservationBase](
    observations: Sequence[TestObservation], event_type: type[TEvent]
) -> TEvent | None:
    matches = [event for item in observations if isinstance((event := item.root), event_type)]
    return matches[0] if len(matches) == 1 else None


def _result(
    check_id: str,
    status: str,
    summary: str,
    evidence: Sequence[CapabilityObservationBase] = (),
) -> CheckResult:
    return CheckResult.model_validate(
        {
            "id": check_id,
            "required": True,
            "status": status,
            "summary": summary,
            "evidence_refs": [f"trace.jsonl#seq={event.seq}" for event in evidence],
        }
    )


def _trace_is_integral(
    observations: Sequence[TestObservation], run_id: ULID, profile_digest: str
) -> bool:
    events = [observation.root for observation in observations]
    sequences = [event.seq for event in events]
    event_ids = [event.event_id for event in events]
    kinds = [event.kind for event in events]
    return (
        sequences == list(range(1, len(events) + 1))
        and len(event_ids) == len(set(event_ids))
        and len(kinds) == len(set(kinds))
        and all(event.run_id == run_id for event in events)
        and all(event.subject_participant_id == "provider-0" for event in events)
        and all(event.observer == _OBSERVER_BY_KIND[event.kind] for event in events)
        and all(
            not isinstance(event, RunAdmittedObservation)
            or event.data.profile_digest == profile_digest
            for event in events
        )
    )


def _all_inconclusive() -> list[CheckResult]:
    return [
        _result(
            check_id,
            "inconclusive",
            (
                "Trace evidence is duplicate, missing, out of order, misattributed, "
                "or bound to another run/profile"
            ),
        )
        for check_id in _REQUIRED_CHECKS
    ]


def evaluate_capability_fulfillment(
    observations: Sequence[TestObservation],
    *,
    run_id: ULID,
    resolved_profile: ResolvedTestProfile,
) -> list[CheckResult]:
    """Return the five frozen required checks from validated trace observations."""
    profile = capability_profile_document(resolved_profile)
    if tuple(profile.evaluator.required_checks) != _REQUIRED_CHECKS:
        raise ValueError("profile required-check table is not the frozen evaluator table")
    if not _trace_is_integral(observations, run_id, resolved_profile.reference.digest):
        return _all_inconclusive()

    admitted = _single(observations, RunAdmittedObservation)
    failed = _single(observations, DriverExchangeFailedObservation)
    registered = _single(observations, ProviderRegisteredObservation)
    lookup_requested = _single(observations, LookupRequestedObservation)
    lookup_returned = _single(observations, LookupReturnedObservation)
    selected = _single(observations, ProviderSelectedObservation)
    request_routed = _single(observations, RequestRoutedObservation)
    intent_returned = _single(observations, IntentReturnedObservation)
    response_routed = _single(observations, ResponseRoutedObservation)
    evaluated = _single(observations, ResultEvaluatedObservation)

    driver = _driver_check(admitted, failed, request_routed, intent_returned)
    provider = _provider_check(admitted, failed, registered)
    discovery = _discovery_check(
        provider, lookup_requested, lookup_returned, selected, request_routed
    )
    request = _request_check(discovery, selected, request_routed)
    fulfillment = _fulfillment_check(
        request,
        failed,
        request_routed,
        intent_returned,
        response_routed,
        evaluated,
        expected_text=profile.fixture.expected_response.text,
    )
    return [driver, provider, discovery, request, fulfillment]


def _driver_check(
    admitted: RunAdmittedObservation | None,
    failed: DriverExchangeFailedObservation | None,
    request_routed: RequestRoutedObservation | None,
    intent_returned: IntentReturnedObservation | None,
) -> CheckResult:
    if failed is not None:
        status = {
            "driver_contract": "fail",
            "incomplete": "inconclusive",
            "town": "error",
        }[failed.data.disposition]
        return _result(
            _REQUIRED_CHECKS[0],
            status,
            "Driver exchange ended with a closed local failure classification",
            [failed],
        )
    if admitted is None:
        return _result(
            _REQUIRED_CHECKS[0], "inconclusive", "No driver admission evidence was observed"
        )
    if admitted.data.intent_kind == "none":
        return _result(
            _REQUIRED_CHECKS[0], "pass", "Driver returned one allowed start intent", [admitted]
        )
    if request_routed is None and intent_returned is None:
        return _result(
            _REQUIRED_CHECKS[0],
            "inconclusive",
            "Start passed but the required message exchange was not observed",
        )
    if intent_returned is None:
        return _result(
            _REQUIRED_CHECKS[0],
            "inconclusive",
            "The routed request has no bounded driver intent evidence",
        )
    if (
        admitted.data.adapter_instance_id != intent_returned.data.adapter_instance_id
        or intent_returned.data.driver_sequence != 1
        or admitted.seq >= intent_returned.seq
    ):
        return _result(
            _REQUIRED_CHECKS[0],
            "fail",
            "Driver instance or sequence continuity was violated",
            [admitted, intent_returned],
        )
    return _result(
        _REQUIRED_CHECKS[0],
        "pass",
        "Driver returned one allowed intent for each required exchange",
        [admitted, intent_returned],
    )


def _provider_check(
    admitted: RunAdmittedObservation | None,
    failed: DriverExchangeFailedObservation | None,
    registered: ProviderRegisteredObservation | None,
) -> CheckResult:
    if failed is not None and failed.data.stage == "start":
        return _result(
            _REQUIRED_CHECKS[1], "not_tested", "Registration depends on successful admission"
        )
    if admitted is None:
        return _result(
            _REQUIRED_CHECKS[1], "not_tested", "Registration was not reached without admission"
        )
    if admitted.data.intent_kind == "none":
        return _result(
            _REQUIRED_CHECKS[1],
            "fail",
            "The adapter declined to declare the required sell capability",
            [admitted],
        )
    if registered is None:
        return _result(
            _REQUIRED_CHECKS[1], "inconclusive", "Provider registration evidence is missing"
        )
    if admitted.seq >= registered.seq:
        return _result(
            _REQUIRED_CHECKS[1],
            "inconclusive",
            "Provider registration is not ordered after admission",
        )
    return _result(
        _REQUIRED_CHECKS[1],
        "pass",
        "The driven provider registered sell through the pinned Registry",
        [admitted, registered],
    )


def _discovery_check(
    provider: CheckResult,
    lookup_requested: LookupRequestedObservation | None,
    lookup_returned: LookupReturnedObservation | None,
    selected: ProviderSelectedObservation | None,
    request_routed: RequestRoutedObservation | None,
) -> CheckResult:
    if provider.status != "pass":
        return _result(
            _REQUIRED_CHECKS[2], "not_tested", "Discovery depends on provider registration"
        )
    evidence = [
        event for event in (lookup_requested, lookup_returned, selected) if event is not None
    ]
    if lookup_returned is not None and "provider-0" not in lookup_returned.data.card_agent_ids:
        return _result(
            _REQUIRED_CHECKS[2],
            "fail",
            "The pinned Registry lookup did not return provider-0",
            evidence,
        )
    complete = lookup_requested is not None and lookup_returned is not None and selected is not None
    if complete:
        assert lookup_requested is not None
        assert lookup_returned is not None
        assert selected is not None
        if (
            lookup_requested.seq < lookup_returned.seq < selected.seq
            and selected.data.lookup_event_id == lookup_returned.event_id
            and "provider-0" in lookup_returned.data.card_agent_ids
        ):
            return _result(
                _REQUIRED_CHECKS[2],
                "pass",
                "Requester selected provider-0 from the exact Registry lookup result",
                evidence,
            )
        return _result(
            _REQUIRED_CHECKS[2],
            "fail",
            "Discovery evidence is not causally linked to the selected provider",
            evidence,
        )
    if request_routed is not None:
        return _result(
            _REQUIRED_CHECKS[2],
            "fail",
            "A routed request cannot substitute for Registry discovery evidence",
            [request_routed],
        )
    return _result(_REQUIRED_CHECKS[2], "inconclusive", "Registry discovery evidence is incomplete")


def _request_check(
    discovery: CheckResult,
    selected: ProviderSelectedObservation | None,
    request_routed: RequestRoutedObservation | None,
) -> CheckResult:
    if discovery.status != "pass":
        return _result(
            _REQUIRED_CHECKS[3], "not_tested", "Request routing depends on proven discovery"
        )
    if selected is None or request_routed is None:
        return _result(_REQUIRED_CHECKS[3], "inconclusive", "Request routing evidence is missing")
    if selected.seq >= request_routed.seq:
        return _result(
            _REQUIRED_CHECKS[3],
            "inconclusive",
            "Request routing is not ordered after provider selection",
        )
    return _result(
        _REQUIRED_CHECKS[3],
        "pass",
        "The exact synthetic request used current simulator routing",
        [selected, request_routed],
    )


def _fulfillment_check(
    request: CheckResult,
    failed: DriverExchangeFailedObservation | None,
    request_routed: RequestRoutedObservation | None,
    intent_returned: IntentReturnedObservation | None,
    response_routed: ResponseRoutedObservation | None,
    evaluated: ResultEvaluatedObservation | None,
    *,
    expected_text: str,
) -> CheckResult:
    if failed is not None and failed.data.stage == "message":
        return _result(
            _REQUIRED_CHECKS[4],
            "not_tested",
            "Capability semantics were not evaluated after a driver exchange failure",
        )
    if request.status != "pass":
        return _result(
            _REQUIRED_CHECKS[4], "not_tested", "Fulfillment depends on proven request routing"
        )
    if request_routed is None or intent_returned is None:
        return _result(
            _REQUIRED_CHECKS[4], "inconclusive", "No bounded message intent was observed"
        )
    if intent_returned.data.intent_kind == "none":
        return _result(
            _REQUIRED_CHECKS[4],
            "fail",
            "The adapter returned none for the synthetic request",
            [intent_returned],
        )
    if response_routed is None or evaluated is None:
        return _result(_REQUIRED_CHECKS[4], "inconclusive", "Fulfillment evidence is incomplete")
    expected_digest = "sha256:" + hashlib.sha256(expected_text.encode()).hexdigest()
    evidence: list[CapabilityObservationBase] = [
        request_routed,
        intent_returned,
        response_routed,
        evaluated,
    ]
    if not (
        request_routed.seq < intent_returned.seq < response_routed.seq < evaluated.seq
        and request_routed.message_id == "message-001"
        and intent_returned.message_id == request_routed.message_id
        and request_routed.correlation_id is not None
        and request_routed.request_digest == request_routed.data.payload_digest
        and response_routed.message_id == "message-002"
        and response_routed.correlation_id is not None
        and response_routed.request_digest == request_routed.data.payload_digest
        and response_routed.response_digest == response_routed.data.payload_digest
        and evaluated.message_id == response_routed.message_id
        and evaluated.response_digest == evaluated.data.actual_response_digest
        and evaluated.data.expected_response_digest == expected_digest
        and evaluated.data.actual_response_digest == response_routed.data.payload_digest
    ):
        return _result(
            _REQUIRED_CHECKS[4],
            "inconclusive",
            "Response and evaluation evidence are not causally or digest linked",
        )
    if response_routed.data.text != expected_text or evaluated.data.verdict != "pass":
        return _result(
            _REQUIRED_CHECKS[4],
            "fail",
            "The routed response did not equal the exact synthetic fulfillment",
            evidence,
        )
    return _result(
        _REQUIRED_CHECKS[4],
        "pass",
        "Requester observed the exact synthetic fulfillment",
        evidence,
    )
