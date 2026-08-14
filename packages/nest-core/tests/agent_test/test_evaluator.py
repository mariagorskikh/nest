# SPDX-License-Identifier: Apache-2.0
"""Pure evidence-table tests for capability-fulfillment evaluation."""

from __future__ import annotations

import hashlib
from typing import Any

import pytest
from nest_core.agent_test.evaluator import evaluate_capability_fulfillment
from nest_core.agent_test.models import TestObservation
from nest_core.agent_test.profiles import resolve_test_profile

RUN_ID = "01K00000000000000000000001"
REGISTRY = "nest_plugins_reference.registry.in_memory.InMemoryRegistry"
OBSERVER_BY_KIND = {
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


def _digest(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()


def _event_id(sequence: int) -> str:
    return f"01K000000000000000000000{sequence + 1:02d}"


def _observation(sequence: int, kind: str, data: dict[str, Any]) -> TestObservation:
    return TestObservation.model_validate(
        {
            "schema_version": "town.test-observation/1",
            "seq": sequence,
            "event_id": _event_id(sequence),
            "run_id": RUN_ID,
            "kind": kind,
            "logical_time": 0.0,
            "observed_at": "2026-08-13T12:00:00Z",
            "duration_ms": None,
            "observer": OBSERVER_BY_KIND[kind],
            "subject_participant_id": "provider-0",
            "message_id": {
                "test.message.request_routed": "message-001",
                "test.driver.intent_returned": "message-001",
                "test.message.response_routed": "message-002",
                "test.capability.result_evaluated": "message-002",
            }.get(kind),
            "correlation_id": (
                "corr-1"
                if kind in {"test.message.request_routed", "test.message.response_routed"}
                else None
            ),
            "request_digest": (
                _digest("buy:widget:2")
                if kind in {"test.message.request_routed", "test.message.response_routed"}
                else None
            ),
            "response_digest": (
                _digest("sold:widget:2")
                if kind in {"test.message.response_routed", "test.capability.result_evaluated"}
                else None
            ),
            "data": data,
        }
    )


def _passing_observations() -> list[TestObservation]:
    return [
        _observation(
            1,
            "test.driver.run_admitted",
            {
                "adapter_instance_id": "adapter:dev",
                "profile_digest": resolve_test_profile("capability-fulfillment").reference.digest,
                "driver_sequence": 0,
                "intent_kind": "declare_capability",
            },
        ),
        _observation(
            2,
            "test.registry.provider_registered",
            {
                "registry_implementation": REGISTRY,
                "card_agent_id": "provider-0",
                "capabilities": ["sell"],
            },
        ),
        _observation(
            3,
            "test.registry.lookup_requested",
            {"registry_implementation": REGISTRY, "capabilities": ["sell"]},
        ),
        _observation(
            4,
            "test.registry.lookup_returned",
            {"registry_implementation": REGISTRY, "card_agent_ids": ["provider-0"]},
        ),
        _observation(
            5,
            "test.requester.provider_selected",
            {"selected_agent_id": "provider-0", "lookup_event_id": _event_id(4)},
        ),
        _observation(
            6,
            "test.message.request_routed",
            {
                "sender_id": "requester-0",
                "recipient_id": "provider-0",
                "media_type": "text/plain; charset=utf-8",
                "text": "buy:widget:2",
                "payload_digest": _digest("buy:widget:2"),
            },
        ),
        _observation(
            7,
            "test.driver.intent_returned",
            {
                "adapter_instance_id": "adapter:dev",
                "driver_event_id": "01K00000000000000000000021",
                "driver_sequence": 1,
                "intent_kind": "send_to_sender",
            },
        ),
        _observation(
            8,
            "test.message.response_routed",
            {
                "sender_id": "provider-0",
                "recipient_id": "requester-0",
                "media_type": "text/plain; charset=utf-8",
                "text": "sold:widget:2",
                "payload_digest": _digest("sold:widget:2"),
            },
        ),
        _observation(
            9,
            "test.capability.result_evaluated",
            {
                "evaluator_id": "nanda.agent.capability-fulfillment",
                "evaluator_version": "1",
                "verdict": "pass",
                "expected_response_digest": _digest("sold:widget:2"),
                "actual_response_digest": _digest("sold:widget:2"),
            },
        ),
    ]


def test_five_required_checks_pass_only_from_ordered_real_path_evidence() -> None:
    """Removing or reordering any real-path stage prevents the five-check PASS table."""
    checks = evaluate_capability_fulfillment(
        _passing_observations(),
        run_id=RUN_ID,
        resolved_profile=resolve_test_profile("capability-fulfillment"),
    )

    assert [(check.id, check.required, check.status) for check in checks] == [
        ("driver.contract", True, "pass"),
        ("registry.provider-registered", True, "pass"),
        ("registry.provider-discovered", True, "pass"),
        ("delivery.request-routed", True, "pass"),
        ("capability.synthetic-request-fulfilled", True, "pass"),
    ]
    assert [check.evidence_refs for check in checks] == [
        ["trace.jsonl#seq=1", "trace.jsonl#seq=7"],
        ["trace.jsonl#seq=1", "trace.jsonl#seq=2"],
        ["trace.jsonl#seq=3", "trace.jsonl#seq=4", "trace.jsonl#seq=5"],
        ["trace.jsonl#seq=5", "trace.jsonl#seq=6"],
        [
            "trace.jsonl#seq=6",
            "trace.jsonl#seq=7",
            "trace.jsonl#seq=8",
            "trace.jsonl#seq=9",
        ],
    ]


def _statuses(observations: list[TestObservation]) -> list[str]:
    return [
        check.status
        for check in evaluate_capability_fulfillment(
            observations,
            run_id=RUN_ID,
            resolved_profile=resolve_test_profile("capability-fulfillment"),
        )
    ]


def _driver_failure(
    *, stage: str, disposition: str, error_code: str = "MALFORMED_RESPONSE"
) -> TestObservation:
    return _observation(
        1,
        "test.driver.exchange_failed",
        {
            "stage": stage,
            "disposition": disposition,
            "error_code": error_code,
            "driver_event_id": "01K00000000000000000000021",
            "driver_sequence": 0 if stage == "start" else 1,
        },
    )


def test_start_none_is_semantic_registration_failure_with_downstream_not_tested() -> None:
    """A valid refusal is conclusive without pretending discovery or delivery ran."""
    observations = _passing_observations()[:1]
    admitted = observations[0].root
    observations[0] = TestObservation.model_validate(
        {
            **admitted.model_dump(mode="json"),
            "data": {**admitted.data.model_dump(mode="json"), "intent_kind": "none"},
        }
    )

    assert _statuses(observations) == [
        "pass",
        "fail",
        "not_tested",
        "not_tested",
        "not_tested",
    ]


def test_start_driver_contract_failure_is_conclusive_and_stops_causal_checks() -> None:
    """Malformed authenticated adapter output fails its check, not the synthetic task."""
    assert _statuses([_driver_failure(stage="start", disposition="driver_contract")]) == [
        "fail",
        "not_tested",
        "not_tested",
        "not_tested",
        "not_tested",
    ]


def test_transport_loss_is_inconclusive_and_stops_causal_checks() -> None:
    """Timeout/loss cannot become a semantic failure or a false downstream pass."""
    assert _statuses(
        [_driver_failure(stage="start", disposition="incomplete", error_code="TIMEOUT")]
    ) == [
        "inconclusive",
        "not_tested",
        "not_tested",
        "not_tested",
        "not_tested",
    ]


def test_direct_addressing_without_linked_lookup_cannot_pass_discovery() -> None:
    """A routed request is evidence of delivery, never retroactive Registry discovery."""
    retained = [
        observation
        for observation in _passing_observations()
        if observation.root.kind
        not in {
            "test.registry.lookup_requested",
            "test.registry.lookup_returned",
            "test.requester.provider_selected",
        }
    ]
    observations = [
        observation.model_copy(
            update={
                "root": observation.root.model_copy(
                    update={"seq": sequence, "event_id": _event_id(sequence)}
                )
            }
        )
        for sequence, observation in enumerate(retained, start=1)
    ]

    assert _statuses(observations) == [
        "pass",
        "pass",
        "fail",
        "not_tested",
        "not_tested",
    ]


def test_message_none_is_a_semantic_fulfillment_failure() -> None:
    """A valid no-op response proves the capability request was not fulfilled."""
    observations = _passing_observations()[:7]
    returned = observations[-1].root
    observations[-1] = TestObservation.model_validate(
        {
            **returned.model_dump(mode="json"),
            "data": {**returned.data.model_dump(mode="json"), "intent_kind": "none"},
        }
    )

    assert _statuses(observations) == ["pass", "pass", "pass", "pass", "fail"]


def test_wrong_bounded_response_is_a_semantic_fulfillment_failure() -> None:
    """Town routes bounded arbitrary text but evaluates only the exact frozen response as pass."""
    observations = _passing_observations()
    observations[7] = _observation(
        8,
        "test.message.response_routed",
        {
            "sender_id": "provider-0",
            "recipient_id": "requester-0",
            "media_type": "text/plain; charset=utf-8",
            "text": "wrong but bounded",
            "payload_digest": _digest("wrong but bounded"),
        },
    )
    response = observations[7].root
    observations[7] = observations[7].model_copy(
        update={
            "root": response.model_copy(update={"response_digest": _digest("wrong but bounded")})
        }
    )
    observations[8] = _observation(
        9,
        "test.capability.result_evaluated",
        {
            "evaluator_id": "nanda.agent.capability-fulfillment",
            "evaluator_version": "1",
            "verdict": "fail",
            "expected_response_digest": _digest("sold:widget:2"),
            "actual_response_digest": _digest("wrong but bounded"),
        },
    )
    evaluated = observations[8].root
    observations[8] = observations[8].model_copy(
        update={
            "root": evaluated.model_copy(update={"response_digest": _digest("wrong but bounded")})
        }
    )

    assert _statuses(observations) == ["pass", "pass", "pass", "pass", "fail"]


def test_unlinked_response_envelope_cannot_pass_fulfillment() -> None:
    """Payload data alone cannot replace the simulator's request/response digest chain."""
    observations = _passing_observations()
    response = observations[7].root
    observations[7] = observations[7].model_copy(
        update={
            "root": response.model_copy(update={"request_digest": _digest("unrelated-request")})
        }
    )

    assert _statuses(observations) == [
        "pass",
        "pass",
        "pass",
        "pass",
        "inconclusive",
    ]


def test_message_driver_contract_failure_leaves_fulfillment_not_tested() -> None:
    """Malformed adapter output after routing fails the driver, not the capability result."""
    observations = _passing_observations()[:6]
    observations.append(
        _observation(
            7,
            "test.driver.exchange_failed",
            {
                "stage": "message",
                "disposition": "driver_contract",
                "error_code": "MALFORMED_RESPONSE",
                "driver_event_id": "01K00000000000000000000021",
                "driver_sequence": 1,
            },
        )
    )

    assert _statuses(observations) == ["fail", "pass", "pass", "pass", "not_tested"]


def test_duplicate_or_out_of_order_evidence_makes_every_check_inconclusive() -> None:
    """Trace integrity failure cannot yield even a partial conclusive result."""
    passing = _passing_observations()
    duplicate = passing.copy()
    duplicate[1] = duplicate[1].model_copy(
        update={
            "root": duplicate[1].root.model_copy(update={"event_id": duplicate[0].root.event_id})
        }
    )
    out_of_order = passing.copy()
    out_of_order[4], out_of_order[5] = out_of_order[5], out_of_order[4]

    assert _statuses(duplicate) == ["inconclusive"] * 5
    assert _statuses(out_of_order) == ["inconclusive"] * 5


def _replace_event_fields(observation: TestObservation, **changes: object) -> TestObservation:
    return TestObservation.model_validate({**observation.root.model_dump(mode="json"), **changes})


def test_wrong_admitted_profile_digest_makes_every_check_inconclusive() -> None:
    """A valid but different profile digest cannot authorize this evaluator table."""
    observations = _passing_observations()
    admitted = observations[0].root
    observations[0] = TestObservation.model_validate(
        {
            **admitted.model_dump(mode="json"),
            "data": {
                **admitted.data.model_dump(mode="json"),
                "profile_digest": "sha256:" + "f" * 64,
            },
        }
    )

    assert _statuses(observations) == ["inconclusive"] * 5


@pytest.mark.parametrize("event_index", range(9))
def test_wrong_observer_for_each_scoped_event_makes_every_check_inconclusive(
    event_index: int,
) -> None:
    """No event kind may borrow authority from another valid Town observer role."""
    observations = _passing_observations()
    observations[event_index] = _replace_event_fields(
        observations[event_index], observer="town.agent-test-runner"
    )

    assert _statuses(observations) == ["inconclusive"] * 5


@pytest.mark.parametrize("event_index", range(9))
def test_wrong_subject_for_each_scoped_event_makes_every_check_inconclusive(
    event_index: int,
) -> None:
    """Every event in this external-provider slice must remain bound to provider-0."""
    observations = _passing_observations()
    observations[event_index] = _replace_event_fields(
        observations[event_index], subject_participant_id="requester-0"
    )

    assert _statuses(observations) == ["inconclusive"] * 5


def test_exchange_failure_with_wrong_authority_is_inconclusive() -> None:
    """A failure classification is evidence only when emitted by the driven agent."""
    failed = _replace_event_fields(
        _driver_failure(stage="start", disposition="driver_contract"),
        observer="town.capability-requester",
    )

    assert _statuses([failed]) == ["inconclusive"] * 5


def test_combined_profile_observer_and_subject_misattribution_cannot_pass() -> None:
    """Several individually valid-looking provenance substitutions never compose to PASS."""
    observations = _passing_observations()
    admitted = observations[0].root
    observations[0] = TestObservation.model_validate(
        {
            **admitted.model_dump(mode="json"),
            "data": {
                **admitted.data.model_dump(mode="json"),
                "profile_digest": "sha256:" + "e" * 64,
            },
        }
    )
    observations[1] = _replace_event_fields(observations[1], observer="town.capability-requester")
    observations[2] = _replace_event_fields(observations[2], subject_participant_id="requester-0")

    assert _statuses(observations) == ["inconclusive"] * 5
