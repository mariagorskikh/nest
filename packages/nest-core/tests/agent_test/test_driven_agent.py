# SPDX-License-Identifier: Apache-2.0
"""Behavior tests for the transport-neutral externally driven participant."""

from __future__ import annotations

import hashlib
import random
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Any

import pytest
from nest_core.agent_test.driven_agent import DrivenAgent
from nest_core.agent_test.driver import (
    DriverContractError,
    DriverIncompleteError,
    TownDriverError,
)
from nest_core.agent_test.models import (
    DeclareCapabilityIntent,
    DriverExchangeFailedObservation,
    DriverReadiness,
    DriverRequest,
    DriverResponse,
    EffectiveDriverLimits,
    NoneIntent,
    ReadyLimits,
    SendToSenderIntent,
)
from nest_core.agent_test.profiles import ResolvedTestProfile, resolve_test_profile
from nest_core.agent_test.runtime import AgentTestRuntime
from nest_core.sim.agent import ScenarioEventRequest
from nest_core.types import AgentId, CorrelationId, Query
from nest_plugins_reference.registry.in_memory import InMemoryRegistry

RUN_ID = "01K00000000000000000000001"
type DriverIntent = DeclareCapabilityIntent | SendToSenderIntent | NoneIntent


def _identity_response(response: DriverResponse) -> DriverResponse:
    return response


def _event_id_factory(start: int) -> Callable[[], str]:
    event_ids = iter(f"01K000000000000000000000{value:02d}" for value in range(start, start + 20))
    return lambda: next(event_ids)


def _digest_request(request: DriverRequest) -> str:
    return "sha256:" + hashlib.sha256(request.model_dump_json().encode()).hexdigest()


def _readiness(instance_id: str = "adapter:dev") -> DriverReadiness:
    profile = resolve_test_profile("capability-fulfillment").reference
    from nest_core.agent_test.models import DriverReady

    return DriverReadiness(
        ready=DriverReady(
            schema_version="town-agent-driver-ready/1",
            adapter_instance_id=instance_id,
            contracts=["town-agent-driver/1"],
            profiles=[profile],
            accepting_runs=True,
            limits=ReadyLimits(
                max_active_runs=1,
                max_request_bytes=65536,
                max_response_bytes=65536,
            ),
        ),
        effective_limits=EffectiveDriverLimits(
            max_request_bytes=65536,
            max_response_bytes=65536,
        ),
    )


class _Driver:
    def __init__(
        self,
        intent_for: Callable[[DriverRequest], DriverIntent],
        response_mutator: Callable[[DriverResponse], DriverResponse] | None = None,
    ) -> None:
        self._intent_for = intent_for
        self._response_mutator: Callable[[DriverResponse], DriverResponse] = (
            response_mutator or _identity_response
        )
        self.requests: list[DriverRequest] = []
        self.close_calls = 0

    async def ready(self, profile: ResolvedTestProfile) -> DriverReadiness:
        return _readiness()

    async def decide(self, request: DriverRequest) -> DriverResponse:
        self.requests.append(request)
        response = DriverResponse(
            schema_version="town-agent-driver/1",
            run_id=request.run_id,
            event_id=request.event_id,
            sequence=request.sequence,
            adapter_instance_id="adapter:dev",
            request_digest=_digest_request(request),
            intent=self._intent_for(request),
        )
        return self._response_mutator(response)

    async def close(self) -> None:
        self.close_calls += 1


class _Context:
    def __init__(self, registry: InMemoryRegistry, runtime: AgentTestRuntime) -> None:
        self.agent_id = AgentId("provider-0")
        self.time = 0.0
        self.rng = random.Random(7)
        self.plugins: dict[str, Any] = {"registry": registry}
        self.test_runtime = runtime
        self.event_sink = runtime
        self.sent: list[tuple[AgentId, bytes]] = []

    async def send(self, to: AgentId, payload: bytes) -> None:
        await self.send_with_correlation(to, payload)

    async def send_with_correlation(self, to: AgentId, payload: bytes) -> CorrelationId:
        self.sent.append((to, payload))
        return CorrelationId(f"corr-{len(self.sent)}")

    async def broadcast(self, payload: bytes) -> None:
        raise AssertionError("DrivenAgent must not broadcast")

    async def schedule(self, delay: float, payload: bytes) -> None:
        raise AssertionError("DrivenAgent must not schedule")

    def record_scenario_event(
        self,
        *,
        kind: str,
        observer: str,
        subject: str,
        data: Mapping[str, object],
        attributes: Mapping[str, object] | None = None,
    ):
        return self.test_runtime.record(
            ScenarioEventRequest(
                kind=kind,
                logical_time=self.time,
                observer=observer,
                subject=subject,
                data=data,
                attributes={} if attributes is None else attributes,
            )
        )


def _runtime() -> AgentTestRuntime:
    return AgentTestRuntime(
        run_id=RUN_ID,
        resolved_profile=resolve_test_profile("capability-fulfillment"),
        event_id_factory=_event_id_factory(10),
        observed_at=lambda: datetime(2026, 8, 13, 12, 0, tzinfo=UTC),
    )


@pytest.mark.asyncio
async def test_start_binds_driver_and_registers_declared_capability() -> None:
    """Changing run/profile/participant/instance binding or bypassing Registry breaks admission."""
    profile = resolve_test_profile("capability-fulfillment")
    registry = InMemoryRegistry()
    runtime = _runtime()
    ctx = _Context(registry, runtime)
    driver = _Driver(
        lambda request: DeclareCapabilityIntent(kind="declare_capability", capabilities=["sell"])
    )
    agent = DrivenAgent(
        driver=driver,
        run_id=RUN_ID,
        resolved_profile=profile,
        readiness=_readiness(),
        event_id_factory=_event_id_factory(2),
    )

    await agent.on_start(ctx)

    request = driver.requests[0]
    assert request.model_dump(mode="json") == {
        "schema_version": "town-agent-driver/1",
        "run_id": RUN_ID,
        "event_id": "01K00000000000000000000002",
        "sequence": 0,
        "participant": {"id": "provider-0", "role": "provider"},
        "profile": profile.reference.model_dump(mode="json"),
        "observation": {
            "kind": "start",
            "logical_time": 0,
            "allowed_intents": ["declare_capability", "none"],
        },
    }
    cards = await registry.lookup(Query(capabilities=["sell"]))
    assert [str(card.agent_id) for card in cards] == ["provider-0"]
    assert [observation.root.kind for observation in runtime.observations] == [
        "test.driver.run_admitted",
        "test.registry.provider_registered",
    ]
    admitted = runtime.observations[0].root
    assert admitted.data.model_dump(mode="json") == {
        "adapter_instance_id": "adapter:dev",
        "profile_digest": profile.reference.digest,
        "driver_sequence": 0,
        "intent_kind": "declare_capability",
    }


@pytest.mark.asyncio
async def test_message_observes_exact_request_and_routes_one_bounded_intent() -> None:
    """Changing the sender/payload envelope or replacing Town routing breaks fulfillment."""
    profile = resolve_test_profile("capability-fulfillment")
    registry = InMemoryRegistry()
    runtime = _runtime()
    ctx = _Context(registry, runtime)

    def intent_for(request: DriverRequest) -> DriverIntent:
        if request.observation.kind == "start":
            return DeclareCapabilityIntent(kind="declare_capability", capabilities=["sell"])
        return SendToSenderIntent(
            kind="send_to_sender",
            media_type="text/plain; charset=utf-8",
            text="bounded but semantically wrong",
        )

    driver = _Driver(intent_for)
    agent = DrivenAgent(
        driver=driver,
        run_id=RUN_ID,
        resolved_profile=profile,
        readiness=_readiness(),
        event_id_factory=_event_id_factory(2),
    )
    await agent.on_start(ctx)

    await agent.on_message(ctx, AgentId("requester-0"), b"buy:widget:2")

    request = driver.requests[1]
    assert request.model_dump(mode="json") == {
        "schema_version": "town-agent-driver/1",
        "run_id": RUN_ID,
        "event_id": "01K00000000000000000000003",
        "sequence": 1,
        "participant": {"id": "provider-0", "role": "provider"},
        "profile": profile.reference.model_dump(mode="json"),
        "observation": {
            "kind": "message",
            "logical_time": 0,
            "allowed_intents": ["send_to_sender", "none"],
            "message": {
                "id": "message-001",
                "sender_id": "requester-0",
                "media_type": "text/plain; charset=utf-8",
                "text": "buy:widget:2",
            },
        },
    }
    assert ctx.sent == [(AgentId("requester-0"), b"bounded but semantically wrong")]
    assert [observation.root.kind for observation in runtime.observations] == [
        "test.driver.run_admitted",
        "test.registry.provider_registered",
        "test.driver.intent_returned",
        "test.message.response_routed",
    ]
    returned = runtime.observations[2].root
    assert returned.data.model_dump(mode="json") == {
        "adapter_instance_id": "adapter:dev",
        "driver_event_id": "01K00000000000000000000003",
        "driver_sequence": 1,
        "intent_kind": "send_to_sender",
    }


@pytest.mark.asyncio
async def test_mismatched_start_response_aborts_and_records_closed_failure() -> None:
    """A wrong response sequence cannot admit/register or fall back to reference behavior."""
    registry = InMemoryRegistry()
    runtime = _runtime()
    ctx = _Context(registry, runtime)
    driver = _Driver(
        lambda request: DeclareCapabilityIntent(kind="declare_capability", capabilities=["sell"]),
        response_mutator=lambda response: response.model_copy(update={"sequence": 1}),
    )
    agent = DrivenAgent(
        driver=driver,
        run_id=RUN_ID,
        resolved_profile=resolve_test_profile("capability-fulfillment"),
        readiness=_readiness(),
        event_id_factory=_event_id_factory(2),
    )

    with pytest.raises(DriverContractError, match="RESPONSE_MISMATCH"):
        await agent.on_start(ctx)

    assert await registry.lookup(Query(capabilities=["sell"])) == []
    assert len(runtime.observations) == 1
    failed = runtime.observations[0].root
    assert failed.kind == "test.driver.exchange_failed"
    assert failed.data.model_dump(mode="json") == {
        "stage": "start",
        "disposition": "driver_contract",
        "error_code": "RESPONSE_MISMATCH",
        "driver_event_id": "01K00000000000000000000002",
        "driver_sequence": 0,
    }


@pytest.mark.asyncio
async def test_duplicate_lifecycle_callbacks_reuse_event_and_apply_intent_once() -> None:
    """A same-event retry is stable while registration and response routing happen once."""
    runtime = _runtime()
    ctx = _Context(InMemoryRegistry(), runtime)

    def intent_for(request: DriverRequest) -> DriverIntent:
        if request.observation.kind == "start":
            return DeclareCapabilityIntent(kind="declare_capability", capabilities=["sell"])
        return SendToSenderIntent(
            kind="send_to_sender",
            media_type="text/plain; charset=utf-8",
            text="sold:widget:2",
        )

    driver = _Driver(intent_for)
    agent = DrivenAgent(
        driver=driver,
        run_id=RUN_ID,
        resolved_profile=resolve_test_profile("capability-fulfillment"),
        readiness=_readiness(),
        event_id_factory=_event_id_factory(2),
    )

    await agent.on_start(ctx)
    await agent.on_start(ctx)
    await agent.on_message(ctx, AgentId("requester-0"), b"buy:widget:2")
    await agent.on_message(ctx, AgentId("requester-0"), b"buy:widget:2")

    assert [(request.sequence, request.event_id) for request in driver.requests] == [
        (0, "01K00000000000000000000002"),
        (0, "01K00000000000000000000002"),
        (1, "01K00000000000000000000003"),
        (1, "01K00000000000000000000003"),
    ]
    assert ctx.sent == [(AgentId("requester-0"), b"sold:widget:2")]
    assert [observation.root.kind for observation in runtime.observations] == [
        "test.driver.run_admitted",
        "test.registry.provider_registered",
        "test.driver.intent_returned",
        "test.message.response_routed",
    ]


@pytest.mark.asyncio
async def test_stop_is_outer_owned_best_effort_and_idempotent() -> None:
    """Simulator on_stop performs no I/O; the outer cleanup sends one stop decision only."""
    ctx = _Context(InMemoryRegistry(), _runtime())

    def intent_for(request: DriverRequest) -> DriverIntent:
        if request.observation.kind == "start":
            return DeclareCapabilityIntent(kind="declare_capability", capabilities=["sell"])
        return NoneIntent(kind="none")

    driver = _Driver(intent_for)
    agent = DrivenAgent(
        driver=driver,
        run_id=RUN_ID,
        resolved_profile=resolve_test_profile("capability-fulfillment"),
        readiness=_readiness(),
        event_id_factory=_event_id_factory(2),
    )
    await agent.on_start(ctx)

    await agent.on_stop(ctx)
    assert len(driver.requests) == 1

    await agent.best_effort_stop("run_failed")
    await agent.best_effort_stop("run_complete")

    assert len(driver.requests) == 2
    stop = driver.requests[1]
    assert stop.sequence == 1
    assert stop.event_id == "01K00000000000000000000003"
    assert stop.observation.model_dump(mode="json") == {
        "kind": "stop",
        "logical_time": 0,
        "allowed_intents": ["none"],
        "reason": "run_failed",
    }
    assert driver.close_calls == 0


@pytest.mark.asyncio
async def test_driver_event_ids_must_be_unique_across_lifecycle_requests() -> None:
    """A colliding generated event ID aborts before a second exchange or routed fallback."""
    ctx = _Context(InMemoryRegistry(), _runtime())

    def intent_for(request: DriverRequest) -> DriverIntent:
        if request.observation.kind == "start":
            return DeclareCapabilityIntent(kind="declare_capability", capabilities=["sell"])
        return SendToSenderIntent(
            kind="send_to_sender",
            media_type="text/plain; charset=utf-8",
            text="sold:widget:2",
        )

    driver = _Driver(intent_for)
    agent = DrivenAgent(
        driver=driver,
        run_id=RUN_ID,
        resolved_profile=resolve_test_profile("capability-fulfillment"),
        readiness=_readiness(),
        event_id_factory=lambda: "01K00000000000000000000002",
    )
    await agent.on_start(ctx)

    with pytest.raises(TownDriverError, match="EVENT_CONFLICT"):
        await agent.on_message(ctx, AgentId("requester-0"), b"buy:widget:2")

    assert len(driver.requests) == 1
    assert ctx.sent == []


@pytest.mark.asyncio
@pytest.mark.parametrize("logical_time", [float("nan"), float("inf"), -1.0, 0.5])
async def test_invalid_town_logical_time_aborts_before_driver_exchange(
    logical_time: float,
) -> None:
    """Driver requests never coerce non-finite, negative, or fractional Town time."""
    ctx = _Context(InMemoryRegistry(), _runtime())
    ctx.time = logical_time
    driver = _Driver(lambda request: NoneIntent(kind="none"))
    agent = DrivenAgent(
        driver=driver,
        run_id=RUN_ID,
        resolved_profile=resolve_test_profile("capability-fulfillment"),
        readiness=_readiness(),
    )

    with pytest.raises(TownDriverError, match="INVALID_LOGICAL_TIME"):
        await agent.on_start(ctx)

    assert driver.requests == []


@pytest.mark.asyncio
async def test_oversized_message_intent_is_revalidated_before_town_routing() -> None:
    """A constructed response cannot bypass the profile's 4096-byte routing bound."""
    ctx = _Context(InMemoryRegistry(), _runtime())

    def intent_for(request: DriverRequest) -> DriverIntent:
        if request.observation.kind == "start":
            return DeclareCapabilityIntent(kind="declare_capability", capabilities=["sell"])
        return SendToSenderIntent(
            kind="send_to_sender",
            media_type="text/plain; charset=utf-8",
            text="sold:widget:2",
        )

    def mutate_message(response: DriverResponse) -> DriverResponse:
        if response.sequence != 1:
            return response
        oversized = SendToSenderIntent.model_construct(
            kind="send_to_sender",
            media_type="text/plain; charset=utf-8",
            text="é" * 2049,
        )
        return response.model_copy(update={"intent": oversized})

    driver = _Driver(intent_for, response_mutator=mutate_message)
    agent = DrivenAgent(
        driver=driver,
        run_id=RUN_ID,
        resolved_profile=resolve_test_profile("capability-fulfillment"),
        readiness=_readiness(),
    )
    await agent.on_start(ctx)

    with pytest.raises(DriverContractError, match="MALFORMED_RESPONSE"):
        await agent.on_message(ctx, AgentId("requester-0"), b"buy:widget:2")

    assert ctx.sent == []
    failed = ctx.test_runtime.observations[-1].root
    assert isinstance(failed, DriverExchangeFailedObservation)
    assert failed.data.disposition == "driver_contract"


@pytest.mark.asyncio
async def test_adapter_instance_drift_aborts_message_without_routing() -> None:
    """One run cannot continue after the ready-bound adapter instance changes."""
    ctx = _Context(InMemoryRegistry(), _runtime())

    def intent_for(request: DriverRequest) -> DriverIntent:
        if request.observation.kind == "start":
            return DeclareCapabilityIntent(kind="declare_capability", capabilities=["sell"])
        return SendToSenderIntent(
            kind="send_to_sender",
            media_type="text/plain; charset=utf-8",
            text="sold:widget:2",
        )

    def mutate_message(response: DriverResponse) -> DriverResponse:
        if response.sequence == 1:
            return response.model_copy(update={"adapter_instance_id": "adapter:other"})
        return response

    driver = _Driver(intent_for, response_mutator=mutate_message)
    agent = DrivenAgent(
        driver=driver,
        run_id=RUN_ID,
        resolved_profile=resolve_test_profile("capability-fulfillment"),
        readiness=_readiness(),
    )
    await agent.on_start(ctx)

    with pytest.raises(DriverIncompleteError, match="ADAPTER_INSTANCE_CHANGED"):
        await agent.on_message(ctx, AgentId("requester-0"), b"buy:widget:2")

    assert ctx.sent == []
    failed = ctx.test_runtime.observations[-1].root
    assert isinstance(failed, DriverExchangeFailedObservation)
    assert failed.data.disposition == "incomplete"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("sender", "payload"),
    [
        (AgentId("provider-0"), b"buy:widget:2"),
        (AgentId("requester-0"), b"buy:widget:1"),
    ],
)
async def test_wrong_synthetic_message_envelope_aborts_before_driver_exchange(
    sender: AgentId,
    payload: bytes,
) -> None:
    """Only the frozen requester and request bytes may enter the driver contract."""
    ctx = _Context(InMemoryRegistry(), _runtime())

    def intent_for(request: DriverRequest) -> DriverIntent:
        if request.observation.kind == "start":
            return DeclareCapabilityIntent(kind="declare_capability", capabilities=["sell"])
        return NoneIntent(kind="none")

    driver = _Driver(intent_for)
    agent = DrivenAgent(
        driver=driver,
        run_id=RUN_ID,
        resolved_profile=resolve_test_profile("capability-fulfillment"),
        readiness=_readiness(),
    )
    await agent.on_start(ctx)

    with pytest.raises(TownDriverError, match="MESSAGE_MISMATCH"):
        await agent.on_message(ctx, sender, payload)

    assert len(driver.requests) == 1
    assert ctx.sent == []


@pytest.mark.asyncio
async def test_duplicate_message_with_changed_logical_time_is_an_event_conflict() -> None:
    """A retry is idempotent only when the complete driver event body is unchanged."""
    ctx = _Context(InMemoryRegistry(), _runtime())

    def intent_for(request: DriverRequest) -> DriverIntent:
        if request.observation.kind == "start":
            return DeclareCapabilityIntent(kind="declare_capability", capabilities=["sell"])
        return SendToSenderIntent(
            kind="send_to_sender",
            media_type="text/plain; charset=utf-8",
            text="sold:widget:2",
        )

    driver = _Driver(intent_for)
    agent = DrivenAgent(
        driver=driver,
        run_id=RUN_ID,
        resolved_profile=resolve_test_profile("capability-fulfillment"),
        readiness=_readiness(),
    )
    await agent.on_start(ctx)
    await agent.on_message(ctx, AgentId("requester-0"), b"buy:widget:2")
    ctx.time = 1.0

    with pytest.raises(TownDriverError, match="EVENT_CONFLICT"):
        await agent.on_message(ctx, AgentId("requester-0"), b"buy:widget:2")

    assert len(driver.requests) == 2
    assert ctx.sent == [(AgentId("requester-0"), b"sold:widget:2")]
