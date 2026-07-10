# SPDX-License-Identifier: Apache-2.0
"""EMPIC-style weather payments scenario.

Providers register weather services, consumers fund pull or pubsub escrows,
and consumer acceptance policy determines whether escrow is released or
refunded.  The scenario is deterministic and uses only in-memory Nanda Town
plugins.

Example::

    agents = empic_payments_factory(config, plugins)
"""

from __future__ import annotations

import json
from typing import Any, Literal, cast

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId, Money, PaymentRef, ServiceRef

DeliveryMode = Literal["pull", "pubsub"]


def _json(data: dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()


def _load(payload: bytes) -> dict[str, Any]:
    try:
        data: object = json.loads(payload.decode("utf-8"))
    except json.JSONDecodeError:
        return {}
    return cast("dict[str, Any]", data) if isinstance(data, dict) else {}


async def _audit(ctx: AgentContext, data: dict[str, Any]) -> None:
    event = {"type": "empic_audit", "tick": int(ctx.time), **data}
    await ctx.send(ctx.agent_id, _json(event))


def _int(value: object, default: int = 0) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return default
    return default


def _float(value: object) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def _evaluate_acceptance(
    delivery: dict[str, Any],
    *,
    policy: dict[str, Any],
    expected_service_id: ServiceRef,
    expected_provider: AgentId,
    expected_consumer: AgentId,
    request_params: dict[str, Any],
    current_tick: int,
) -> tuple[bool, str]:
    data_obj = delivery.get("data")
    if not isinstance(data_obj, dict):
        return False, "missing data object"
    data = cast("dict[str, Any]", data_obj)

    if policy.get("bind_service_id", True) and delivery.get("service_id") != str(
        expected_service_id
    ):
        return False, "service_id mismatch"
    if policy.get("bind_provider_id", True) and delivery.get("provider_id") != str(
        expected_provider
    ):
        return False, "provider_id mismatch"
    if policy.get("bind_consumer_id", True) and delivery.get("consumer_id") != str(
        expected_consumer
    ):
        return False, "consumer_id mismatch"
    if policy.get("bind_request_params", True) and delivery.get("request_params") != request_params:
        return False, "request_params mismatch"

    required = policy.get("required_fields", [])
    if isinstance(required, list):
        for field in cast("list[object]", required):
            if isinstance(field, str) and field not in data:
                return False, f"missing field {field}"

    ranges = policy.get("numeric_ranges", {})
    if isinstance(ranges, dict):
        for field, bounds_obj in cast("dict[object, object]", ranges).items():
            if not isinstance(field, str) or not isinstance(bounds_obj, dict):
                continue
            bounds = cast("dict[str, object]", bounds_obj)
            value = _float(data.get(field))
            if value is None:
                return False, f"{field} is not numeric"
            min_value = _float(bounds.get("min"))
            max_value = _float(bounds.get("max"))
            if min_value is not None and value < min_value:
                return False, f"{field} below minimum"
            if max_value is not None and value > max_value:
                return False, f"{field} above maximum"

    max_age = _int(policy.get("max_age_ticks"), default=-1)
    data_tick = _int(data.get("tick"), default=current_tick)
    if max_age >= 0 and current_tick - data_tick > max_age:
        return False, "delivery stale"

    return True, "accepted"


class WeatherProviderAgent(StateMachineAgent):
    """Provider that registers one EMPIC weather service and delivers data.

    Example::

        agent = WeatherProviderAgent(
            AgentId("provider-0"),
            service_id=ServiceRef("weather"),
            behavior="honest",
            delivery_modes=("pull",),
        )
    """

    def __init__(
        self,
        agent_id: AgentId,
        *,
        service_id: ServiceRef,
        behavior: str,
        delivery_modes: tuple[DeliveryMode, ...],
    ) -> None:
        self._id = agent_id
        self._service_id = service_id
        self._behavior = behavior
        self._delivery_modes = delivery_modes

    async def on_start(self, ctx: AgentContext) -> None:
        """Register this provider's service metadata."""
        payments = ctx.plugins.get("payments")
        if payments is None:
            return

        from nest_plugins_reference.payments.empic_escrow import PubsubTerms

        terms = (
            PubsubTerms(rate_per_tick=10, max_total=40, duration_ticks=6, min_valid_ratio=0.75)
            if "pubsub" in self._delivery_modes
            else None
        )
        schema = {
            "required_fields": [
                "temperature_c",
                "temperature_f",
                "windspeed_kmh",
                "timestamp",
                "tick",
            ]
        }
        payments.register_service(
            service_id=self._service_id,
            provider=self._id,
            price=Money(amount=50),
            delivery_modes=self._delivery_modes,
            schema=schema,
            pubsub_terms=terms,
            metadata={"behavior": self._behavior},
        )
        terms_payload = (
            {
                "rate_per_tick": terms.rate_per_tick,
                "max_total": terms.max_total,
                "duration_ticks": terms.duration_ticks,
                "min_valid_ratio": terms.min_valid_ratio,
                "min_msg_count": terms.min_msg_count,
                "auto_renew": terms.auto_renew,
            }
            if terms is not None
            else None
        )
        await _audit(
            ctx,
            {
                "event_type": "empic_service_registered",
                "service_id": str(self._service_id),
                "provider": str(self._id),
                "delivery_modes": list(self._delivery_modes),
                "price": 50,
                "schema": schema,
                "pubsub_terms": terms_payload,
            },
        )

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Handle service requests and scheduled pubsub emits."""
        msg = _load(payload)
        msg_type = msg.get("type")
        if msg_type in ("empic_audit", "empic_delivery"):
            return
        if msg_type == "empic_pubsub_emit":
            await self._send_pubsub_delivery(ctx, msg)
            return
        if msg_type != "empic_request":
            return

        mode = msg.get("delivery_mode")
        if mode == "pull":
            await ctx.send(sender, _json(self._delivery(ctx, msg, sequence=0)))
        elif mode == "pubsub":
            for seq in range(4):
                emit = {**msg, "type": "empic_pubsub_emit", "seq": seq}
                await ctx.schedule(float(seq + 1), _json(emit))

    async def _send_pubsub_delivery(self, ctx: AgentContext, msg: dict[str, Any]) -> None:
        consumer = AgentId(str(msg.get("consumer_id", "")))
        seq = _int(msg.get("seq"))
        await ctx.send(consumer, _json(self._delivery(ctx, msg, sequence=seq)))

    def _delivery(
        self,
        ctx: AgentContext,
        request: dict[str, Any],
        *,
        sequence: int,
    ) -> dict[str, Any]:
        current_tick = int(ctx.time)
        data: dict[str, Any] = {
            "temperature_c": 21.0 + sequence,
            "temperature_f": 69.8 + (sequence * 1.8),
            "windspeed_kmh": 8.0 + sequence,
            "timestamp": f"tick-{current_tick}",
            "tick": current_tick,
        }
        provider_id = str(self._id)
        service_id = str(self._service_id)
        consumer_id = str(request.get("consumer_id", ""))

        if self._behavior == "missing_field":
            data.pop("temperature_f")
        elif self._behavior == "stale":
            data["tick"] = current_tick - 10
            data["timestamp"] = f"tick-{current_tick - 10}"
        elif self._behavior == "wrong_provider":
            provider_id = "provider-spoof"
            service_id = f"{self._service_id}-spoof"
        elif self._behavior == "wrong_consumer":
            consumer_id = "consumer-spoof"
        elif self._behavior == "pubsub_mixed" and sequence == 2:
            data["temperature_c"] = 120.0

        ref = str(request.get("payment_ref", ""))
        delivery_id = f"{ref}-delivery-{sequence}"
        return {
            "type": "empic_delivery",
            "delivery_id": delivery_id,
            "payment_ref": ref,
            "service_id": service_id,
            "provider_id": provider_id,
            "consumer_id": consumer_id,
            "delivery_mode": request.get("delivery_mode", "pull"),
            "request_params": request.get("request_params", {}),
            "data": data,
        }


class WeatherConsumerAgent(StateMachineAgent):
    """Consumer that funds escrow and releases only acceptable weather data.

    Example::

        agent = WeatherConsumerAgent(
            AgentId("consumer-0"),
            provider=AgentId("provider-0"),
            service_id=ServiceRef("weather"),
            mode="pull",
            policy={"required_fields": ["temperature_c"]},
            request_params={"city": "Cambridge"},
            max_spend=100,
        )
    """

    def __init__(
        self,
        agent_id: AgentId,
        *,
        provider: AgentId,
        service_id: ServiceRef,
        mode: DeliveryMode,
        policy: dict[str, Any],
        request_params: dict[str, Any],
        max_spend: int,
    ) -> None:
        self._id = agent_id
        self._provider = provider
        self._service_id = service_id
        self._mode = mode
        self._policy = policy
        self._request_params = request_params
        self._max_spend = max_spend
        self._ref = PaymentRef(f"{agent_id}-{service_id}")
        self._stream_closed = False

    async def on_start(self, ctx: AgentContext) -> None:
        """Fund escrow and request provider data."""
        payments = ctx.plugins.get("payments")
        if payments is None:
            return

        quote = await payments.quote(self._service_id)
        await _audit(
            ctx,
            {
                "event_type": "empic_acceptance_policy",
                "payment_ref": str(self._ref),
                "service_id": str(self._service_id),
                "payer": str(self._id),
                "consumer_id": str(self._id),
                "provider": str(self._provider),
                "mode": self._mode,
                "request_params": self._request_params,
                "policy": self._policy,
                "max_spend": self._max_spend,
            },
        )
        if quote.price.amount > self._max_spend:
            await _audit(
                ctx,
                {
                    "event_type": "empic_request_declined",
                    "payment_ref": str(self._ref),
                    "service_id": str(self._service_id),
                    "reason": "max spend exceeded",
                },
            )
            return

        if self._mode == "pull":
            await payments.open_pull_escrow(
                self._provider,
                quote.price,
                self._ref,
                service_id=self._service_id,
            )
            await _audit(
                ctx,
                {
                    "event_type": "empic_escrow_debited",
                    "payment_ref": str(self._ref),
                    "service_id": str(self._service_id),
                    "payer": str(self._id),
                    "consumer_id": str(self._id),
                    "provider": str(self._provider),
                    "amount": quote.price.amount,
                    "mode": "pull",
                },
            )
        else:
            service = payments.service_record(self._service_id)
            terms = service.pubsub_terms if service is not None else None
            if terms is None:
                return
            await payments.open_stream(
                self._provider,
                rate_per_tick=terms.rate_per_tick,
                max_total=terms.max_total,
                ref=self._ref,
                service_id=self._service_id,
                opened_at_tick=int(ctx.time),
            )
            await _audit(
                ctx,
                {
                    "event_type": "empic_stream_opened",
                    "payment_ref": str(self._ref),
                    "service_id": str(self._service_id),
                    "payer": str(self._id),
                    "consumer_id": str(self._id),
                    "provider": str(self._provider),
                    "amount": terms.max_total,
                    "rate_per_tick": terms.rate_per_tick,
                    "max_total": terms.max_total,
                    "duration_ticks": terms.duration_ticks,
                    "mode": "pubsub",
                },
            )
            await _audit(
                ctx,
                {
                    "event_type": "empic_escrow_debited",
                    "payment_ref": str(self._ref),
                    "service_id": str(self._service_id),
                    "payer": str(self._id),
                    "consumer_id": str(self._id),
                    "provider": str(self._provider),
                    "amount": terms.max_total,
                    "mode": "pubsub",
                },
            )
            await ctx.schedule(float(terms.duration_ticks), _json({"type": "empic_close_stream"}))

        await ctx.send(
            self._provider,
            _json(
                {
                    "type": "empic_request",
                    "payment_ref": str(self._ref),
                    "service_id": str(self._service_id),
                    "consumer_id": str(self._id),
                    "delivery_mode": self._mode,
                    "request_params": self._request_params,
                }
            ),
        )

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Evaluate deliveries and close streams."""
        msg = _load(payload)
        msg_type = msg.get("type")
        if msg_type == "empic_audit":
            return
        if msg_type == "empic_close_stream":
            await self._close_stream(ctx)
            return
        if msg_type != "empic_delivery":
            return

        await self._handle_delivery(ctx, sender, msg)

    async def _handle_delivery(
        self,
        ctx: AgentContext,
        sender: AgentId,
        delivery: dict[str, Any],
    ) -> None:
        payments = ctx.plugins.get("payments")
        if payments is None:
            return

        accepted, reason = _evaluate_acceptance(
            delivery,
            policy=self._policy,
            expected_service_id=self._service_id,
            expected_provider=self._provider,
            expected_consumer=self._id,
            request_params=self._request_params,
            current_tick=int(ctx.time),
        )
        delivery_id = str(delivery.get("delivery_id", ""))
        payments.record_delivery(
            self._ref,
            delivery_id=delivery_id,
            service_id=self._service_id,
            provider=sender,
            mode=self._mode,
            tick=int(ctx.time),
            accepted=accepted,
            data=cast("dict[str, Any]", delivery.get("data", {})),
            reason=reason,
        )
        await _audit(
            ctx,
            {
                "event_type": "empic_delivery_evaluated",
                "delivery_id": delivery_id,
                "payment_ref": str(self._ref),
                "service_id": str(self._service_id),
                "payer": str(self._id),
                "consumer_id": str(self._id),
                "provider": str(self._provider),
                "delivery_service_id": str(delivery.get("service_id", "")),
                "delivery_provider_id": str(delivery.get("provider_id", "")),
                "delivery_consumer_id": str(delivery.get("consumer_id", "")),
                "request_params": delivery.get("request_params", {}),
                "accepted": accepted,
                "reason": reason,
                "mode": self._mode,
            },
        )

        if self._mode == "pull":
            if accepted:
                record = payments.payment_record(self._ref)
                evidence = record.deliveries[-1] if record is not None else None
                receipt = await payments.fulfill(self._ref, evidence)
                await _audit(
                    ctx,
                    {
                        "event_type": "empic_escrow_released",
                        "delivery_id": delivery_id,
                        "payment_ref": str(self._ref),
                        "service_id": str(self._service_id),
                        "payer": str(self._id),
                        "consumer_id": str(self._id),
                        "provider": str(self._provider),
                        "amount": receipt.amount.amount,
                        "mode": "pull",
                    },
                )
            else:
                record = payments.payment_record(self._ref)
                refund_amount = record.escrowed if record is not None else 0
                await payments.reject(self._ref, reason=reason, data_ref=delivery_id)
                await _audit(
                    ctx,
                    {
                        "event_type": "empic_escrow_refunded",
                        "delivery_id": delivery_id,
                        "payment_ref": str(self._ref),
                        "service_id": str(self._service_id),
                        "payer": str(self._id),
                        "consumer_id": str(self._id),
                        "provider": str(self._provider),
                        "amount": refund_amount,
                        "reason": reason,
                        "mode": "pull",
                    },
                )
            return

        if accepted:
            record = payments.payment_record(self._ref)
            before = record.released if record is not None else 0
            await payments.tick_stream(self._ref, int(ctx.time))
            after_record = payments.payment_record(self._ref)
            released = (after_record.released if after_record is not None else before) - before
            if released > 0:
                await _audit(
                    ctx,
                    {
                        "event_type": "empic_escrow_released",
                        "delivery_id": delivery_id,
                        "payment_ref": str(self._ref),
                        "service_id": str(self._service_id),
                        "payer": str(self._id),
                        "consumer_id": str(self._id),
                        "provider": str(self._provider),
                        "amount": released,
                        "mode": "pubsub",
                    },
                )

    async def _close_stream(self, ctx: AgentContext) -> None:
        if self._mode != "pubsub" or self._stream_closed:
            return
        payments = ctx.plugins.get("payments")
        if payments is None:
            return
        record = payments.payment_record(self._ref)
        refund_amount = record.escrowed if record is not None else 0
        await payments.close_stream(self._ref, current_tick=int(ctx.time))
        self._stream_closed = True
        if refund_amount > 0:
            await _audit(
                ctx,
                {
                    "event_type": "empic_escrow_refunded",
                    "payment_ref": str(self._ref),
                    "service_id": str(self._service_id),
                    "payer": str(self._id),
                    "consumer_id": str(self._id),
                    "provider": str(self._provider),
                    "amount": refund_amount,
                    "reason": "stream closed",
                    "mode": "pubsub",
                },
            )
        await _audit(
            ctx,
            {
                "event_type": "empic_stream_closed",
                "payment_ref": str(self._ref),
                "service_id": str(self._service_id),
                "payer": str(self._id),
                "consumer_id": str(self._id),
                "provider": str(self._provider),
                "mode": "pubsub",
            },
        )


def empic_payments_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create consumers and providers for EMPIC pull/pubsub settlement.

    Example::

        agents = empic_payments_factory(config, plugins)
    """
    default_policy: dict[str, Any] = {
        "required_fields": [
            "temperature_c",
            "temperature_f",
            "windspeed_kmh",
            "timestamp",
            "tick",
        ],
        "numeric_ranges": {
            "temperature_c": {"min": -50, "max": 60},
            "temperature_f": {"min": -58, "max": 140},
            "windspeed_kmh": {"min": 0, "max": 300},
        },
        "max_age_ticks": _int(config.task.config.get("max_age_ticks"), default=3),
        "max_spend": 100,
        "bind_service_id": True,
        "bind_provider_id": True,
        "bind_consumer_id": True,
        "bind_request_params": True,
    }
    raw_policy: object = config.task.config.get("acceptance_policy", {})
    if isinstance(raw_policy, dict):
        policy: dict[str, Any] = {**default_policy, **cast("dict[str, Any]", raw_policy)}
    else:
        policy = default_policy.copy()
    request_params: dict[str, Any] = {"lat": 42.3601, "lon": -71.0942}
    max_spend = _int(policy.get("max_spend"), default=100)

    provider_specs = [
        ("provider-0", "weather-pull-good", "valid", ("pull",)),
        ("provider-1", "weather-pull-missing", "missing_field", ("pull",)),
        ("provider-2", "weather-pull-stale", "stale", ("pull",)),
        ("provider-3", "weather-pull-spoof", "wrong_provider", ("pull",)),
        ("provider-4", "weather-pubsub", "pubsub_mixed", ("pull", "pubsub")),
        ("provider-5", "weather-pull-wrong-consumer", "wrong_consumer", ("pull",)),
    ]
    consumer_specs = [
        ("consumer-0", "provider-0", "weather-pull-good", "pull", max_spend),
        ("consumer-1", "provider-1", "weather-pull-missing", "pull", max_spend),
        ("consumer-2", "provider-2", "weather-pull-stale", "pull", max_spend),
        ("consumer-3", "provider-3", "weather-pull-spoof", "pull", max_spend),
        ("consumer-4", "provider-4", "weather-pubsub", "pubsub", max_spend),
        ("consumer-5", "provider-5", "weather-pull-wrong-consumer", "pull", max_spend),
    ]

    agents: dict[AgentId, StateMachineAgent] = {}
    for provider_id, service_id, behavior, modes in provider_specs:
        aid = AgentId(provider_id)
        agents[aid] = WeatherProviderAgent(
            aid,
            service_id=ServiceRef(service_id),
            behavior=behavior,
            delivery_modes=cast("tuple[DeliveryMode, ...]", modes),
        )

    for consumer_id, provider_id, service_id, mode, max_spend in consumer_specs:
        aid = AgentId(consumer_id)
        agents[aid] = WeatherConsumerAgent(
            aid,
            provider=AgentId(provider_id),
            service_id=ServiceRef(service_id),
            mode=cast("DeliveryMode", mode),
            policy=policy,
            request_params=request_params,
            max_spend=max_spend,
        )

    _instantiate_plugins(plugins, list(agents.keys()))
    return agents


def _instantiate_plugins(plugins: dict[str, Any], all_ids: list[AgentId]) -> None:
    """Instantiate shared and per-agent plugin handles for this scenario."""
    if not plugins:
        return

    registry_cls = plugins.get("registry")
    if registry_cls is not None and isinstance(registry_cls, type):
        plugins["registry"] = registry_cls()

    trust_cls = plugins.get("trust")
    if trust_cls is not None and isinstance(trust_cls, type):
        plugins["trust"] = trust_cls()

    agent_plugins: dict[AgentId, dict[str, Any]] = plugins.setdefault("_agent_plugins", {})

    payments_cls = plugins.get("payments")
    if payments_cls is not None and isinstance(payments_cls, type):
        balances: dict[AgentId, int] = {aid: 1000 for aid in all_ids}
        payment_records: dict[PaymentRef, Any] = {}
        services: dict[ServiceRef, Any] = {}
        system_id = AgentId("system")
        plugins["payments"] = payments_cls(
            system_id,
            initial_balance=0,
            balances=balances,
            payments=payment_records,
            services=services,
        )
        for aid in all_ids:
            agent_plugins.setdefault(aid, {})["payments"] = payments_cls(
                aid,
                initial_balance=0,
                balances=balances,
                payments=payment_records,
                services=services,
            )

    identity_cls = plugins.get("identity")
    if identity_cls is not None and isinstance(identity_cls, type):
        identities: dict[AgentId, Any] = {}
        for aid in all_ids:
            identities[aid] = identity_cls(aid, seed=b"sim-seed")
        for aid, ident in identities.items():
            for peer_id, peer_ident in identities.items():
                if peer_id != aid:
                    ident.register_peer(peer_id, peer_ident.public_key)
        for aid, ident in identities.items():
            agent_plugins.setdefault(aid, {})["identity"] = ident
        plugins.pop("identity", None)
