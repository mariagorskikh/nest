# SPDX-License-Identifier: Apache-2.0
"""Tests for message middleware and the middleware registry."""

from __future__ import annotations

import json
import random
from pathlib import Path

import pytest
from nest_core.middleware_registry import MiddlewareRegistry
from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.sim.middleware import MessageContext, MiddlewareChain
from nest_core.sim.middleware_builtins.auth_scope import (
    AuthScopeMiddleware,
    attach_auth_token,
)
from nest_core.sim.middleware_builtins.latency import LatencyMiddleware
from nest_core.sim.middleware_builtins.observability import ObservabilityMiddleware
from nest_core.sim.middleware_builtins.resilience import ResilienceMiddleware
from nest_core.sim.simulator import Simulator
from nest_core.types import AgentId
from nest_plugins_reference.auth.jwt_auth import JwtAuth


class _EchoAgent(StateMachineAgent):
    async def on_start(self, ctx: AgentContext) -> None:
        if str(ctx.agent_id) == "a1":
            await ctx.send(AgentId("a2"), b"ping")

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        await ctx.send(sender, payload)


class _BoomAgent(StateMachineAgent):
    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        del ctx, sender, payload
        raise RuntimeError("boom")


class _StartToBoomAgent(StateMachineAgent):
    async def on_start(self, ctx: AgentContext) -> None:
        await ctx.send(AgentId("boom"), b"ping")


class _DropSendMiddleware:
    async def on_send(self, ctx: MessageContext) -> MessageContext | None:
        if ctx.payload == b"drop-me":
            return None
        return ctx

    async def on_receive(self, ctx: MessageContext) -> MessageContext | None:
        return ctx


class _TransformReceiveMiddleware:
    async def on_send(self, ctx: MessageContext) -> MessageContext | None:
        return ctx

    async def on_receive(self, ctx: MessageContext) -> MessageContext | None:
        ctx.payload = ctx.payload.upper()
        return ctx


class TestMiddlewareChain:
    @pytest.mark.asyncio
    async def test_drop_on_send(self) -> None:
        chain = MiddlewareChain([_DropSendMiddleware()])
        ctx = MessageContext(
            sender=AgentId("a1"),
            recipient=AgentId("a2"),
            payload=b"drop-me",
            correlation_id=None,
            now=0.0,
            rng=random.Random(1),
            direction="send",
        )
        assert await chain.on_send(ctx) is None

    @pytest.mark.asyncio
    async def test_transform_on_receive(self) -> None:
        chain = MiddlewareChain([_TransformReceiveMiddleware()])
        ctx = MessageContext(
            sender=AgentId("a1"),
            recipient=AgentId("a2"),
            payload=b"hello",
            correlation_id=None,
            now=0.0,
            rng=random.Random(1),
            direction="receive",
        )
        result = await chain.on_receive(ctx)
        assert result is not None
        assert result.payload == b"HELLO"


class TestMiddlewareRegistry:
    def test_list_builtins(self) -> None:
        registry = MiddlewareRegistry()
        names = registry.list_middleware()
        assert "resilience" in names
        assert "observability" in names
        assert "auth_scope" in names
        assert "latency" in names

    def test_instantiate_builtin(self) -> None:
        registry = MiddlewareRegistry()
        mw = registry.instantiate("resilience")
        assert isinstance(mw, ResilienceMiddleware)


class TestBuiltinMiddleware:
    @pytest.mark.asyncio
    async def test_resilience_swallows_delivery_errors(self, tmp_path: Path) -> None:
        trace_file = tmp_path / "trace.jsonl"
        sim = Simulator(
            seed=7,
            trace_path=trace_file,
            middleware=[ResilienceMiddleware()],
        )
        sim.add_agent(AgentId("boom"), _BoomAgent())
        sim.add_agent(AgentId("sender"), _StartToBoomAgent())
        await sim.run(max_ticks=10)
        kinds = [json.loads(line)["kind"] for line in trace_file.read_text().splitlines() if line]
        assert "error" in kinds

    @pytest.mark.asyncio
    async def test_observability_counts(self) -> None:
        mw = ObservabilityMiddleware()
        ctx = MessageContext(
            sender=AgentId("a1"),
            recipient=AgentId("a2"),
            payload=b"x",
            correlation_id=None,
            now=0.0,
            rng=random.Random(1),
            direction="send",
        )
        await mw.on_send(ctx)
        await mw.on_receive(ctx)
        assert mw.sent_count == 1
        assert mw.received_count == 1

    @pytest.mark.asyncio
    async def test_auth_scope_denies_missing_plugin(self) -> None:
        mw = AuthScopeMiddleware(config={"required_scope": "read"})
        ctx = MessageContext(
            sender=AgentId("a1"),
            recipient=AgentId("a2"),
            payload=b"plain",
            correlation_id=None,
            now=0.0,
            rng=random.Random(1),
            direction="receive",
            plugins={},
        )
        assert await mw.on_receive(ctx) is None
        assert mw.denied_count == 1

    @pytest.mark.asyncio
    async def test_auth_scope_denies_missing_token(self) -> None:
        auth = JwtAuth(secret=b"secret", clock=0.0)
        mw = AuthScopeMiddleware(config={"required_scope": "read"})
        ctx = MessageContext(
            sender=AgentId("a1"),
            recipient=AgentId("a2"),
            payload=b"plain",
            correlation_id=None,
            now=0.0,
            rng=random.Random(1),
            direction="receive",
            plugins={"auth": auth},
        )
        assert await mw.on_receive(ctx) is None
        assert mw.denied_count == 1

    @pytest.mark.asyncio
    async def test_auth_scope_allows_valid_token(self) -> None:
        auth = JwtAuth(secret=b"secret", clock=0.0)
        token = await auth.issue(AgentId("a1"), ["read"])
        payload = attach_auth_token(b"plain", str(token))
        mw = AuthScopeMiddleware(config={"required_scope": "read"})
        ctx = MessageContext(
            sender=AgentId("a1"),
            recipient=AgentId("a2"),
            payload=payload,
            correlation_id=None,
            now=0.0,
            rng=random.Random(1),
            direction="receive",
            plugins={"auth": auth},
        )
        result = await mw.on_receive(ctx)
        assert result is not None

    @pytest.mark.asyncio
    async def test_latency_sets_deliver_at(self) -> None:
        mw = LatencyMiddleware(config={"base_delay": 0.5, "jitter": 0.0})
        ctx = MessageContext(
            sender=AgentId("a1"),
            recipient=AgentId("a2"),
            payload=b"x",
            correlation_id=None,
            now=1.0,
            rng=random.Random(1),
            direction="send",
        )
        result = await mw.on_send(ctx)
        assert result is not None
        assert result.metadata["deliver_at"] == 1.5


class TestSimulatorMiddlewareIntegration:
    @pytest.mark.asyncio
    async def test_no_middleware_regression_trace(self, tmp_path: Path) -> None:
        traces: list[str] = []
        for _ in range(2):
            trace_file = tmp_path / f"baseline-{len(traces)}.jsonl"
            sim = Simulator(seed=99, trace_path=trace_file)
            sim.add_agent(AgentId("a1"), _EchoAgent())
            sim.add_agent(AgentId("a2"), _EchoAgent())
            await sim.run(max_ticks=20)
            traces.append(trace_file.read_text())
        assert traces[0] == traces[1]

    @pytest.mark.asyncio
    async def test_observability_preserves_determinism(self, tmp_path: Path) -> None:
        traces: list[str] = []
        for _ in range(2):
            trace_file = tmp_path / f"obs-{len(traces)}.jsonl"
            sim = Simulator(
                seed=42,
                trace_path=trace_file,
                middleware=[ObservabilityMiddleware()],
            )
            sim.add_agent(AgentId("a1"), _EchoAgent())
            sim.add_agent(AgentId("a2"), _EchoAgent())
            await sim.run(max_ticks=20)
            traces.append(trace_file.read_text())
        assert traces[0] == traces[1]

    @pytest.mark.asyncio
    async def test_latency_deterministic_traces(self, tmp_path: Path) -> None:
        traces: list[str] = []
        for _ in range(2):
            trace_file = tmp_path / f"lat-{len(traces)}.jsonl"
            sim = Simulator(
                seed=11,
                trace_path=trace_file,
                middleware=[LatencyMiddleware(config={"base_delay": 0.01, "jitter": 0.0})],
            )
            sim.add_agent(AgentId("a1"), _EchoAgent())
            sim.add_agent(AgentId("a2"), _EchoAgent())
            await sim.run(max_ticks=20)
            traces.append(trace_file.read_text())
        assert traces[0] == traces[1]
        assert '"kind":"receive"' in traces[0]

    def test_scenario_middleware_config(self) -> None:
        config = ScenarioConfig.from_dict(
            {
                "name": "mw",
                "middleware": [{"name": "resilience", "config": {}}],
            }
        )
        assert config.middleware[0].name == "resilience"
