# SPDX-License-Identifier: Apache-2.0

"""Tests for HTTP transport, trace merge, and distributed workers."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from nest_core.runner import ScenarioRunner, build_routes
from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.sim.network_runner import RoutedTransport, WorkerHttpBridge, check_health
from nest_core.sim.partition import partition_agents
from nest_core.sim.plugin_rpc import RegistryRpcServer, RemoteRegistry
from nest_core.sim.simulator import Simulator
from nest_core.sim.trace_merge import merge_traces
from nest_core.types import AgentCard, AgentId, Query
from nest_plugins_reference.registry.in_memory import InMemoryRegistry


class _EchoAgent(StateMachineAgent):
    async def on_start(self, ctx: AgentContext) -> None:

        if str(ctx.agent_id) == "a0":
            await ctx.send(AgentId("a1"), b"ping")

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:

        if str(ctx.agent_id) == "a1":
            await ctx.send(sender, b"pong")


class TestTraceMerge:
    def test_merge_sorts_by_timestamp(self, tmp_path: Path) -> None:

        a = tmp_path / "a.jsonl"

        b = tmp_path / "b.jsonl"

        a.write_text('{"ts":2.0,"agent":"x","kind":"send"}\n')

        b.write_text('{"ts":1.0,"agent":"y","kind":"send"}\n')

        out = tmp_path / "merged.jsonl"

        merge_traces([a, b], out)

        lines = out.read_text().strip().split("\n")

        assert len(lines) == 2

        assert '"ts":1.0' in lines[0]

        assert '"sequence":0' in lines[0]


class TestPartitionRoutes:
    def test_advertise_host_from_worker_hosts(self, tmp_path: Path) -> None:

        ids = [AgentId(f"a{i}") for i in range(4)]

        parts = partition_agents(
            ids,
            2,
            master_seed=1,
            trace_dir=tmp_path,
            bind_host="0.0.0.0",
            worker_hosts=["10.0.0.2", "10.0.0.3"],
        )

        assert parts[0].advertise_host == "10.0.0.2"

        assert parts[1].advertise_host == "10.0.0.3"

        assert parts[0].bind_host == "0.0.0.0"

        routes = build_routes(parts)

        assert routes[AgentId("a0")].startswith("http://10.0.0.2:")

        assert routes[AgentId("a1")].startswith("http://10.0.0.3:")


class TestHealthEndpoint:
    @pytest.mark.asyncio
    async def test_worker_bridge_health(self) -> None:

        sim = Simulator(seed=1, trace_path=None, parallel=True)

        bridge = WorkerHttpBridge(sim.event_queue, sim.clock)

        port = await bridge.start(0, host="127.0.0.1")

        try:
            ok = await check_health(f"http://127.0.0.1:{port}")

            assert ok is True

        finally:
            await bridge.stop()


class TestHttpRouting:
    @pytest.mark.asyncio
    async def test_two_worker_http_ping_pong(self, tmp_path: Path) -> None:

        trace0 = tmp_path / "w0.jsonl"

        trace1 = tmp_path / "w1.jsonl"

        sim0 = Simulator(seed=42, trace_path=trace0, parallel=True)

        sim1 = Simulator(seed=43, trace_path=trace1, parallel=True)

        bridge0 = WorkerHttpBridge(sim0.event_queue, sim0.clock)

        bridge1 = WorkerHttpBridge(sim1.event_queue, sim1.clock)

        port0 = await bridge0.start(0)

        port1 = await bridge1.start(0)

        routes = {
            AgentId("a0"): f"http://127.0.0.1:{port0}",
            AgentId("a1"): f"http://127.0.0.1:{port1}",
        }

        local0 = {AgentId("a0")}

        local1 = {AgentId("a1")}

        def factory0(
            agent_id: AgentId,
            queue: object,
            clock: object,
            all_ids: list[AgentId],
        ) -> RoutedTransport:

            return RoutedTransport(
                agent_id,
                queue,  # type: ignore[arg-type]
                clock,  # type: ignore[arg-type]
                all_ids,
                local_agents=local0,
                routes=routes,
            )

        def factory1(
            agent_id: AgentId,
            queue: object,
            clock: object,
            all_ids: list[AgentId],
        ) -> RoutedTransport:

            return RoutedTransport(
                agent_id,
                queue,  # type: ignore[arg-type]
                clock,  # type: ignore[arg-type]
                all_ids,
                local_agents=local1,
                routes=routes,
            )

        sim0.set_transport_factory(factory0)

        sim1.set_transport_factory(factory1)

        sim0.add_agent(AgentId("a0"), _EchoAgent())

        sim1.add_agent(AgentId("a1"), _EchoAgent())

        await asyncio.gather(sim0.run(max_ticks=200), sim1.run(max_ticks=200))

        await bridge0.stop()

        await bridge1.stop()

        merged = tmp_path / "merged.jsonl"

        merge_traces([trace0, trace1], merged)

        text = merged.read_text()

        assert "receive" in text or "send" in text


class TestRegistryRpc:
    @pytest.mark.asyncio
    async def test_remote_registry_round_trip(self) -> None:

        server = RegistryRpcServer(InMemoryRegistry())

        port = await server.start("127.0.0.1", 0)

        client = RemoteRegistry(f"http://127.0.0.1:{port}")

        card = AgentCard(
            agent_id=AgentId("seller-0"),
            name="seller",
            capabilities=["sell"],
        )

        try:
            await client.register(card)

            found = await client.lookup(Query(capabilities=["sell"]))

            assert any(str(c.agent_id) == "seller-0" for c in found)

        finally:
            await server.stop()


class TestDistributedRunner:
    @pytest.fixture(autouse=True)
    def _http_shared_secret(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("NEST_HTTP_SHARED_SECRET", "test-dist-secret")

    @pytest.mark.asyncio
    async def test_two_worker_marketplace(self, tmp_path: Path) -> None:

        trace_file = tmp_path / "market.jsonl"

        config = ScenarioConfig.from_dict(
            {
                "name": "dist-market",
                "seed": 42,
                "workers": 2,
                "parallel": True,
                "agents": {
                    "count": 10,
                    "roles": [
                        {"name": "buyer", "count": 5},
                        {"name": "seller", "count": 5},
                    ],
                },
                "task": {"type": "marketplace", "config": {"rounds": 2}},
                "duration": "ticks: 1500",
                "output": {"trace": str(trace_file)},
            }
        )

        runner = ScenarioRunner(config)

        result = await runner.run()

        assert result.exists()

        assert result.read_text().strip()

        manifest_dir = trace_file.parent / f".{config.name}-workers"

        assert (manifest_dir / "routes.json").exists()

        assert (manifest_dir / "worker-0-spec.json").exists()

    @pytest.mark.asyncio
    async def test_manual_worker_mode(self, tmp_path: Path) -> None:

        trace_file = tmp_path / "manual.jsonl"

        trace_dir = trace_file.parent / ".dist-manual-workers"

        trace_dir.mkdir(parents=True)

        (trace_dir / "worker-0.jsonl").write_text(
            '{"ts":1.0,"agent":"a0","kind":"send","sequence":0}\n',
            encoding="utf-8",
        )

        (trace_dir / "worker-1.jsonl").write_text(
            '{"ts":2.0,"agent":"a1","kind":"send","sequence":0}\n',
            encoding="utf-8",
        )

        config = ScenarioConfig.from_dict(
            {
                "name": "dist-manual",
                "seed": 7,
                "workers": 2,
                "parallel": True,
                "worker_mode": "manual",
                "agents": {"count": 4, "roles": [{"name": "buyer", "count": 4}]},
                "task": {"type": "marketplace", "config": {"rounds": 1}},
                "duration": "ticks: 100",
                "output": {"trace": str(trace_file)},
            }
        )

        runner = ScenarioRunner(config)

        result = await runner.run()

        assert result.exists()

        lines = result.read_text().strip().split("\n")

        assert len(lines) == 2

    @pytest.mark.asyncio
    async def test_shared_registry_marketplace(self, tmp_path: Path) -> None:

        trace_file = tmp_path / "shared-reg.jsonl"

        config = ScenarioConfig.from_dict(
            {
                "name": "shared-reg",
                "seed": 99,
                "workers": 2,
                "parallel": True,
                "distributed": {"shared_registry": True},
                "agents": {
                    "count": 6,
                    "roles": [
                        {"name": "buyer", "count": 3},
                        {"name": "seller", "count": 3},
                    ],
                },
                "task": {"type": "marketplace", "config": {"rounds": 2}},
                "duration": "ticks: 2000",
                "output": {"trace": str(trace_file)},
            }
        )

        runner = ScenarioRunner(config)

        result = await runner.run()

        text = result.read_text()

        assert result.exists()

        assert text.strip()

        assert "register" in text.lower() or "lookup" in text.lower() or "send" in text
