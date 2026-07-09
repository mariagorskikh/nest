# SPDX-License-Identifier: Apache-2.0
"""Tests for scenario loading, plugin resolution, and end-to-end marketplace run."""

from __future__ import annotations

import json
import random
from pathlib import Path
from typing import Any

import pytest
from nest_core.plugins import PluginRegistry
from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_core.types import AgentId
from nest_core.validators import validate_trace


class _FakeAgentContext:
    def __init__(self, agent_id: AgentId, plugins: dict[str, Any]) -> None:
        self.agent_id = agent_id
        self.time = 0.0
        self.rng = random.Random(1)
        self.plugins = plugins
        self.sent: list[tuple[AgentId, bytes]] = []

    async def send(self, to: AgentId, payload: bytes) -> None:
        self.sent.append((to, payload))

    async def broadcast(self, payload: bytes) -> None:
        self.sent.append((AgentId("*"), payload))

    async def schedule(self, delay: float, payload: bytes) -> None:
        self.sent.append((AgentId(f"self-after-{delay}"), payload))


# ---------------------------------------------------------------------------
# Scenario schema tests
# ---------------------------------------------------------------------------


class TestScenarioConfig:
    def test_from_dict_defaults(self) -> None:
        config = ScenarioConfig.from_dict({"name": "test"})
        assert config.name == "test"
        assert config.tier == 1
        assert config.agents.count == 10
        assert config.layers.transport == "in_memory"

    def test_get_max_ticks(self) -> None:
        config = ScenarioConfig.from_dict({"name": "t", "duration": "ticks: 5000"})
        assert config.get_max_ticks() == 5000

    def test_from_yaml(self, tmp_path: Path) -> None:
        yaml_file = tmp_path / "test.yaml"
        yaml_file.write_text("name: yaml-test\ntier: 1\nseed: 99\n")
        config = ScenarioConfig.from_yaml(yaml_file)
        assert config.name == "yaml-test"
        assert config.seed == 99

    def test_roles_parsed(self) -> None:
        config = ScenarioConfig.from_dict(
            {
                "name": "roles-test",
                "agents": {
                    "count": 100,
                    "roles": [
                        {"name": "buyer", "count": 50},
                        {"name": "seller", "count": 50},
                    ],
                },
            }
        )
        assert len(config.agents.roles) == 2
        assert config.agents.roles[0].name == "buyer"
        assert config.agents.roles[1].count == 50

    def test_rejects_invalid_failure_rates(self) -> None:
        with pytest.raises(ValueError, match="between 0 and 1"):
            ScenarioConfig.from_dict({"name": "bad", "failures": {"message_drop": 1.5}})

    def test_rejects_negative_role_count(self) -> None:
        with pytest.raises(ValueError, match="role count"):
            ScenarioConfig.from_dict(
                {"name": "bad", "agents": {"roles": [{"name": "buyer", "count": -1}]}}
            )

    def test_rejects_invalid_duration(self) -> None:
        with pytest.raises(ValueError, match="duration"):
            ScenarioConfig.from_dict({"name": "bad", "duration": "seconds: 10"})


# ---------------------------------------------------------------------------
# Plugin registry tests
# ---------------------------------------------------------------------------


class TestPluginRegistry:
    def test_resolve_builtin(self) -> None:
        reg = PluginRegistry()
        cls = reg.resolve("memory", "blackboard")
        assert cls.__name__ == "Blackboard"

    def test_resolve_all_defaults(self) -> None:
        reg = PluginRegistry()
        for layer, name in [
            ("transport", "in_memory"),
            ("comms", "nest_native"),
            ("identity", "did_key"),
            ("registry", "in_memory"),
            ("auth", "jwt"),
            ("trust", "score_average"),
            ("payments", "prepaid_credits"),
            ("coordination", "contract_net"),
            ("negotiation", "alternating_offers"),
            ("memory", "blackboard"),
            ("privacy", "noop"),
            ("datafacts", "datafacts_v1"),
        ]:
            cls = reg.resolve(layer, name)
            assert cls is not None, f"Failed to resolve {layer}/{name}"

    def test_resolve_missing(self) -> None:
        reg = PluginRegistry()
        with pytest.raises(KeyError, match="No plugin found"):
            reg.resolve("payments", "nonexistent")

    def test_list_plugins(self) -> None:
        reg = PluginRegistry()
        plugins = reg.list_plugins("payments")
        assert ("payments", "prepaid_credits") in plugins
        assert ("payments", "empic_escrow") in plugins


# ---------------------------------------------------------------------------
# End-to-end marketplace scenario
# ---------------------------------------------------------------------------


class TestMarketplaceScenario:
    @pytest.mark.asyncio
    async def test_seller_ignores_invalid_signature(self) -> None:
        from nest_core.scenarios_builtin.marketplace import SellerAgent
        from nest_plugins_reference.identity.did_key import DidKeyIdentity

        seller_id = AgentId("seller-0")
        buyer_id = AgentId("buyer-0")
        seller_identity = DidKeyIdentity(seller_id, seed=b"sim-seed")
        buyer_identity = DidKeyIdentity(buyer_id, seed=b"sim-seed")
        seller_identity.register_peer(buyer_id, buyer_identity.public_key)
        ctx = _FakeAgentContext(seller_id, {"identity": seller_identity})

        seller = SellerAgent(seller_id, min_price=10)
        await seller.on_message(ctx, buyer_id, b"buy:product-0:50|sig:00")

        assert ctx.sent == []

    @pytest.mark.asyncio
    async def test_marketplace_from_dict(self, tmp_path: Path) -> None:
        trace_file = tmp_path / "trace.jsonl"
        config = ScenarioConfig.from_dict(
            {
                "name": "test-marketplace",
                "seed": 42,
                "agents": {
                    "count": 20,
                    "roles": [
                        {"name": "buyer", "count": 10},
                        {"name": "seller", "count": 10},
                    ],
                },
                "task": {"type": "marketplace", "config": {"rounds": 5}},
                "duration": "ticks: 5000",
                "output": {"trace": str(trace_file)},
            }
        )

        runner = ScenarioRunner(config)
        result_path = await runner.run()

        assert result_path.exists()
        content = result_path.read_text()
        lines = [ln for ln in content.strip().split("\n") if ln]
        assert len(lines) > 0

        validations = validate_trace(result_path, "marketplace")
        assert all(r.passed for r in validations), validations

        payments = runner.resolved_plugins["payments"]
        assert len(payments._payments) > 0  # noqa: SLF001
        balances = payments._balances  # noqa: SLF001
        assert any(
            balance < 1000 for aid, balance in balances.items() if str(aid).startswith("buyer-")
        )
        assert any(
            balance > 1000 for aid, balance in balances.items() if str(aid).startswith("seller-")
        )

        for line in lines:
            event = json.loads(line)
            assert "ts" in event
            assert "agent" in event
            assert "kind" in event

    @pytest.mark.asyncio
    async def test_marketplace_yaml(self, tmp_path: Path) -> None:
        """Load and run the actual marketplace.yaml scenario."""
        yaml_path = Path(__file__).parent.parent.parent.parent / "scenarios" / "marketplace.yaml"
        if not yaml_path.exists():
            pytest.skip("marketplace.yaml not found")

        config = ScenarioConfig.from_yaml(yaml_path)
        config.output.trace = str(tmp_path / "marketplace.jsonl")
        config.duration = "ticks: 5000"

        runner = ScenarioRunner(config)
        result_path = await runner.run()

        assert result_path.exists()
        content = result_path.read_text()
        lines = [ln for ln in content.strip().split("\n") if ln]
        assert len(lines) > 20

    @pytest.mark.asyncio
    async def test_marketplace_deterministic(self, tmp_path: Path) -> None:
        """Same config + seed produces identical traces."""
        traces: list[str] = []
        for i in range(2):
            trace_file = tmp_path / f"trace_{i}.jsonl"
            config = ScenarioConfig.from_dict(
                {
                    "name": "det-test",
                    "seed": 123,
                    "agents": {"count": 10},
                    "task": {"type": "marketplace", "config": {"rounds": 3}},
                    "duration": "ticks: 2000",
                    "output": {"trace": str(trace_file)},
                }
            )
            runner = ScenarioRunner(config)
            await runner.run()
            traces.append(trace_file.read_text())

        assert traces[0] == traces[1]
        assert len(traces[0]) > 0


class TestEmpicPaymentsScenario:
    """End-to-end checks for the EMPIC payments scenario."""

    @pytest.mark.asyncio
    async def test_empic_payments_yaml(self, tmp_path: Path) -> None:
        """Run the EMPIC weather market and validate escrow invariants."""
        yaml_path = Path(__file__).parent.parent.parent.parent / "scenarios" / "empic_payments.yaml"
        config = ScenarioConfig.from_yaml(yaml_path)
        config.output.trace = str(tmp_path / "empic_payments.jsonl")
        config.duration = "ticks: 2000"

        runner = ScenarioRunner(config)
        result_path = await runner.run()

        assert result_path.exists()
        validations = validate_trace(result_path, "empic_payments")
        assert all(r.passed for r in validations), validations

        payments = runner.resolved_plugins["payments"]
        assert len(payments._payments) == 6  # noqa: SLF001
        assert payments.balance(AgentId("empic-escrow")) == 0
        assert payments.balance(AgentId("provider-0")) > 1000
        assert payments.balance(AgentId("provider-1")) == 1000
        assert payments.balance(AgentId("provider-4")) > 1000
        assert payments.balance(AgentId("provider-5")) == 1000

    @pytest.mark.asyncio
    async def test_empic_payments_partition_yaml(self, tmp_path: Path) -> None:
        """Run the partition variant and confirm overbilling does not occur."""
        yaml_path = (
            Path(__file__).parent.parent.parent.parent
            / "scenarios"
            / "empic_payments_partition.yaml"
        )
        config = ScenarioConfig.from_yaml(yaml_path)
        config.output.trace = str(tmp_path / "empic_payments_partition.jsonl")
        config.duration = "ticks: 2000"

        runner = ScenarioRunner(config)
        result_path = await runner.run()

        validations = validate_trace(result_path, "empic_payments")
        assert all(r.passed for r in validations), validations
