# SPDX-License-Identifier: Apache-2.0
"""Tests for auction, voting, consensus, supply-chain, and reputation scenarios."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_core.validators import validate_trace


class TestAuctionScenario:
    @pytest.mark.asyncio
    async def test_auction_from_dict(self, tmp_path: Path) -> None:
        trace_file = tmp_path / "auction.jsonl"
        config = ScenarioConfig.from_dict(
            {
                "name": "test-auction",
                "seed": 42,
                "agents": {
                    "count": 6,
                    "roles": [
                        {"name": "auctioneer", "count": 1},
                        {"name": "bidder", "count": 5},
                    ],
                },
                "task": {"type": "auction", "config": {"rounds": 3}},
                "duration": "ticks: 5000",
                "output": {"trace": str(trace_file)},
            }
        )

        runner = ScenarioRunner(config)
        result = await runner.run()

        assert result.exists()
        content = result.read_text()
        lines = [ln for ln in content.strip().split("\n") if ln]
        assert len(lines) > 0

        kinds: set[str] = set()
        for line in lines:
            event: dict[str, Any] = json.loads(line)
            kinds.add(event["kind"])

        assert "send" in kinds
        assert "receive" in kinds

    @pytest.mark.asyncio
    async def test_auction_yaml(self, tmp_path: Path) -> None:
        yaml_path = Path(__file__).parent.parent.parent.parent / "scenarios" / "auction.yaml"
        if not yaml_path.exists():
            pytest.skip("auction.yaml not found")

        config = ScenarioConfig.from_yaml(yaml_path)
        config.output.trace = str(tmp_path / "auction.jsonl")
        config.duration = "ticks: 5000"

        runner = ScenarioRunner(config)
        result = await runner.run()
        assert result.exists()

        content = result.read_text()
        lines = [ln for ln in content.strip().split("\n") if ln]
        assert len(lines) > 10


class TestVotingScenario:
    @pytest.mark.asyncio
    async def test_voting_from_dict(self, tmp_path: Path) -> None:
        trace_file = tmp_path / "voting.jsonl"
        config = ScenarioConfig.from_dict(
            {
                "name": "test-voting",
                "seed": 42,
                "agents": {
                    "count": 12,
                    "roles": [
                        {"name": "proposer", "count": 1},
                        {"name": "coordinator", "count": 1},
                        {"name": "voter", "count": 10},
                    ],
                },
                "task": {"type": "voting", "config": {"rounds": 3, "threshold": 0.5}},
                "duration": "ticks: 5000",
                "output": {"trace": str(trace_file)},
            }
        )

        runner = ScenarioRunner(config)
        result = await runner.run()

        assert result.exists()
        content = result.read_text()
        lines = [ln for ln in content.strip().split("\n") if ln]
        assert len(lines) > 0

        kinds: set[str] = set()
        for line in lines:
            event: dict[str, Any] = json.loads(line)
            kinds.add(event["kind"])

        assert "send" in kinds
        assert "receive" in kinds

    @pytest.mark.asyncio
    async def test_voting_yaml(self, tmp_path: Path) -> None:
        yaml_path = Path(__file__).parent.parent.parent.parent / "scenarios" / "voting.yaml"
        if not yaml_path.exists():
            pytest.skip("voting.yaml not found")

        config = ScenarioConfig.from_yaml(yaml_path)
        config.output.trace = str(tmp_path / "voting.jsonl")
        config.duration = "ticks: 5000"

        runner = ScenarioRunner(config)
        result = await runner.run()
        assert result.exists()

        content = result.read_text()
        lines = [ln for ln in content.strip().split("\n") if ln]
        assert len(lines) > 10

    @pytest.mark.asyncio
    async def test_voting_deterministic(self, tmp_path: Path) -> None:
        traces: list[str] = []
        for i in range(2):
            trace_file = tmp_path / f"vote_{i}.jsonl"
            config = ScenarioConfig.from_dict(
                {
                    "name": "det-vote",
                    "seed": 77,
                    "agents": {
                        "count": 7,
                        "roles": [
                            {"name": "proposer", "count": 1},
                            {"name": "coordinator", "count": 1},
                            {"name": "voter", "count": 5},
                        ],
                    },
                    "task": {"type": "voting", "config": {"rounds": 2}},
                    "duration": "ticks: 3000",
                    "output": {"trace": str(trace_file)},
                }
            )
            runner = ScenarioRunner(config)
            await runner.run()
            traces.append(trace_file.read_text())

        assert traces[0] == traces[1]
        assert len(traces[0]) > 0


class TestRoboAgentGuardScenario:
    @pytest.mark.asyncio
    async def test_roboagent_guard_yaml_passes_validators(self, tmp_path: Path) -> None:
        yaml_path = (
            Path(__file__).parent.parent.parent.parent / "scenarios" / "roboagent_guard.yaml"
        )
        config = ScenarioConfig.from_yaml(yaml_path)
        config.output.trace = str(tmp_path / "roboagent_guard.jsonl")

        runner = ScenarioRunner(config)
        trace_path = await runner.run()

        results = validate_trace(trace_path, "roboagent_guard")
        assert all(result.passed for result in results), results

    @pytest.mark.asyncio
    async def test_roboagent_guard_noop_privacy_fails_validators(self, tmp_path: Path) -> None:
        yaml_path = (
            Path(__file__).parent.parent.parent.parent / "scenarios" / "roboagent_guard.yaml"
        )
        config = ScenarioConfig.from_yaml(yaml_path)
        config.layers.privacy = "noop"
        config.output.trace = str(tmp_path / "roboagent_guard_noop.jsonl")

        runner = ScenarioRunner(config)
        trace_path = await runner.run()

        results = validate_trace(trace_path, "roboagent_guard")
        assert [result.passed for result in results] == [False, False]

    @pytest.mark.asyncio
    async def test_roboagent_guard_unsafe_config_fails_validators(
        self,
        tmp_path: Path,
    ) -> None:
        trace_file = tmp_path / "roboagent_guard_unsafe.jsonl"
        config = ScenarioConfig.from_dict(
            {
                "name": "test-roboagent-unsafe",
                "seed": 42,
                "agents": {
                    "count": 4,
                    "roles": [
                        {"name": "planner", "count": 1},
                        {"name": "vision", "count": 1},
                        {"name": "robot", "count": 1},
                        {"name": "mapper", "count": 1},
                    ],
                },
                "layers": {"privacy": "sensor_redaction"},
                "task": {"type": "roboagent_guard", "config": {"unsafe": True}},
                "duration": "ticks: 1000",
                "output": {"trace": str(trace_file)},
            }
        )

        runner = ScenarioRunner(config)
        trace_path = await runner.run()

        results = validate_trace(trace_path, "roboagent_guard")
        assert [result.passed for result in results] == [False, True]


class TestConsensusScenario:
    @pytest.mark.asyncio
    async def test_consensus_from_dict(self, tmp_path: Path) -> None:
        trace_file = tmp_path / "consensus.jsonl"
        config = ScenarioConfig.from_dict(
            {
                "name": "test-consensus",
                "seed": 42,
                "agents": {
                    "count": 8,
                    "roles": [
                        {"name": "leader", "count": 1},
                        {"name": "follower", "count": 7},
                    ],
                },
                "task": {
                    "type": "consensus",
                    "config": {"rounds": 3, "quorum": 0.667},
                },
                "duration": "ticks: 5000",
                "output": {"trace": str(trace_file)},
            }
        )

        runner = ScenarioRunner(config)
        result = await runner.run()

        assert result.exists()
        content = result.read_text()
        lines = [ln for ln in content.strip().split("\n") if ln]
        assert len(lines) > 0

        kinds: set[str] = set()
        for line in lines:
            event: dict[str, Any] = json.loads(line)
            kinds.add(event["kind"])

        assert "send" in kinds
        assert "receive" in kinds

    @pytest.mark.asyncio
    async def test_consensus_yaml(self, tmp_path: Path) -> None:
        yaml_path = Path(__file__).parent.parent.parent.parent / "scenarios" / "consensus.yaml"
        if not yaml_path.exists():
            pytest.skip("consensus.yaml not found")

        config = ScenarioConfig.from_yaml(yaml_path)
        config.output.trace = str(tmp_path / "consensus.jsonl")
        config.duration = "ticks: 5000"

        runner = ScenarioRunner(config)
        result = await runner.run()
        assert result.exists()

        content = result.read_text()
        lines = [ln for ln in content.strip().split("\n") if ln]
        assert len(lines) > 10


class TestSupplyChainScenario:
    @pytest.mark.asyncio
    async def test_supply_chain_from_dict(self, tmp_path: Path) -> None:
        trace_file = tmp_path / "supply_chain.jsonl"
        config = ScenarioConfig.from_dict(
            {
                "name": "test-supply-chain",
                "seed": 42,
                "agents": {
                    "count": 4,
                    "roles": [
                        {"name": "supplier", "count": 1},
                        {"name": "manufacturer", "count": 1},
                        {"name": "distributor", "count": 1},
                        {"name": "retailer", "count": 1},
                    ],
                },
                "task": {
                    "type": "supply_chain",
                    "config": {"items_per_round": 2, "rounds": 3},
                },
                "duration": "ticks: 5000",
                "output": {"trace": str(trace_file)},
            }
        )

        runner = ScenarioRunner(config)
        result = await runner.run()

        assert result.exists()
        content = result.read_text()
        lines = [ln for ln in content.strip().split("\n") if ln]
        assert len(lines) > 0

        kinds: set[str] = set()
        for line in lines:
            event: dict[str, Any] = json.loads(line)
            kinds.add(event["kind"])

        assert "send" in kinds
        assert "receive" in kinds

    @pytest.mark.asyncio
    async def test_supply_chain_yaml(self, tmp_path: Path) -> None:
        yaml_path = Path(__file__).parent.parent.parent.parent / "scenarios" / "supply_chain.yaml"
        if not yaml_path.exists():
            pytest.skip("supply_chain.yaml not found")

        config = ScenarioConfig.from_yaml(yaml_path)
        config.output.trace = str(tmp_path / "supply_chain.jsonl")
        config.duration = "ticks: 5000"

        runner = ScenarioRunner(config)
        result = await runner.run()
        assert result.exists()

        content = result.read_text()
        lines = [ln for ln in content.strip().split("\n") if ln]
        assert len(lines) > 10


class TestReputationScenario:
    @pytest.mark.asyncio
    async def test_reputation_from_dict(self, tmp_path: Path) -> None:
        trace_file = tmp_path / "reputation.jsonl"
        config = ScenarioConfig.from_dict(
            {
                "name": "test-reputation",
                "seed": 42,
                "agents": {
                    "count": 6,
                    "roles": [
                        {"name": "honest", "count": 3},
                        {"name": "malicious", "count": 2},
                        {"name": "observer", "count": 1},
                    ],
                },
                "task": {
                    "type": "reputation",
                    "config": {"rounds": 3, "malicious_fraction": 0.4},
                },
                "duration": "ticks: 5000",
                "output": {"trace": str(trace_file)},
            }
        )

        runner = ScenarioRunner(config)
        result = await runner.run()

        assert result.exists()
        content = result.read_text()
        lines = [ln for ln in content.strip().split("\n") if ln]
        assert len(lines) > 0

        kinds: set[str] = set()
        for line in lines:
            event: dict[str, Any] = json.loads(line)
            kinds.add(event["kind"])

        assert "send" in kinds
        assert "receive" in kinds

    @pytest.mark.asyncio
    async def test_reputation_yaml(self, tmp_path: Path) -> None:
        yaml_path = Path(__file__).parent.parent.parent.parent / "scenarios" / "reputation.yaml"
        if not yaml_path.exists():
            pytest.skip("reputation.yaml not found")

        config = ScenarioConfig.from_yaml(yaml_path)
        config.output.trace = str(tmp_path / "reputation.jsonl")
        config.duration = "ticks: 5000"

        runner = ScenarioRunner(config)
        result = await runner.run()
        assert result.exists()

        content = result.read_text()
        lines = [ln for ln in content.strip().split("\n") if ln]
        assert len(lines) > 10
