# SPDX-License-Identifier: Apache-2.0
"""Tests for The Dealmakers scenario — multi-attribute bargaining with learning."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_core.types import AgentId


class TestDealmakerParams:
    def test_buyer_params_deterministic(self) -> None:
        from nest_core.scenarios_builtin.dealmakers import DealParams

        p1 = DealParams.for_buyer(AgentId("buyer-0"), seed=42, pair_index=0)
        p2 = DealParams.for_buyer(AgentId("buyer-0"), seed=42, pair_index=0)
        assert p1.role == "buyer"
        assert p1.min_p == p2.min_p
        assert p1.max_p == p2.max_p
        assert p1.target_q == p2.target_q
        assert p1.strategy_id == p2.strategy_id

    def test_seller_params_deterministic(self) -> None:
        from nest_core.scenarios_builtin.dealmakers import DealParams

        p1 = DealParams.for_seller(AgentId("seller-0"), seed=42, pair_index=0)
        p2 = DealParams.for_seller(AgentId("seller-0"), seed=42, pair_index=0)
        assert p1.role == "seller"
        assert p1.min_p == p2.min_p
        assert p1.capacity == p2.capacity

    def test_pair_index_varies_params(self) -> None:
        from nest_core.scenarios_builtin.dealmakers import DealParams

        p0 = DealParams.for_buyer(AgentId("buyer-0"), seed=7, pair_index=0)
        p1 = DealParams.for_buyer(AgentId("buyer-0"), seed=7, pair_index=1)
        # Different pair indices should produce different params
        assert p0.target_q != p1.target_q or p0.min_p != p1.min_p

    def test_buyer_utility_range(self) -> None:
        from nest_core.scenarios_builtin.dealmakers import DealParams

        p = DealParams.for_buyer(AgentId("buyer-0"), seed=42, pair_index=0)
        # Utility at reservation should be positive
        u_best = p.utility(p.min_p, p.target_q)
        u_worst = p.utility(p.max_p, p.max_q)
        assert 0.0 <= u_worst <= u_best <= 1.0

    def test_seller_utility_range(self) -> None:
        from nest_core.scenarios_builtin.dealmakers import DealParams

        p = DealParams.for_seller(AgentId("seller-0"), seed=42, pair_index=0)
        u_best = p.utility(p.max_p, p.capacity)
        u_worst = p.utility(p.min_p, p.min_q)
        assert 0.0 <= u_worst <= u_best <= 1.0

    def test_to_dict_roundtrip(self) -> None:
        from nest_core.scenarios_builtin.dealmakers import DealParams

        p = DealParams.for_buyer(AgentId("buyer-2"), seed=13, pair_index=2)
        d = p.to_dict()
        assert d["role"] == "buyer"
        assert "w_p" in d and "w_q" in d
        assert "min_p" in d and "target_q" in d
        # Must be JSON-serialisable
        json.dumps(d)


class TestDealmakerStrategies:
    def test_logrolling_counter_clamps(self) -> None:
        from nest_core.scenarios_builtin.dealmakers import DealParams, logrolling_counter

        p = DealParams.for_buyer(AgentId("buyer-0"), seed=42, pair_index=0)
        cp, cq = logrolling_counter(p, 80, 40, p.min_p, p.min_q, 0.6, 0.4, 1)
        assert p.min_p <= cp <= p.max_p
        assert p.min_q <= cq <= p.max_q

    def test_ttt_mirror_counter_clamps(self) -> None:
        from nest_core.scenarios_builtin.dealmakers import DealParams, ttt_mirror_counter

        p = DealParams.for_buyer(AgentId("buyer-0"), seed=42, pair_index=0)
        cp, cq = ttt_mirror_counter(p, 50, 25, p.min_p + 5, p.min_q + 3, 45, 22)
        assert p.min_p <= cp <= p.max_p
        assert p.min_q <= cq <= p.max_q

    def test_nash_split_counter_clamps(self) -> None:
        from nest_core.scenarios_builtin.dealmakers import DealParams, nash_split_counter

        p = DealParams.for_buyer(AgentId("buyer-0"), seed=42, pair_index=0)
        cp, cq = nash_split_counter(p, 60, 30, p.min_p + 10, p.min_q + 5, 3)
        assert p.min_p <= cp <= p.max_p
        assert p.min_q <= cq <= p.max_q

    def test_decode_offer_valid(self) -> None:
        from nest_core.scenarios_builtin.dealmakers import decode_offer

        result = decode_offer("offer:buyer-0:seller-0:r1:p=42,q=18:logrolling")
        assert result == (42, 18)

    def test_decode_offer_with_comment(self) -> None:
        from nest_core.scenarios_builtin.dealmakers import decode_offer

        result = decode_offer("offer:buyer-0:seller-0:r2:p=35,q=22:ttt_mirror # buyer proposes")
        assert result == (35, 22)

    def test_decode_offer_invalid(self) -> None:
        from nest_core.scenarios_builtin.dealmakers import decode_offer

        assert decode_offer("config:buyer-0:{}") is None
        assert decode_offer("offer:only:three") is None


class TestDealmakerLearning:
    def test_weight_update_ema(self) -> None:
        from nest_core.scenarios_builtin.dealmakers import DealmakerAgent, DealParams

        p = DealParams.for_buyer(AgentId("buyer-0"), seed=42, pair_index=0)
        agent = DealmakerAgent(
            agent_id=AgentId("buyer-0"),
            role="buyer",
            partner_id=AgentId("seller-0"),
            params=p,
            rounds=10,
            open_p=40,
            open_q=20,
        )
        # Initial weights are equal
        wp, wq = agent.opp_weights("seller-0")
        assert abs(wp - 0.5) < 1e-9
        assert abs(wq - 0.5) < 1e-9

        # After a price-heavy session, price weight should increase
        agent.update_opp_weights("seller-0", [10, 8, 6], [1, 0, 1])
        wp2, wq2 = agent.opp_weights("seller-0")
        assert wp2 > 0.5, "price-heavy session should push est_w_p above 0.5"
        assert abs(wp2 + wq2 - 1.0) < 0.01  # weights sum to ~1

    def test_weight_update_persists_per_partner(self) -> None:
        from nest_core.scenarios_builtin.dealmakers import DealmakerAgent, DealParams

        p = DealParams.for_buyer(AgentId("buyer-1"), seed=7, pair_index=1)
        agent = DealmakerAgent(
            agent_id=AgentId("buyer-1"),
            role="buyer",
            partner_id=AgentId("seller-1"),
            params=p,
            rounds=10,
            open_p=40,
            open_q=20,
        )
        agent.update_opp_weights("seller-1", [5, 4], [2, 1])
        agent.update_opp_weights("seller-2", [1, 1], [8, 9])

        wp1, _ = agent.opp_weights("seller-1")
        _, wq2 = agent.opp_weights("seller-2")
        # seller-1 is price-heavy; seller-2 is quantity-heavy
        assert wp1 > 0.5
        assert wq2 > 0.5


class TestDealmakerScenario:
    @pytest.mark.asyncio
    async def test_dealmakers_from_dict(self, tmp_path: Path) -> None:
        trace_file = tmp_path / "dealmakers.jsonl"
        config = ScenarioConfig.from_dict(
            {
                "name": "test-dealmakers",
                "seed": 13,
                "agents": {
                    "count": 4,
                    "roles": [
                        {"name": "buyer", "count": 2},
                        {"name": "seller", "count": 2},
                    ],
                },
                "task": {"type": "dealmakers", "config": {"rounds": 6, "pairs": 2}},
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
        msgs: list[str] = []
        for line in lines:
            event: dict[str, Any] = json.loads(line)
            kinds.add(event["kind"])
            msgs.append(event.get("msg", ""))

        assert "send" in kinds
        assert "receive" in kinds
        # At least one offer must have been sent
        assert any("offer:" in m for m in msgs)

    @pytest.mark.asyncio
    async def test_dealmakers_yaml(self, tmp_path: Path) -> None:
        yaml_path = Path(__file__).parent.parent.parent.parent / "scenarios" / "dealmakers.yaml"
        if not yaml_path.exists():
            pytest.skip("dealmakers.yaml not found")

        config = ScenarioConfig.from_yaml(yaml_path)
        config.output.trace = str(tmp_path / "dealmakers.jsonl")
        config.duration = "ticks: 5000"

        runner = ScenarioRunner(config)
        result = await runner.run()
        assert result.exists()

        content = result.read_text()
        lines = [ln for ln in content.strip().split("\n") if ln]
        assert len(lines) > 10

    @pytest.mark.asyncio
    async def test_dealmakers_deterministic(self, tmp_path: Path) -> None:
        """Two runs with the same seed must produce the same trace."""
        base_cfg: dict[str, Any] = {
            "name": "test-dealmakers-det",
            "seed": 99,
            "agents": {
                "count": 4,
                "roles": [
                    {"name": "buyer", "count": 2},
                    {"name": "seller", "count": 2},
                ],
            },
            "task": {"type": "dealmakers", "config": {"rounds": 5, "pairs": 2}},
            "duration": "ticks: 5000",
            "output": {"trace": str(tmp_path / "run1.jsonl")},
        }
        r1 = await ScenarioRunner(ScenarioConfig.from_dict(base_cfg)).run()
        base_cfg["output"]["trace"] = str(tmp_path / "run2.jsonl")
        r2 = await ScenarioRunner(ScenarioConfig.from_dict(base_cfg)).run()

        msgs1 = [
            json.loads(ln).get("msg", "")
            for ln in r1.read_text().strip().split("\n")
            if ln and json.loads(ln).get("kind") == "send"
        ]
        msgs2 = [
            json.loads(ln).get("msg", "")
            for ln in r2.read_text().strip().split("\n")
            if ln and json.loads(ln).get("kind") == "send"
        ]
        assert msgs1 == msgs2

    @pytest.mark.asyncio
    async def test_dealmakers_validators(self, tmp_path: Path) -> None:
        """Validators must all pass on a clean dealmakers run."""
        from nest_core.validators import validate_events

        trace_file = tmp_path / "dealmakers_val.jsonl"
        config = ScenarioConfig.from_dict(
            {
                "name": "test-dealmakers-val",
                "seed": 13,
                "agents": {
                    "count": 4,
                    "roles": [
                        {"name": "buyer", "count": 2},
                        {"name": "seller", "count": 2},
                    ],
                },
                "task": {"type": "dealmakers", "config": {"rounds": 8, "pairs": 2}},
                "duration": "ticks: 5000",
                "output": {"trace": str(trace_file)},
            }
        )

        result = await ScenarioRunner(config).run()
        events: list[dict[str, Any]] = [
            json.loads(ln) for ln in result.read_text().strip().split("\n") if ln
        ]

        results = validate_events(events, "dealmakers")
        failures = [r for r in results if not r.passed]
        assert not failures, f"Validator failures: {failures}"

    @pytest.mark.asyncio
    async def test_dealmakers_quantity_axis_moves(self, tmp_path: Path) -> None:
        """At least one pair must move the quantity axis — proving Pareto exploration."""
        trace_file = tmp_path / "dealmakers_q.jsonl"
        config = ScenarioConfig.from_dict(
            {
                "name": "test-dealmakers-q",
                "seed": 13,
                "agents": {
                    "count": 8,
                    "roles": [
                        {"name": "buyer", "count": 4},
                        {"name": "seller", "count": 4},
                    ],
                },
                "task": {"type": "dealmakers", "config": {"rounds": 10, "pairs": 4}},
                "duration": "ticks: 5000",
                "output": {"trace": str(trace_file)},
            }
        )

        result = await ScenarioRunner(config).run()

        pair_quantities: dict[str, set[int]] = {}
        for ln in result.read_text().strip().split("\n"):
            if not ln:
                continue
            ev: dict[str, Any] = json.loads(ln)
            if ev.get("kind") != "send":
                continue
            msg = str(ev.get("msg", "")).split(" # ")[0]
            if not msg.startswith("offer:"):
                continue
            parts = msg.split(":")
            if len(parts) < 6:
                continue
            from_ag, to_ag = parts[1], parts[2]
            pk = "__".join(sorted([from_ag, to_ag]))
            attrs = parts[4]
            try:
                kv = dict(item.split("=") for item in attrs.split(","))
                q_val = int(kv["q"])
            except (ValueError, KeyError):
                continue
            pair_quantities.setdefault(pk, set()).add(q_val)

        pairs_with_q_movement = sum(1 for qs in pair_quantities.values() if len(qs) > 1)
        assert pairs_with_q_movement >= 1, (
            "Expected at least one pair to move the quantity axis — "
            "Pareto exploration is not happening"
        )
