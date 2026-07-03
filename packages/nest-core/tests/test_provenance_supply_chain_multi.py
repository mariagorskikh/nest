# SPDX-License-Identifier: Apache-2.0
"""Tests for the provenance_supply_chain_multi scenario.

Verifies:
- configurable supplier count works
- configurable manufacturer count works
- scenario executes successfully end-to-end
- provenance validation passes with cid_facts
- determinism is preserved across repeated runs with the same seed
- the existing diamond scenario (provenance_supply_chain) is untouched
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_core.validators import validate_trace

type Event = dict[str, Any]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run(
    out: Path,
    num_suppliers: int = 2,
    num_manufacturers: int = 2,
    datafacts: str = "cid_facts",
    seed: int = 42,
) -> None:
    """Run the multi scenario with configurable parameters."""
    cfg = ScenarioConfig.from_yaml("scenarios/provenance_supply_chain_multi.yaml")
    cfg.layers.datafacts = datafacts
    cfg.seed = seed
    cfg.output.trace = str(out)
    cfg.task.config = {
        "num_suppliers": num_suppliers,
        "num_manufacturers": num_manufacturers,
    }
    asyncio.run(ScenarioRunner(cfg).run())


def _chain_ok_depth(trace: Path) -> int | None:
    """Return the lineage depth reported by the first chain_ok message, or None."""
    for line in trace.read_text().splitlines():
        msg = str(json.loads(line).get("msg", ""))
        if msg.startswith("chain_ok|"):
            parts = msg.split("|")
            if len(parts) >= 3:
                return int(parts[2])
    return None


# ---------------------------------------------------------------------------
# Unit: configurable supplier / manufacturer count
# ---------------------------------------------------------------------------


class TestConfigurableTopology:
    def test_factory_default_counts(self, tmp_path: Path) -> None:
        """Default 2×2 topology completes without error."""
        out = tmp_path / "default.jsonl"
        _run(out, num_suppliers=2, num_manufacturers=2)
        assert out.exists()

    def test_factory_three_suppliers(self, tmp_path: Path) -> None:
        """3 suppliers → 2 manufacturers topology executes and passes."""
        out = tmp_path / "3s2m.jsonl"
        _run(out, num_suppliers=3, num_manufacturers=2)
        results = validate_trace(out, "provenance_supply_chain_multi")
        assert results, "expected validators to run"
        assert all(r.passed for r in results), [r.detail for r in results if not r.passed]

    def test_factory_one_supplier_three_manufacturers(self, tmp_path: Path) -> None:
        """1 supplier → 3 manufacturers topology executes and passes."""
        out = tmp_path / "1s3m.jsonl"
        _run(out, num_suppliers=1, num_manufacturers=3)
        results = validate_trace(out, "provenance_supply_chain_multi")
        assert results, "expected validators to run"
        assert all(r.passed for r in results), [r.detail for r in results if not r.passed]

    def test_factory_one_supplier_one_manufacturer(self, tmp_path: Path) -> None:
        """Minimal 1×1 topology (degenerate, no fan) executes and passes."""
        out = tmp_path / "1s1m.jsonl"
        _run(out, num_suppliers=1, num_manufacturers=1)
        results = validate_trace(out, "provenance_supply_chain_multi")
        assert results, "expected validators to run"
        assert all(r.passed for r in results), [r.detail for r in results if not r.passed]


# ---------------------------------------------------------------------------
# Unit: factory rejects invalid arguments
# ---------------------------------------------------------------------------


class TestFactoryValidation:
    def test_zero_suppliers_raises(self) -> None:
        """num_suppliers=0 must raise ValueError before any agent is created."""
        import pytest
        from nest_core.scenario import ScenarioConfig
        from nest_core.scenarios import get_scenario_factory

        cfg = ScenarioConfig.from_yaml("scenarios/provenance_supply_chain_multi.yaml")
        cfg.task.config = {"num_suppliers": 0, "num_manufacturers": 2}
        factory = get_scenario_factory("provenance_supply_chain_multi")
        with pytest.raises(ValueError, match="num_suppliers"):
            factory(cfg, {})

    def test_zero_manufacturers_raises(self) -> None:
        """num_manufacturers=0 must raise ValueError before any agent is created."""
        import pytest
        from nest_core.scenario import ScenarioConfig
        from nest_core.scenarios import get_scenario_factory

        cfg = ScenarioConfig.from_yaml("scenarios/provenance_supply_chain_multi.yaml")
        cfg.task.config = {"num_suppliers": 2, "num_manufacturers": 0}
        factory = get_scenario_factory("provenance_supply_chain_multi")
        with pytest.raises(ValueError, match="num_manufacturers"):
            factory(cfg, {})


class TestScenarioEndToEnd:
    def test_cid_facts_passes_all(self, tmp_path: Path) -> None:
        """cid_facts with default 2×2 topology passes all four provenance validators."""
        out = tmp_path / "cid_facts.jsonl"
        _run(out, num_suppliers=2, num_manufacturers=2)
        results = validate_trace(out, "provenance_supply_chain_multi")
        assert results, "expected validators to run"
        assert all(r.passed for r in results), [r.detail for r in results if not r.passed]

    def test_dag_walk_covers_full_lineage(self, tmp_path: Path) -> None:
        """The DAG walk must visit all nodes: 2 suppliers + 2 manufacturers + 1 distributor = 5."""
        out = tmp_path / "cid_facts.jsonl"
        _run(out, num_suppliers=2, num_manufacturers=2)
        depth = _chain_ok_depth(out)
        assert depth is not None, "no chain_ok recorded in trace"
        # 2 suppliers + 2 manufacturers + 1 distributor = 5 distinct lineage nodes
        assert depth == 5, f"expected depth 5, got {depth}"

    def test_dag_walk_three_suppliers(self, tmp_path: Path) -> None:
        """3×2 topology: 3 suppliers + 2 manufacturers + 1 distributor = 6 nodes."""
        out = tmp_path / "3s2m.jsonl"
        _run(out, num_suppliers=3, num_manufacturers=2)
        depth = _chain_ok_depth(out)
        assert depth is not None, "no chain_ok recorded in trace"
        # Each manufacturer lists all 3 supplier URLs as parents, but the
        # BFS de-duplicates. Total unique nodes = 3+2+1 = 6.
        assert depth == 6, f"expected depth 6, got {depth}"

    def test_datafacts_v1_fails_adversarial_checks(self, tmp_path: Path) -> None:
        """datafacts_v1 passes the chain walk but fails all three attack validators."""
        out = tmp_path / "v1.jsonl"
        _run(out, datafacts="datafacts_v1")
        results = {r.name: r.passed for r in validate_trace(out, "provenance_supply_chain_multi")}
        # The happy-path walk still succeeds — v1 stores parents in metadata.
        assert results["provenance_chain_integrity"] is True
        assert results["provenance_substitution_resistant"] is False
        assert results["provenance_freshness_unforgeable"] is False
        assert results["provenance_chain_unforgeable"] is False


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_deterministic_across_required_seeds(self, tmp_path: Path) -> None:
        """Identical seeds produce byte-identical traces."""
        for seed in (42, 7, 1337):
            a = tmp_path / f"{seed}a.jsonl"
            b = tmp_path / f"{seed}b.jsonl"
            _run(a, seed=seed)
            _run(b, seed=seed)
            assert a.read_bytes() == b.read_bytes(), f"seed {seed} not deterministic"
            assert all(r.passed for r in validate_trace(a, "provenance_supply_chain_multi"))


# ---------------------------------------------------------------------------
# Non-regression: diamond scenario untouched
# ---------------------------------------------------------------------------


class TestDiamondScenarioUnchanged:
    def test_diamond_still_passes(self, tmp_path: Path) -> None:
        """The original diamond scenario is completely unaffected by this PR."""
        cfg = ScenarioConfig.from_yaml("scenarios/provenance_supply_chain.yaml")
        cfg.output.trace = str(tmp_path / "diamond.jsonl")
        asyncio.run(ScenarioRunner(cfg).run())
        results = validate_trace(tmp_path / "diamond.jsonl", "provenance_supply_chain")
        assert results, "expected diamond validators to run"
        assert all(r.passed for r in results), [r.detail for r in results if not r.passed]

    def test_diamond_chain_ok_depth_still_four(self, tmp_path: Path) -> None:
        """The diamond scenario still reports a 4-node lineage (unchanged)."""
        cfg = ScenarioConfig.from_yaml("scenarios/provenance_supply_chain.yaml")
        out = tmp_path / "diamond.jsonl"
        cfg.output.trace = str(out)
        asyncio.run(ScenarioRunner(cfg).run())
        depth = _chain_ok_depth(out)
        assert depth == 4, f"diamond depth changed: expected 4, got {depth}"
