# SPDX-License-Identifier: Apache-2.0
"""Tests for the provenance_supply_chain_linear scenario.

Same core claim as the diamond scenario, on a deep linear spine: the three
adversarial validators FAIL against the default ``datafacts_v1`` layer
(name-addressed, unauthenticated freshness, no provenance) and PASS against
``cid_facts``, driven by a real simulator run over a four-hop single-parent
chain. Also pins the lineage depth and byte-identical determinism.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_core.validators import validate_trace

_SCENARIO = "provenance_supply_chain_linear"
_YAML = "scenarios/provenance_supply_chain_linear.yaml"


def _run(datafacts: str, out: Path, seed: int = 42) -> None:
    cfg = ScenarioConfig.from_yaml(_YAML)
    cfg.layers.datafacts = datafacts
    cfg.seed = seed
    cfg.output.trace = str(out)
    asyncio.run(ScenarioRunner(cfg).run())


class TestScenarioEndToEnd:
    def test_cid_facts_passes_all(self, tmp_path: Path) -> None:
        out = tmp_path / "cid_facts.jsonl"
        _run("cid_facts", out)
        results = validate_trace(out, _SCENARIO)
        assert results, "expected validators to run"
        assert all(r.passed for r in results), [r.detail for r in results if not r.passed]

    def test_linear_walk_visits_all_four_hops(self, tmp_path: Path) -> None:
        """The defining property is depth, not node count.

        ``chain_ok`` reports the distinct-node count, which is 4 for *both* the
        diamond and this linear chain -- so on its own it cannot tell them apart
        (a diamond trace would satisfy it verbatim). What makes this scenario
        worth having is the lineage *depth*: ``chain_depth`` is the longest
        root-path length, 4 here (supplier -> manufacturer -> distributor ->
        retailer), whereas the diamond's longest path is only 3.
        """
        out = tmp_path / "cid_facts.jsonl"
        _run("cid_facts", out)
        msgs = [str(json.loads(line).get("msg", "")) for line in out.read_text().splitlines()]
        chain_ok = [m for m in msgs if m.startswith("chain_ok|")]
        chain_depth = [m for m in msgs if m.startswith("chain_depth|")]
        assert chain_ok, "no chain_ok recorded"
        assert chain_ok[0].rsplit("|", 1)[-1] == "4"  # 4 distinct datasets
        assert chain_depth, "no chain_depth recorded"
        assert chain_depth[0].rsplit("|", 1)[-1] == "4"  # longest path = 4 (diamond's is 3)

    def test_datafacts_v1_fails_all_adversarial_checks(self, tmp_path: Path) -> None:
        out = tmp_path / "v1.jsonl"
        _run("datafacts_v1", out)
        results = {r.name: r.passed for r in validate_trace(out, _SCENARIO)}
        # The happy-path lineage walk still works -- v1 stores parents in its
        # metadata dict even though it never validates them.
        assert results["provenance_chain_integrity"] is True
        assert results["provenance_substitution_resistant"] is False
        assert results["provenance_freshness_unforgeable"] is False
        assert results["provenance_chain_unforgeable"] is False

    def test_deterministic_across_required_seeds(self, tmp_path: Path) -> None:
        for seed in (42, 7, 1337):
            a, b = tmp_path / f"{seed}a.jsonl", tmp_path / f"{seed}b.jsonl"
            _run("cid_facts", a, seed=seed)
            _run("cid_facts", b, seed=seed)
            assert a.read_bytes() == b.read_bytes(), f"seed {seed} not deterministic"
            assert all(r.passed for r in validate_trace(a, _SCENARIO))
