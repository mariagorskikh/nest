# SPDX-License-Identifier: Apache-2.0
"""End-to-end tests for the sybil_bond scenario + adversarial validators.

The charter's adversarial proof: the ``sybil_bond`` validators **FAIL** under
``trust: score_average`` (the free-minted clique promotes itself to the top) and
**PASS** under ``trust: bonded_trust`` (unbonded identities stay pinned at the
untrusted floor), plus a byte-level determinism check.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_core.validators import validate_trace

_SCENARIO_YAML = Path(__file__).parent.parent.parent.parent / "scenarios" / "sybil_bond.yaml"


def _config(trust: str, trace: Path, seed: int | None = None) -> ScenarioConfig:
    """Load the scenario YAML, override the trust plugin, seed, and trace path."""
    config = ScenarioConfig.from_yaml(_SCENARIO_YAML)
    config.layers.trust = trust
    config.output.trace = str(trace)
    if seed is not None:
        config.seed = seed
    return config


def _results(trace: Path) -> dict[str, bool]:
    return {r.name: r.passed for r in validate_trace(trace, "sybil_bond")}


class TestAdversarialProof:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("seed", [1, 7, 42, 123, 9999])
    async def test_validators_pass_under_bonded_trust(self, tmp_path: Path, seed: int) -> None:
        trace = tmp_path / f"ours_{seed}.jsonl"
        await ScenarioRunner(_config("bonded_trust", trace, seed=seed)).run()
        results = _results(trace)
        assert results["sybil_bond_no_free_trust"] is True
        assert results["sybil_bond_honest_trusted"] is True
        assert results["sybil_bond_attempts_rejected"] is True

    @pytest.mark.asyncio
    async def test_validators_fail_under_score_average(self, tmp_path: Path) -> None:
        trace = tmp_path / "baseline.jsonl"
        await ScenarioRunner(_config("score_average", trace)).run()
        results = _results(trace)
        # The whole point: the naive baseline lets the free-minted clique win.
        assert results["sybil_bond_no_free_trust"] is False
        assert results["sybil_bond_honest_trusted"] is False
        assert results["sybil_bond_attempts_rejected"] is False


class TestDeterminism:
    @pytest.mark.asyncio
    async def test_same_seed_identical_trace(self, tmp_path: Path) -> None:
        t1 = tmp_path / "run1.jsonl"
        t2 = tmp_path / "run2.jsonl"
        await ScenarioRunner(_config("bonded_trust", t1)).run()
        await ScenarioRunner(_config("bonded_trust", t2)).run()
        assert (
            hashlib.sha256(t1.read_bytes()).hexdigest()
            == hashlib.sha256(t2.read_bytes()).hexdigest()
        )


class TestScenarioShape:
    @pytest.mark.asyncio
    async def test_every_population_scored(self, tmp_path: Path) -> None:
        trace = tmp_path / "shape.jsonl"
        await ScenarioRunner(_config("bonded_trust", trace)).run()
        text = trace.read_text()
        assert "trustscore:honest-0:" in text
        assert "trustscore:sybil-0:" in text

    @pytest.mark.asyncio
    async def test_unbonded_sybil_scores_zero(self, tmp_path: Path) -> None:
        """A free-minted Sybil that never bonds is pinned at the untrusted floor."""
        trace = tmp_path / "sybil.jsonl"
        await ScenarioRunner(_config("bonded_trust", trace)).run()
        line = next(ln for ln in trace.read_text().splitlines() if "trustscore:sybil-0:" in ln)
        score = float(line.split("trustscore:sybil-0:", 1)[1].split('"', 1)[0])
        assert score == 0.0
