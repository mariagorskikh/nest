# SPDX-License-Identifier: Apache-2.0
"""End-to-end tests for the majority-ring red-team scenario (issue #97).

The wash-trading ring *outnumbers* the honest population (8 ring vs 5 honest),
so under the old severance rule the ring became the largest SCC — the exempt
"honest anchor" — and kept its manufactured reputation. The headline
assertions:

* all three ``receipt_reputation_majority`` validators **PASS** under
  ``trust: agent_receipts`` (the ring is severed even as the largest
  component; the sparse honest cycle is retained), and
* ``receipt_reputation_ring_severed`` **FAILS** under ``trust: score_average``
  (naive averaging rewards the majority ring) — the discriminator,

plus a byte-level determinism check (same seed -> identical trace sha256).
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_core.validators import validate_trace

_SCENARIO_YAML = (
    Path(__file__).parent.parent.parent.parent
    / "scenarios"
    / "receipt_reputation_majority_ring.yaml"
)


def _config(trust: str, trace: Path, seed: int | None = None) -> ScenarioConfig:
    """Load the majority-ring YAML, override the trust plugin, seed, and trace path."""
    config = ScenarioConfig.from_yaml(_SCENARIO_YAML)
    config.layers.trust = trust
    config.output.trace = str(trace)
    if seed is not None:
        config.seed = seed
    return config


class TestMajorityRingAdversarialProof:
    # Seed-bank robustness: the leaderboard re-runs under multiple seeds, so the
    # adversarial proof must hold across the bank, not just the default seed.
    @pytest.mark.asyncio
    @pytest.mark.parametrize("seed", [1, 7, 42, 123, 9999])
    async def test_all_validators_pass_under_agent_receipts(
        self, tmp_path: Path, seed: int
    ) -> None:
        trace = tmp_path / f"majority_{seed}.jsonl"
        await ScenarioRunner(_config("agent_receipts", trace, seed=seed)).run()
        results = {r.name: r for r in validate_trace(trace, "receipt_reputation_majority")}
        assert results["receipt_reputation_ring_severed"].passed, results[
            "receipt_reputation_ring_severed"
        ].detail
        assert results["receipt_reputation_honest_confidence"].passed, results[
            "receipt_reputation_honest_confidence"
        ].detail
        majority = results["receipt_reputation_ring_majority"]
        assert majority.passed, majority.detail
        # The liveness check must confirm the trace held the #97 precondition.
        assert "8 ring > 5 honest" in majority.detail

    @pytest.mark.asyncio
    async def test_score_average_fails_discriminator(self, tmp_path: Path) -> None:
        trace = tmp_path / "baseline.jsonl"
        await ScenarioRunner(_config("score_average", trace)).run()
        results = {r.name: r for r in validate_trace(trace, "receipt_reputation_majority")}
        # The whole point: the naive baseline rewards the majority wash ring.
        severed = results["receipt_reputation_ring_severed"]
        assert severed.passed is False
        assert "ring not severed" in severed.detail
        # The attack precondition itself held either way.
        assert results["receipt_reputation_ring_majority"].passed is True


class TestDeterminism:
    @pytest.mark.asyncio
    async def test_same_seed_identical_trace(self, tmp_path: Path) -> None:
        t1 = tmp_path / "run1.jsonl"
        t2 = tmp_path / "run2.jsonl"
        await ScenarioRunner(_config("agent_receipts", t1)).run()
        await ScenarioRunner(_config("agent_receipts", t2)).run()
        h1 = hashlib.sha256(t1.read_bytes()).hexdigest()
        h2 = hashlib.sha256(t2.read_bytes()).hexdigest()
        assert h1 == h2
