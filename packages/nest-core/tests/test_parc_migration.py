# SPDX-License-Identifier: Apache-2.0
"""End-to-end tests for the parc_migration scenario + adversarial validators.

The headline assertions are the differential proof the charter requires:

* all six ``parc_migration`` validators **PASS** under ``trust: parc`` with
  the recomputing gate (default config),
* the inflation and ring validators **FAIL** under the *naive gate*
  (``task.config.naive_gate: true`` — proof still checked, signed claims
  trusted), while the proof/replay/stale-key defenses keep passing, and
* **every** validator FAILS under ``trust: score_average`` (no credentials
  can even be built),

plus a byte-level determinism check (same seed -> identical trace sha256).
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_core.validators import validate_trace

_SCENARIO_YAML = Path(__file__).parent.parent.parent.parent / "scenarios" / "parc_migration.yaml"

_ALL_VALIDATORS = (
    "parc_honest_admitted",
    "parc_forgery_rejected",
    "parc_inflation_rejected",
    "parc_ring_severed",
    "parc_replay_rejected",
    "parc_stale_key_rejected",
)


def _config(
    trace: Path,
    *,
    trust: str = "parc",
    naive_gate: bool = False,
    seed: int | None = None,
) -> ScenarioConfig:
    """Load the scenario YAML with trust/naive-gate/seed/trace overrides."""
    config = ScenarioConfig.from_yaml(_SCENARIO_YAML)
    config.layers.trust = trust
    config.task.config["naive_gate"] = naive_gate
    config.output.trace = str(trace)
    if seed is not None:
        config.seed = seed
    return config


def _results(trace: Path) -> dict[str, bool]:
    return {r.name: r.passed for r in validate_trace(trace, "parc_migration")}


class TestAdversarialProof:
    # Seed-bank robustness: the leaderboard re-runs under multiple seeds, so
    # the adversarial proof must hold across the bank, not just the default.
    @pytest.mark.asyncio
    @pytest.mark.parametrize("seed", [1, 7, 42, 123, 9999])
    async def test_all_validators_pass_under_parc(self, tmp_path: Path, seed: int) -> None:
        trace = tmp_path / f"parc_{seed}.jsonl"
        await ScenarioRunner(_config(trace, seed=seed)).run()
        results = _results(trace)
        for name in _ALL_VALIDATORS:
            assert results[name] is True, name

    @pytest.mark.asyncio
    async def test_naive_gate_fails_exactly_the_recomputation_defenses(
        self, tmp_path: Path
    ) -> None:
        trace = tmp_path / "naive.jsonl"
        await ScenarioRunner(_config(trace, naive_gate=True)).run()
        results = _results(trace)
        # The whole point: signature-checking alone admits the inflated
        # credential and the wash ring...
        assert results["parc_inflation_rejected"] is False
        assert results["parc_ring_severed"] is False
        # ...while the non-recomputation defenses (and honest retention) hold.
        assert results["parc_honest_admitted"] is True
        assert results["parc_forgery_rejected"] is True
        assert results["parc_replay_rejected"] is True
        assert results["parc_stale_key_rejected"] is True

    @pytest.mark.asyncio
    async def test_score_average_fails_everything(self, tmp_path: Path) -> None:
        trace = tmp_path / "baseline.jsonl"
        await ScenarioRunner(_config(trace, trust="score_average")).run()
        results = _results(trace)
        # A trust plugin with no export surface cannot even produce
        # credentials, let alone gate them.
        for name in _ALL_VALIDATORS:
            assert results[name] is False, name


class TestDeterminism:
    @pytest.mark.asyncio
    async def test_same_seed_identical_trace(self, tmp_path: Path) -> None:
        t1 = tmp_path / "run1.jsonl"
        t2 = tmp_path / "run2.jsonl"
        await ScenarioRunner(_config(t1)).run()
        await ScenarioRunner(_config(t2)).run()
        h1 = hashlib.sha256(t1.read_bytes()).hexdigest()
        h2 = hashlib.sha256(t2.read_bytes()).hexdigest()
        assert h1 == h2


class TestScenarioShape:
    @pytest.mark.asyncio
    async def test_every_role_gets_exactly_one_decision(self, tmp_path: Path) -> None:
        trace = tmp_path / "shape.jsonl"
        await ScenarioRunner(_config(trace)).run()
        import json

        decided: dict[str, str] = {}
        exports = 0
        for line in trace.read_text().splitlines():
            event = json.loads(line)
            if event.get("kind") != "broadcast":
                continue
            msg = str(event.get("msg", ""))
            if msg.startswith("export:"):
                exports += 1
            if msg.startswith("admit:"):
                agent, _decision, _reason, role = msg.split(":")[1:5]
                decided[agent] = role
        # 9 exports from auditor A + 1 from the corrupt auditor. The replayer
        # never earns an export — it presents a stolen credential.
        assert exports == 10
        # 11 migrants decided: 4 honest, 3 ring, forger, replayer, stale,
        # inflated.
        assert len(decided) == 11
        assert sorted(decided.values()).count("honest") == 4
        assert sorted(decided.values()).count("ring") == 3
        for role in ("forged", "replay", "stale", "inflated"):
            assert role in decided.values()
