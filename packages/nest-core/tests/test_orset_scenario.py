# SPDX-License-Identifier: Apache-2.0
"""End-to-end tests for the memory_orset_claims scenario and its validators.

The core claims under test: the claim/release marketplace replays byte-identically
across the required seeds; under 10% message loss and one Byzantine forger every
replica converges, every honest claim survives, and the attacker provably ran;
and the memory_orset_claims validators FAIL against a trace with no OR-Set final
records at all.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_core.validators import validate_events, validate_trace

_SCENARIO = "scenarios/memory_orset_claims.yaml"
_SEEDS = (42, 7, 1337)


def _run(out: Path, seed: int) -> None:
    cfg = ScenarioConfig.from_yaml(_SCENARIO)
    cfg.seed = seed
    cfg.output.trace = str(out)
    asyncio.run(ScenarioRunner(cfg).run())


class TestOrSetClaimsScenario:
    def test_runs_and_passes_all_validators(self, tmp_path: Path) -> None:
        out = tmp_path / "orset.jsonl"
        _run(out, seed=42)
        results = validate_trace(out, "memory_orset_claims")
        assert results, "expected validators to run"
        assert all(r.passed for r in results), [r.detail for r in results if not r.passed]

    def test_deterministic_across_required_seeds(self, tmp_path: Path) -> None:
        for seed in _SEEDS:
            a, b = tmp_path / f"{seed}a.jsonl", tmp_path / f"{seed}b.jsonl"
            _run(a, seed=seed)
            _run(b, seed=seed)
            assert a.read_bytes() == b.read_bytes(), f"seed {seed} not byte-deterministic"
            assert all(r.passed for r in validate_trace(a, "memory_orset_claims")), seed

    def test_all_ten_honest_claims_survive(self, tmp_path: Path) -> None:
        out = tmp_path / "orset.jsonl"
        _run(out, seed=1337)
        results = {r.name: r for r in validate_trace(out, "memory_orset_claims")}
        liveness = results["orset_claims_honest_liveness"]
        assert liveness.passed
        # All ten permanent self-claims must be present at convergence.
        for i in range(10):
            assert f"slot-{i}" in liveness.detail, liveness.detail

    def test_attacker_actually_ran(self, tmp_path: Path) -> None:
        out = tmp_path / "orset.jsonl"
        _run(out, seed=7)
        results = {r.name: r for r in validate_trace(out, "memory_orset_claims")}
        # Sanity: if this ever fails, the Byzantine forger silently no-op'd and
        # liveness was never actually tested.
        assert results["orset_claims_attacker_ran"].passed


class TestValidatorsFailAgainstNonOrSetTrace:
    def test_fails_against_empty_style_trace(self) -> None:
        events = [
            {"kind": "start", "agent": "claimant-0"},
            {"kind": "send", "agent": "claimant-0", "msg": "bids:[]"},
            {"kind": "stop", "agent": "claimant-0"},
        ]
        results = validate_events(events, "memory_orset_claims")
        assert any(not r.passed for r in results), "expected at least one validator to fail"

    def test_fails_when_a_replica_never_reports(self) -> None:
        # A started replica that emits no final: record is a liveness failure.
        events = [
            {"kind": "start", "agent": "claimant-0"},
            {"kind": "start", "agent": "claimant-1"},
            {
                "kind": "broadcast",
                "agent": "claimant-0",
                "msg": 'final:{"crdt": "or_set", "adds": {"\\"slot-0\\"": [["claimant-0", 1]]}, '
                '"removed": []}',
            },
        ]
        results = {r.name: r for r in validate_events(events, "memory_orset_claims")}
        assert results["memory_liveness"].passed is False
