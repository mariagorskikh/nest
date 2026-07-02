# SPDX-License-Identifier: Apache-2.0
"""End-to-end tests for the bft_hotstuff scenario and its validators.

The core claims under test: the partition scenario heals and resumes commit
progress deterministically across the required seeds; the byzantine
scenario's safety/forged-quorum/stuck-view validators pass while the
equivocation validator correctly catches the configured malicious leaders
(proving the malicious logic actually ran, not silently no-op'd); and the
bft_hotstuff validator suite FAILS against a contract_net-coordinated trace
that has no prepare:/qc:/result:committed lines at all.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_core.validators import validate_events, validate_trace


def _run(yaml_path: str, out: Path, seed: int = 42) -> None:
    cfg = ScenarioConfig.from_yaml(yaml_path)
    cfg.seed = seed
    cfg.output.trace = str(out)
    asyncio.run(ScenarioRunner(cfg).run())


class TestBftPartitionScenario:
    def test_runs_and_passes_all_validators(self, tmp_path: Path) -> None:
        out = tmp_path / "partition.jsonl"
        _run("scenarios/bft_consensus_partition.yaml", out)
        results = validate_trace(out, "bft_hotstuff")
        assert results, "expected validators to run"
        assert all(r.passed for r in results), [r.detail for r in results if not r.passed]

    def test_deterministic_across_required_seeds(self, tmp_path: Path) -> None:
        for seed in (42, 7, 1337, 0xDEADBEEF):
            a, b = tmp_path / f"{seed}a.jsonl", tmp_path / f"{seed}b.jsonl"
            _run("scenarios/bft_consensus_partition.yaml", a, seed=seed)
            _run("scenarios/bft_consensus_partition.yaml", b, seed=seed)
            assert a.read_bytes() == b.read_bytes(), f"seed {seed} not deterministic"
            assert all(r.passed for r in validate_trace(a, "bft_hotstuff")), seed


class TestBftByzantineScenario:
    def test_safety_and_recovery_pass_but_equivocation_is_detected(self, tmp_path: Path) -> None:
        out = tmp_path / "byzantine.jsonl"
        _run("scenarios/bft_consensus_byzantine.yaml", out)
        results = {r.name: r for r in validate_trace(out, "bft_hotstuff")}

        assert results["bft_no_conflicting_commits"].passed is True, results[
            "bft_no_conflicting_commits"
        ].detail
        assert results["bft_forged_quorum"].passed is True, results["bft_forged_quorum"].detail
        assert results["bft_no_stuck_view"].passed is True, results["bft_no_stuck_view"].detail
        # Sanity check: if this ever passes, the configured malicious_agents
        # silently no-op'd instead of actually equivocating.
        assert results["bft_no_equivocation"].passed is False


class TestValidatorsFailAgainstNonBftTrace:
    def test_fails_against_synthetic_contract_net_style_trace(self) -> None:
        events = [
            {"kind": "start", "agent": "r0"},
            {"kind": "send", "agent": "r0", "msg": "bids:[]"},
            {"kind": "stop", "agent": "r0"},
        ]
        results = validate_events(events, "bft_hotstuff")
        assert any(not r.passed for r in results), "expected at least one validator to fail"

    def test_fails_against_real_consensus_trace(self, tmp_path: Path) -> None:
        out = tmp_path / "consensus.jsonl"
        _run("scenarios/consensus.yaml", out)
        results = validate_trace(out, "bft_hotstuff")
        assert any(not r.passed for r in results), "expected at least one validator to fail"
