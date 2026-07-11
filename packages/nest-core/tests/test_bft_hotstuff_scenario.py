# SPDX-License-Identifier: Apache-2.0
"""End-to-end tests for the bft_hotstuff scenario and its validators.

The core claims under test: the partition scenario heals and resumes commit
progress deterministically across the required seeds; the byzantine
scenario's safety/forged-quorum/stuck-view/locked-QC validators pass while
the equivocation validator correctly catches the configured malicious
leaders (proving the malicious logic actually ran, not silently no-op'd);
the locked-qc-bypass scenario's safety/forged-quorum/stuck-view validators
still pass -- proving the fixed locked-QC rule stops the attack from
actually forking anything -- while the new ``bft_locked_qc_respected``
validator correctly catches the repeated bypass attempts, mirroring how
``bft_no_equivocation`` behaves in the byzantine scenario; the
``validate_bft_locked_qc_respected`` validator is exercised directly against
hand-built traces to prove its detection logic in isolation; and the
bft_hotstuff validator suite FAILS against a contract_net-coordinated trace
that has no prepare:/qc:/result:committed lines at all.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_core.validators import validate_bft_locked_qc_respected, validate_events, validate_trace


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
        assert results["bft_locked_qc_respected"].passed is True, results[
            "bft_locked_qc_respected"
        ].detail
        # Sanity check: if this ever passes, the configured malicious_agents
        # silently no-op'd instead of actually equivocating.
        assert results["bft_no_equivocation"].passed is False


class TestBftLockedQcBypassScenario:
    """The locked-QC rule must reject a leader that omits justify_qc entirely.

    Regression coverage for the bug where ``ReplicaAgent._handle_prepare``
    only compared ``justify_qc.view`` against the replica's lock when a
    ``justify_qc`` was present at all -- a leader could dodge the whole
    check by sending ``justify_qc=None``. ``NoJustifyLeaderAgent`` (see
    ``nest_core.scenarios_builtin.bft_hotstuff``) does exactly that on
    *every* one of its leader turns, so ``bft_locked_qc_respected`` is
    expected to keep firing for the lifetime of the run -- same shape as
    ``bft_no_equivocation`` in the byzantine scenario above, it is a
    "did the attack happen" detector, not a safety-outcome check. What the
    fix actually guarantees is that despite the repeated attempts, no
    honest replica is fooled: the safety and liveness validators
    (conflicting-commits, forged-quorum, stuck-view) must all still pass.
    """

    def test_bypass_attempts_detected_but_safety_and_liveness_hold(self, tmp_path: Path) -> None:
        out = tmp_path / "locked_qc_bypass.jsonl"
        _run("scenarios/bft_consensus_locked_qc_bypass.yaml", out)
        results = {r.name: r for r in validate_trace(out, "bft_hotstuff")}

        assert results["bft_no_conflicting_commits"].passed is True, results[
            "bft_no_conflicting_commits"
        ].detail
        assert results["bft_forged_quorum"].passed is True, results["bft_forged_quorum"].detail
        assert results["bft_no_stuck_view"].passed is True, results["bft_no_stuck_view"].detail
        # Sanity check: if this ever passes, NoJustifyLeaderAgent silently
        # no-op'd instead of actually attempting the bypass.
        assert results["bft_locked_qc_respected"].passed is False

    def test_deterministic_across_required_seeds(self, tmp_path: Path) -> None:
        for seed in (42, 7, 1337, 0xDEADBEEF):
            a, b = tmp_path / f"{seed}a.jsonl", tmp_path / f"{seed}b.jsonl"
            _run("scenarios/bft_consensus_locked_qc_bypass.yaml", a, seed=seed)
            _run("scenarios/bft_consensus_locked_qc_bypass.yaml", b, seed=seed)
            assert a.read_bytes() == b.read_bytes(), f"seed {seed} not deterministic"
            safety = {r.name: r for r in validate_trace(a, "bft_hotstuff")}
            assert safety["bft_no_conflicting_commits"].passed is True, seed
            assert safety["bft_forged_quorum"].passed is True, seed
            assert safety["bft_no_stuck_view"].passed is True, seed


class TestLockedQcRespectedValidatorUnit:
    """Exercise ``validate_bft_locked_qc_respected`` directly against hand-built traces.

    Isolates the detection logic from the simulator so the validator's
    behavior at the exact attack boundary is pinned down independently of
    whether any given scenario run happens to trigger it.
    """

    _LOCK_QC = "qc:prepare:3:aaaa:2:replica-0=00,replica-2=00,replica-3=00"

    def test_flags_proposal_with_no_justify_qc_after_a_prior_lock(self) -> None:
        events = [
            {"kind": "send", "agent": "replica-0", "ts": 0.0, "msg": self._LOCK_QC},
            {"kind": "send", "agent": "replica-1", "ts": 50.0, "msg": "prepare:5:bbbb:99:none"},
        ]
        results = validate_bft_locked_qc_respected(events)
        assert len(results) == 1
        assert results[0].passed is False
        assert "view 5" in results[0].detail

    def test_flags_proposal_with_justify_qc_below_the_prior_lock(self) -> None:
        events = [
            {"kind": "send", "agent": "replica-0", "ts": 0.0, "msg": self._LOCK_QC},
            {
                "kind": "send",
                "agent": "replica-1",
                "ts": 50.0,
                "msg": "prepare:5:bbbb:99:prepare;1;cccc;replica-0=00,replica-2=00,replica-3=00",
            },
        ]
        results = validate_bft_locked_qc_respected(events)
        assert results[0].passed is False

    def test_passes_when_justify_qc_covers_the_prior_lock(self) -> None:
        events = [
            {"kind": "send", "agent": "replica-0", "ts": 0.0, "msg": self._LOCK_QC},
            {
                "kind": "send",
                "agent": "replica-1",
                "ts": 50.0,
                "msg": "prepare:5:bbbb:99:prepare;3;aaaa;replica-0=00,replica-2=00,replica-3=00",
            },
        ]
        results = validate_bft_locked_qc_respected(events)
        assert results[0].passed is True

    def test_passes_when_no_prior_lock_exists_yet(self) -> None:
        events = [
            {"kind": "send", "agent": "replica-0", "ts": 0.0, "msg": "prepare:0:aaaa:42:none"},
        ]
        results = validate_bft_locked_qc_respected(events)
        assert results[0].passed is True


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
