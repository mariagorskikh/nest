# SPDX-License-Identifier: Apache-2.0
"""Unit + end-to-end tests for the failure-detector layer and its scenario.

Four layers of coverage:

1. **Detector unit tests** — drive the phi-accrual math and the fixed-timeout
   baseline directly at known logical times, asserting the cold/warm/silent
   regimes, the variance-awareness that distinguishes jitter from a crash, and
   the timeout boundary.
2. **Full simulator integration** — boot the ``failure_detection`` scenario via
   ``ScenarioRunner`` under seeds 42, 7, 1337 with the phi-accrual detector and
   assert every invariant validator (completeness, accuracy, recovery) passes.
3. **Adversarial discrimination** — the *same* scenario run with the naive
   fixed-timeout baseline (``timeout=16``, just above the mean heartbeat
   interval) MUST FAIL the accuracy validator on the upper tail of normal
   jitter, while the accrual detector MUST PASS it.  This is the bar for a
   validator that catches a class of mistakes the baseline plugin makes.
4. **Determinism** — two runs at the same seed produce byte-identical traces.

The integration tests exercise the real ``Simulator`` end to end; there is no
mocking past the plugin boundary.
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path
from typing import Any

import pytest
from nest_core.layers.failure_detector import FailureDetector
from nest_core.plugins import PluginRegistry
from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_core.types import AgentId
from nest_core.validators import ValidationResult, validate_trace
from nest_plugins_reference.failure_detection.heartbeat import HeartbeatFailureDetector
from nest_plugins_reference.failure_detection.phi_accrual import PhiAccrualFailureDetector

# ---------------------------------------------------------------------------
# Async helpers (sync tests, like the gossip suite, drive coroutines inline)
# ---------------------------------------------------------------------------


def _feed(fd: FailureDetector, peer: AgentId, times: list[float]) -> None:
    async def _go() -> None:
        for t in times:
            await fd.heartbeat(peer, now=t)

    asyncio.run(_go())


def _phi(fd: FailureDetector, peer: AgentId, now: float) -> float:
    return asyncio.run(fd.phi(peer, now=now))


def _suspect(fd: FailureDetector, peer: AgentId, now: float) -> bool:
    return asyncio.run(fd.suspect(peer, now=now))


# ---------------------------------------------------------------------------
# Phi-accrual detector unit tests
# ---------------------------------------------------------------------------

_PEER = AgentId("peer-1")


def test_phi_unknown_peer_is_not_suspected() -> None:
    """A peer with no observed heartbeat scores 0 and is never suspected."""
    fd = PhiAccrualFailureDetector()
    assert _phi(fd, _PEER, now=10_000.0) == 0.0
    assert _suspect(fd, _PEER, now=10_000.0) is False


def test_phi_cold_below_min_samples_stays_zero() -> None:
    """Below ``min_samples`` intervals the detector refuses to suspect."""
    fd = PhiAccrualFailureDetector(min_samples=5)
    _feed(fd, _PEER, [0.0, 10.0, 20.0])  # only 2 intervals < min_samples
    assert _phi(fd, _PEER, now=500.0) == 0.0
    assert _suspect(fd, _PEER, now=500.0) is False


def test_phi_low_right_after_heartbeat_high_after_long_silence() -> None:
    """Suspicion is ~0 right after a beat and climbs past threshold once silent."""
    fd = PhiAccrualFailureDetector(min_samples=5, threshold=8.0)
    _feed(fd, _PEER, [0.0, 10.0, 20.0, 30.0, 40.0, 50.0, 60.0])  # 6 intervals of 10
    # Right at the last heartbeat: delta 0, suspicion negligible.
    assert _phi(fd, _PEER, now=60.0) < 1.0
    assert _suspect(fd, _PEER, now=60.0) is False
    # Long after the expected next beat: clearly suspected.
    assert _suspect(fd, _PEER, now=200.0) is True
    assert _phi(fd, _PEER, now=200.0) >= 8.0


def test_phi_tolerates_jitter_but_catches_real_silence() -> None:
    """A gap inside the learned jitter range is tolerated; a long one is not.

    Intervals alternate 10/20 (mean 15, std 5).  A 20-unit gap is the upper
    edge of normal and must NOT be suspected -- this is exactly where a fixed
    timeout set near the mean would false-positive -- yet a 90-unit silence
    must be caught.
    """
    fd = PhiAccrualFailureDetector(min_samples=5, min_std=1.0, threshold=8.0)
    _feed(fd, _PEER, [0.0, 10.0, 30.0, 40.0, 60.0, 70.0, 90.0])
    assert _suspect(fd, _PEER, now=90.0) is False  # delta 0
    assert _suspect(fd, _PEER, now=110.0) is False  # delta 20 == jitter max
    assert _suspect(fd, _PEER, now=180.0) is True  # delta 90, genuine crash


def test_phi_report_snapshot_fields() -> None:
    """``report`` returns a coherent snapshot (suspected matches the verdict)."""
    fd = PhiAccrualFailureDetector(min_samples=5, threshold=8.0)
    _feed(fd, _PEER, [0.0, 10.0, 20.0, 30.0, 40.0, 50.0, 60.0])
    snap = asyncio.run(fd.report(_PEER, now=200.0))
    assert snap.peer == _PEER
    assert snap.suspected is True
    assert snap.last_heartbeat == 60.0
    assert snap.observed_at == 200.0
    assert _PEER in fd.known_peers()


# ---------------------------------------------------------------------------
# Fixed-timeout baseline unit tests
# ---------------------------------------------------------------------------


def test_heartbeat_unknown_peer_is_not_suspected() -> None:
    """The baseline cannot suspect a peer it has never seen alive."""
    fd = HeartbeatFailureDetector(timeout=10.0)
    assert _suspect(fd, _PEER, now=10_000.0) is False
    assert _phi(fd, _PEER, now=10_000.0) == 0.0


def test_heartbeat_timeout_boundary_is_strict() -> None:
    """Silence exactly equal to the timeout is tolerated; just beyond suspects."""
    fd = HeartbeatFailureDetector(timeout=10.0)
    _feed(fd, _PEER, [0.0])
    assert _suspect(fd, _PEER, now=10.0) is False  # elapsed == timeout, not >
    assert _suspect(fd, _PEER, now=10.5) is True


def test_heartbeat_phi_is_elapsed_over_timeout() -> None:
    """The baseline's phi is the elapsed/timeout ratio, rounded."""
    fd = HeartbeatFailureDetector(timeout=10.0)
    _feed(fd, _PEER, [0.0])
    assert _phi(fd, _PEER, now=5.0) == 0.5
    assert _phi(fd, _PEER, now=10.0) == 1.0


# ---------------------------------------------------------------------------
# End-to-end scenario integration
# ---------------------------------------------------------------------------

SCENARIO_PATH = Path(__file__).resolve().parents[3] / "scenarios" / "failure_detection.yaml"

_SEEDS = [42, 7, 1337]


def _run_scenario(
    seed: int,
    fd_plugin: str | None = None,
    fd_params: dict[str, Any] | None = None,
) -> dict[str, ValidationResult]:
    """Run the scenario (optionally overriding the detector) and return results."""
    config = ScenarioConfig.from_yaml(str(SCENARIO_PATH))
    updates: dict[str, Any] = {"seed": seed}
    if fd_plugin is not None or fd_params is not None:
        task_cfg = dict(config.task.config)
        if fd_plugin is not None:
            task_cfg["fd_plugin"] = fd_plugin
        if fd_params is not None:
            task_cfg["fd_params"] = fd_params
        updates["task"] = config.task.model_copy(update={"config": task_cfg})
    config = config.model_copy(update=updates)

    with tempfile.TemporaryDirectory() as tmp:
        trace_path = Path(tmp) / f"fd_{seed}.jsonl"
        config = config.model_copy(
            update={"output": config.output.model_copy(update={"trace": str(trace_path)})}
        )
        runner = ScenarioRunner(config, registry=PluginRegistry())
        asyncio.run(runner.run())
        results = validate_trace(trace_path, "failure_detection")
    return {r.name: r for r in results}


def _run_bytes(seed: int) -> bytes:
    """Run the scenario and return the raw trace bytes."""
    config = ScenarioConfig.from_yaml(str(SCENARIO_PATH)).model_copy(update={"seed": seed})
    with tempfile.TemporaryDirectory() as tmp:
        trace_path = Path(tmp) / "fd_replay.jsonl"
        config = config.model_copy(
            update={"output": config.output.model_copy(update={"trace": str(trace_path)})}
        )
        runner = ScenarioRunner(config, registry=PluginRegistry())
        asyncio.run(runner.run())
        return trace_path.read_bytes()


@pytest.mark.parametrize("seed", _SEEDS)
def test_scenario_phi_accrual_passes_every_validator(seed: int) -> None:
    """With phi-accrual, completeness, accuracy and recovery all hold."""
    if not SCENARIO_PATH.exists():
        pytest.skip(f"scenario not found at {SCENARIO_PATH}")

    results = _run_scenario(seed)
    expected = {
        "failure_detection_completeness",
        "failure_detection_accuracy",
        "failure_detection_recovery",
    }
    assert expected <= set(results), f"missing validators: {expected - set(results)}"
    for name, res in results.items():
        assert res.passed, f"seed={seed} {name} failed: {res.detail}"


@pytest.mark.parametrize("seed", _SEEDS)
def test_scenario_baseline_fails_accuracy_but_accrual_passes(seed: int) -> None:
    """The discriminator: the fixed timeout false-suspects live jitter; phi does not.

    Both detectors still satisfy completeness (the genuine outage is caught) --
    the accuracy validator is the property that separates them.
    """
    if not SCENARIO_PATH.exists():
        pytest.skip(f"scenario not found at {SCENARIO_PATH}")

    baseline = _run_scenario(seed, fd_plugin="heartbeat", fd_params={"timeout": 16.0})
    assert baseline["failure_detection_completeness"].passed, baseline[
        "failure_detection_completeness"
    ].detail
    assert not baseline["failure_detection_accuracy"].passed, (
        "fixed timeout should false-suspect a live peer on jitter tails, "
        f"but accuracy passed: {baseline['failure_detection_accuracy'].detail}"
    )

    accrual = _run_scenario(
        seed,
        fd_plugin="phi_accrual",
        fd_params={"window_size": 200, "min_samples": 5, "min_std": 1.0, "threshold": 8.0},
    )
    assert accrual["failure_detection_accuracy"].passed, accrual[
        "failure_detection_accuracy"
    ].detail


def test_scenario_is_byte_for_byte_deterministic() -> None:
    """Two runs at the same seed yield identical trace bytes."""
    if not SCENARIO_PATH.exists():
        pytest.skip(f"scenario not found at {SCENARIO_PATH}")
    assert _run_bytes(42) == _run_bytes(42)
