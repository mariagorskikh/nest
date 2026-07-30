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
import json
import tempfile
from pathlib import Path
from typing import Any

import pytest
from nest_core.layers.failure_detector import FailureDetector
from nest_core.plugins import PluginRegistry
from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_core.scenarios_builtin.failure_detection import (
    IDENTITY_SEED,
    claimed_peer,
    heartbeat_payload,
    verify_heartbeat,
)
from nest_core.types import AgentId
from nest_core.validators import (
    ValidationResult,
    validate_failure_detection_accuracy,
    validate_trace,
)
from nest_plugins_reference.failure_detection.heartbeat import HeartbeatFailureDetector
from nest_plugins_reference.failure_detection.phi_accrual import PhiAccrualFailureDetector
from nest_plugins_reference.identity.did_key import DidKeyIdentity

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


# ---------------------------------------------------------------------------
# Signed-heartbeat unit tests
# ---------------------------------------------------------------------------

_VICTIM = AgentId("target-0")
_FORGER = AgentId("forger-0")
_OBSERVER = AgentId("observer-0")


def _fd_identities() -> dict[AgentId, Any]:
    """Build cross-registered identities for the observer, victim, and forger."""
    ids: dict[AgentId, Any] = {
        aid: DidKeyIdentity(aid, seed=IDENTITY_SEED) for aid in (_OBSERVER, _VICTIM, _FORGER)
    }
    for aid, ident in ids.items():
        for peer, peer_ident in ids.items():
            if peer != aid:
                ident.register_peer(peer, peer_ident.public_key)
    return ids


def test_signed_heartbeat_authentic_is_accepted() -> None:
    """A heartbeat signed by the claimed peer verifies and returns (peer, ts)."""
    ids = _fd_identities()
    payload = heartbeat_payload(ids[_VICTIM], _VICTIM, now=10.0)
    assert verify_heartbeat(ids[_OBSERVER], payload, last_ts={}, now=10.0) == (_VICTIM, 10.0)


def test_fabricated_heartbeat_signed_with_wrong_key_is_rejected() -> None:
    """A heartbeat that claims the victim but is signed by the forger fails verification."""
    ids = _fd_identities()
    forged = heartbeat_payload(ids[_FORGER], _VICTIM, now=10.0)  # claims victim, forger's key
    assert claimed_peer(forged) == _VICTIM  # the trusting parse is fooled...
    assert (
        verify_heartbeat(ids[_OBSERVER], forged, last_ts={}, now=10.0) is None
    )  # ...verify is not


def test_replayed_heartbeat_is_rejected_by_freshness() -> None:
    """A byte-exact replay of an accepted heartbeat is stale and rejected."""
    ids = _fd_identities()
    payload = heartbeat_payload(ids[_VICTIM], _VICTIM, now=10.0)
    last: dict[AgentId, float] = {}
    assert verify_heartbeat(ids[_OBSERVER], payload, last, now=10.0) == (_VICTIM, 10.0)
    last[_VICTIM] = 10.0
    assert verify_heartbeat(ids[_OBSERVER], payload, last, now=25.0) is None


def test_future_dated_heartbeat_is_rejected() -> None:
    """A heartbeat whose signed timestamp is ahead of now is rejected."""
    ids = _fd_identities()
    payload = heartbeat_payload(ids[_VICTIM], _VICTIM, now=50.0)
    assert verify_heartbeat(ids[_OBSERVER], payload, last_ts={}, now=10.0) is None


def test_malformed_or_unsigned_heartbeat_is_rejected() -> None:
    """Unsigned, truncated, and non-heartbeat payloads all fail verification."""
    ids = _fd_identities()
    assert verify_heartbeat(ids[_OBSERVER], b"FDHB|target-0|10.0", last_ts={}, now=10.0) is None
    assert verify_heartbeat(ids[_OBSERVER], b"FDHB|target-0|bad|zz", last_ts={}, now=10.0) is None
    assert verify_heartbeat(ids[_OBSERVER], b"not-a-heartbeat", last_ts={}, now=10.0) is None
    assert claimed_peer(b"FDHB|target-0|10.0|ab") == _VICTIM
    assert claimed_peer(b"nope") is None


def test_non_finite_timestamp_heartbeat_is_rejected() -> None:
    """A validly-signed but non-finite (nan/inf) timestamp is rejected.

    ``nan`` would otherwise slip both IEEE-754 freshness comparisons.  The
    signature here is genuine over the ``nan`` base, so only the explicit
    finiteness guard rejects it.
    """
    ids = _fd_identities()
    for ts_text in ("nan", "inf", "-inf"):
        base = f"FDHB|{_VICTIM}|{ts_text}".encode()
        sig = ids[_VICTIM].sign(base)
        payload = base + b"|" + sig.value.hex().encode()
        assert verify_heartbeat(ids[_OBSERVER], payload, last_ts={}, now=10_000.0) is None


def _accuracy_probe_events(hb_max: float, gap: float) -> list[dict[str, Any]]:
    """Trace where peer 'p' is reachable, beats at t=200, and is suspected `gap` later."""

    def bcast(agent: str, obj: dict[str, Any], ts: float) -> dict[str, Any]:
        return {
            "agent": agent,
            "kind": "broadcast",
            "ts": ts,
            "msg": json.dumps(obj, sort_keys=True, separators=(",", ":")),
        }

    return [
        bcast("observer-0", {"fd": "config", "hb_max": hb_max, "verify": True, "ts": 0.0}, 0.0),
        bcast("p", {"fd": "phase", "peer": "p", "reachable": True, "ts": 0.0}, 0.0),
        {
            "agent": "observer-0",
            "from": "p",
            "kind": "receive",
            "ts": 200.0,
            "msg": "FDHB|p|200.0|ab",
        },
        bcast(
            "observer-0",
            {
                "fd": "status",
                "peer": "p",
                "suspected": True,
                "phi": 9.0,
                "elapsed": gap,
                "ts": 200.0 + gap,
            },
            200.0 + gap,
        ),
    ]


def test_accuracy_bound_is_derived_from_config_marker() -> None:
    """A suspicion `gap` after a beat is a false positive only within the derived bound.

    With ``hb_max=40`` the derived plausible gap is 42, so a 30-unit gap is a
    false positive and accuracy fails.  The same trace with the pre-marker
    fallback (22) would have judged 30 as a real outage and passed, so the
    failure proves the bound is read from the ``fd:config`` marker, not
    hardcoded.
    """
    results = {
        r.name: r for r in validate_failure_detection_accuracy(_accuracy_probe_events(40.0, 30.0))
    }
    assert not results["failure_detection_accuracy"].passed, results[
        "failure_detection_accuracy"
    ].detail
    # A gap beyond the derived bound (45 > 42) is a real outage, not a false positive.
    ok = {
        r.name: r for r in validate_failure_detection_accuracy(_accuracy_probe_events(40.0, 45.0))
    }
    assert ok["failure_detection_accuracy"].passed, ok["failure_detection_accuracy"].detail


def test_accuracy_bound_ignores_spoofed_config_from_non_observer() -> None:
    """A forged fd:config from a non-observer cannot inflate the plausible gap.

    Only the observer (an agent that also emits fd:status) is trusted for the
    bound.  Here the honest observer marker says hb_max=20 (gap 22), so a
    60-unit suspicion is a genuine outage and accuracy passes.  A Byzantine
    ``forger-0`` also broadcasts fd:config with hb_max=1000; if that were
    trusted the bound would be 1002 and the 60-unit suspicion would be
    misjudged a false positive and accuracy would fail.
    """
    events = _accuracy_probe_events(20.0, 60.0)
    forged = {
        "agent": "forger-0",
        "kind": "broadcast",
        "ts": 0.0,
        "msg": json.dumps(
            {"fd": "config", "hb_max": 1000.0, "verify": True, "ts": 0.0},
            sort_keys=True,
            separators=(",", ":"),
        ),
    }
    results = {r.name: r for r in validate_failure_detection_accuracy([forged, *events])}
    assert results["failure_detection_accuracy"].passed, results[
        "failure_detection_accuracy"
    ].detail


# ---------------------------------------------------------------------------
# Forgery scenario: signed heartbeats defeat a keep-alive attack
# ---------------------------------------------------------------------------

FORGERY_PATH = Path(__file__).resolve().parents[3] / "scenarios" / "failure_detection_forgery.yaml"


def _forgery_config(seed: int, verify: bool | None) -> ScenarioConfig:
    config = ScenarioConfig.from_yaml(str(FORGERY_PATH))
    updates: dict[str, Any] = {"seed": seed}
    if verify is not None:
        task_cfg = dict(config.task.config)
        task_cfg["verify_heartbeats"] = verify
        updates["task"] = config.task.model_copy(update={"config": task_cfg})
    return config.model_copy(update=updates)


def _run_forgery(seed: int, verify: bool | None = None) -> dict[str, ValidationResult]:
    """Run the forgery scenario and return validator results by name."""
    config = _forgery_config(seed, verify)
    with tempfile.TemporaryDirectory() as tmp:
        trace_path = Path(tmp) / f"fdf_{seed}.jsonl"
        config = config.model_copy(
            update={"output": config.output.model_copy(update={"trace": str(trace_path)})}
        )
        runner = ScenarioRunner(config, registry=PluginRegistry())
        asyncio.run(runner.run())
        results = validate_trace(trace_path, "failure_detection_forgery")
    return {r.name: r for r in results}


def _run_forgery_bytes(seed: int) -> bytes:
    config = _forgery_config(seed, verify=None)
    with tempfile.TemporaryDirectory() as tmp:
        trace_path = Path(tmp) / "fdf_replay.jsonl"
        config = config.model_copy(
            update={"output": config.output.model_copy(update={"trace": str(trace_path)})}
        )
        runner = ScenarioRunner(config, registry=PluginRegistry())
        asyncio.run(runner.run())
        return trace_path.read_bytes()


@pytest.mark.parametrize("seed", _SEEDS)
def test_forgery_signed_heartbeats_defeat_the_attack(seed: int) -> None:
    """With verification on, every validator passes despite the forger."""
    if not FORGERY_PATH.exists():
        pytest.skip(f"scenario not found at {FORGERY_PATH}")

    results = _run_forgery(seed)
    expected = {
        "failure_detection_completeness",
        "failure_detection_accuracy",
        "failure_detection_recovery",
        "failure_detection_no_forged_liveness",
    }
    assert expected <= set(results), f"missing validators: {expected - set(results)}"
    for name, res in results.items():
        assert res.passed, f"seed={seed} {name} failed: {res.detail}"


@pytest.mark.parametrize("seed", _SEEDS)
def test_forgery_discriminator_trusting_observer_is_fooled(seed: int) -> None:
    """The discriminator: a payload-trusting observer is fooled; a verifying one is not.

    Verification is the property that separates them.  The trusting observer
    (verify_heartbeats=False) accepts the forged beats and never suspects the
    dead victim, so no_forged_liveness fails; the verifying observer rejects
    every forgery and passes it.
    """
    if not FORGERY_PATH.exists():
        pytest.skip(f"scenario not found at {FORGERY_PATH}")

    trusting = _run_forgery(seed, verify=False)
    assert not trusting["failure_detection_no_forged_liveness"].passed, (
        "a payload-trusting observer should be fooled by forged heartbeats, "
        f"but no_forged_liveness passed: {trusting['failure_detection_no_forged_liveness'].detail}"
    )

    verifying = _run_forgery(seed, verify=True)
    assert verifying["failure_detection_no_forged_liveness"].passed, verifying[
        "failure_detection_no_forged_liveness"
    ].detail


def test_forgery_scenario_is_byte_for_byte_deterministic() -> None:
    """Two runs of the signed forgery scenario at the same seed match byte for byte."""
    if not FORGERY_PATH.exists():
        pytest.skip(f"scenario not found at {FORGERY_PATH}")
    assert _run_forgery_bytes(42) == _run_forgery_bytes(42)
