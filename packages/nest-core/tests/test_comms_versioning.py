# SPDX-License-Identifier: Apache-2.0
"""Tests for the comms_versioning adversarial validators and scenario.

The core claim under test: the validators FAIL against the default
``nest_native`` comms layer (which drops unknown fields and accepts breaking
majors) and PASS against ``versioned`` -- driven both from synthetic traces and
from a real simulator run.
"""

from __future__ import annotations

import asyncio
import base64
import json
from pathlib import Path
from typing import Any

from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_core.validators import (
    validate_comms_no_silent_drop,
    validate_comms_reject_unknown_major,
    validate_trace,
)

type Event = dict[str, Any]


def _envelope(mid: str, version: str, extra: dict[str, Any] | None = None) -> str:
    env: dict[str, Any] = {
        "schema_version": version,
        "kind": "offer",
        "id": mid,
        "sender": "peer-1",
        "receiver": "auditor-0",
        "payload": base64.b64encode(b"x").decode("ascii"),
        "correlation_id": None,
        "timestamp": None,
        "metadata": {},
    }
    if extra:
        env.update(extra)
    return json.dumps(env, sort_keys=True)


def _recv(mid: str, version: str, extra: dict[str, Any] | None = None) -> Event:
    return {
        "ts": 1.0,
        "agent": "auditor-0",
        "kind": "receive",
        "from": "peer-1",
        "msg": _envelope(mid, version, extra),
    }


def _ack(mid: str, status: str, preserved: str = "") -> Event:
    return {
        "ts": 2.0,
        "agent": "auditor-0",
        "kind": "send",
        "to": "peer-1",
        "msg": f"ack:{mid}:{status}:{preserved}",
    }


# ---------------------------------------------------------------------------
# Validator unit tests (synthetic traces)
# ---------------------------------------------------------------------------


class TestRejectUnknownMajor:
    def test_pass_when_future_major_rejected(self) -> None:
        events = [_recv("m1", "2.0"), _ack("m1", "rejected_major")]
        results = validate_comms_reject_unknown_major(events)
        assert results[0].passed is True

    def test_fail_when_future_major_accepted(self) -> None:
        # nest_native behaviour: no rejection, decoded as if valid.
        events = [_recv("m1", "2.0"), _ack("m1", "accepted")]
        results = validate_comms_reject_unknown_major(events)
        assert results[0].passed is False

    def test_fail_when_future_major_unacked(self) -> None:
        events = [_recv("m1", "2.0")]
        results = validate_comms_reject_unknown_major(events)
        assert results[0].passed is False

    def test_same_major_is_ignored(self) -> None:
        events = [_recv("m1", "1.5"), _ack("m1", "accepted")]
        results = validate_comms_reject_unknown_major(events)
        assert results[0].passed is True


class TestNoSilentDrop:
    def test_pass_when_unknown_preserved(self) -> None:
        events = [_recv("m1", "1.1", {"x-trace-id": "t"}), _ack("m1", "accepted", "x-trace-id")]
        results = validate_comms_no_silent_drop(events)
        assert results[0].passed is True

    def test_fail_when_unknown_dropped(self) -> None:
        # nest_native behaviour: accepted, but the unknown field vanished.
        events = [_recv("m1", "1.1", {"x-trace-id": "t"}), _ack("m1", "accepted")]
        results = validate_comms_no_silent_drop(events)
        assert results[0].passed is False

    def test_no_unknown_fields_is_trivially_ok(self) -> None:
        events = [_recv("m1", "1.0"), _ack("m1", "accepted")]
        results = validate_comms_no_silent_drop(events)
        assert results[0].passed is True

    def test_dropped_message_is_not_a_violation(self) -> None:
        """An envelope never delivered (no receive event) is not judged."""
        events = [_ack("m1", "accepted")]
        results = validate_comms_no_silent_drop(events)
        assert results[0].passed is True


# ---------------------------------------------------------------------------
# End-to-end: real simulator run
# ---------------------------------------------------------------------------


def _run(comms: str, out: Path, seed: int = 42) -> None:
    cfg = ScenarioConfig.from_yaml("scenarios/comms_versioning.yaml")
    cfg.layers.comms = comms
    cfg.seed = seed
    cfg.output.trace = str(out)
    asyncio.run(ScenarioRunner(cfg).run())


class TestScenarioEndToEnd:
    def test_versioned_passes(self, tmp_path: Path) -> None:
        out = tmp_path / "versioned.jsonl"
        _run("versioned", out)
        results = validate_trace(out, "comms_versioning")
        assert results, "expected validators to run"
        assert all(r.passed for r in results), [r.detail for r in results if not r.passed]

    def test_nest_native_fails_both_checks(self, tmp_path: Path) -> None:
        out = tmp_path / "native.jsonl"
        _run("nest_native", out)
        results = {r.name: r.passed for r in validate_trace(out, "comms_versioning")}
        assert results["comms_reject_unknown_major"] is False
        assert results["comms_no_silent_drop"] is False

    def test_deterministic_across_required_seeds(self, tmp_path: Path) -> None:
        for seed in (42, 7, 1337):
            a, b = tmp_path / f"{seed}a.jsonl", tmp_path / f"{seed}b.jsonl"
            _run("versioned", a, seed=seed)
            _run("versioned", b, seed=seed)
            assert a.read_bytes() == b.read_bytes(), f"seed {seed} not deterministic"
            assert all(r.passed for r in validate_trace(a, "comms_versioning"))
