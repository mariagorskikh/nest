# SPDX-License-Identifier: Apache-2.0
"""Tests for the comms replay-attack validator and scenario.

The core claim under test: ``validate_comms_replay_resistance`` FAILS against
comms layers with no replay memory (``authenticated``, ``versioned``,
``nest_native`` — a captured, byte-identical envelope re-verifies and is
accepted twice) and PASSES against ``replay_safe`` (which remembers accepted
ids per sender and refuses the second delivery) — driven both from synthetic
traces and from a real simulator run.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_core.types import AgentId, Message, MessageId
from nest_core.validators import (
    validate_comms_replay_honest_delivery,
    validate_comms_replay_resistance,
    validate_trace,
)
from nest_plugins_reference.comms.authenticated import AuthenticatedComms

type Event = dict[str, Any]


def _authentic_envelope(mid: str) -> dict[str, Any]:
    """Return a genuine, correctly-tagged envelope as a dict."""
    comms = AuthenticatedComms(AgentId("peer-1"))
    raw = comms.serialize(
        Message(
            id=MessageId(mid),
            sender=AgentId("peer-1"),
            receiver=AgentId("auditor-0"),
            payload=b"x",
            metadata={"schema_version": "1.1", "kind": "offer"},
        )
    )
    return json.loads(raw)


def _recv(env: dict[str, Any]) -> Event:
    return {
        "ts": 1.0,
        "agent": "auditor-0",
        "kind": "receive",
        "from": "peer-1",
        "msg": json.dumps(env, sort_keys=True),
    }


def _ack(mid: str, status: str) -> Event:
    return {
        "ts": 2.0,
        "agent": "auditor-0",
        "kind": "send",
        "to": "peer-1",
        "msg": f"ack:{mid}:{status}:",
    }


# ---------------------------------------------------------------------------
# Validator unit tests (synthetic traces)
# ---------------------------------------------------------------------------


class TestReplayValidator:
    def test_pass_when_replay_rejected_and_first_delivery_accepted(self) -> None:
        env = _authentic_envelope("m-replayed")
        events = [
            _recv(env),
            _ack("m-replayed", "accepted"),
            _recv(env),  # verbatim replay
            _ack("m-replayed", "rejected_replay"),
        ]
        results = validate_comms_replay_resistance(events)
        assert results[0].passed is True

    def test_fail_when_replay_accepted(self) -> None:
        """authenticated/versioned behaviour: the duplicate is silently accepted."""
        env = _authentic_envelope("m-replayed")
        events = [
            _recv(env),
            _ack("m-replayed", "accepted"),
            _recv(env),
            _ack("m-replayed", "accepted"),  # no replay memory: accepted again
        ]
        results = validate_comms_replay_resistance(events)
        assert results[0].passed is False

    def test_fail_when_third_delivery_also_accepted(self) -> None:
        env = _authentic_envelope("m-replayed")
        events = [
            _recv(env),
            _ack("m-replayed", "accepted"),
            _recv(env),
            _ack("m-replayed", "rejected_replay"),
            _recv(env),
            _ack("m-replayed", "accepted"),  # a plugin that only catches the 2nd delivery
        ]
        results = validate_comms_replay_resistance(events)
        assert results[0].passed is False

    def test_no_replays_in_trace_reports_nothing_to_judge(self) -> None:
        env = _authentic_envelope("m-solo")
        events = [_recv(env), _ack("m-solo", "accepted")]
        results = validate_comms_replay_resistance(events)
        assert results[0].passed is False
        assert "no replayed envelopes" in results[0].detail

    def test_fail_when_first_delivery_rejected(self) -> None:
        """A plugin cannot pass by rejecting everything: the first delivery must land."""
        env = _authentic_envelope("m-solo")
        events = [_recv(env), _ack("m-solo", "rejected_tampered")]
        results = validate_comms_replay_honest_delivery(events)
        assert results[0].passed is False

    def test_honest_delivery_passes_for_solo_and_first_of_replayed(self) -> None:
        solo = _authentic_envelope("m-solo")
        replayed = _authentic_envelope("m-replayed")
        events = [
            _recv(solo),
            _ack("m-solo", "accepted"),
            _recv(replayed),
            _ack("m-replayed", "accepted"),
            _recv(replayed),
            _ack("m-replayed", "rejected_replay"),
        ]
        results = validate_comms_replay_honest_delivery(events)
        assert results[0].passed is True

    def test_no_deliveries_reports_nothing_to_judge(self) -> None:
        results = validate_comms_replay_honest_delivery([])
        assert results[0].passed is False
        assert "no delivered envelopes" in results[0].detail


# ---------------------------------------------------------------------------
# End-to-end: real simulator run
# ---------------------------------------------------------------------------


def _run(comms: str, out: Path, seed: int = 42) -> None:
    cfg = ScenarioConfig.from_yaml("scenarios/comms_replay.yaml")
    cfg.layers.comms = comms
    cfg.seed = seed
    cfg.output.trace = str(out)
    asyncio.run(ScenarioRunner(cfg).run())


class TestScenarioEndToEnd:
    def test_replay_safe_passes(self, tmp_path: Path) -> None:
        out = tmp_path / "replay_safe.jsonl"
        _run("replay_safe", out)
        results = validate_trace(out, "comms_replay")
        assert results, "expected validator to run"
        assert all(r.passed for r in results), [r.detail for r in results if not r.passed]

    def test_authenticated_fails(self, tmp_path: Path) -> None:
        """AuthenticatedComms has no replay memory -> accepts the duplicate."""
        out = tmp_path / "authenticated.jsonl"
        _run("authenticated", out)
        results = validate_trace(out, "comms_replay")
        by_name = {r.name: r.passed for r in results}
        assert by_name["comms_replay_resistance"] is False
        assert by_name["comms_replay_honest_delivery"] is True

    def test_versioned_fails(self, tmp_path: Path) -> None:
        out = tmp_path / "versioned.jsonl"
        _run("versioned", out)
        results = validate_trace(out, "comms_replay")
        assert {r.name: r.passed for r in results}["comms_replay_resistance"] is False

    def test_nest_native_fails(self, tmp_path: Path) -> None:
        out = tmp_path / "native.jsonl"
        _run("nest_native", out)
        results = validate_trace(out, "comms_replay")
        assert {r.name: r.passed for r in results}["comms_replay_resistance"] is False

    def test_deterministic_across_required_seeds(self, tmp_path: Path) -> None:
        for seed in (42, 7, 1337):
            a, b = tmp_path / f"{seed}a.jsonl", tmp_path / f"{seed}b.jsonl"
            _run("replay_safe", a, seed=seed)
            _run("replay_safe", b, seed=seed)
            assert a.read_bytes() == b.read_bytes(), f"seed {seed} not deterministic"
            assert all(r.passed for r in validate_trace(a, "comms_replay"))
