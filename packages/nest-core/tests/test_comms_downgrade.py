# SPDX-License-Identifier: Apache-2.0
"""Tests for the comms downgrade-attack validator and scenario.

The core claim under test: ``validate_comms_downgrade_resistance`` FAILS against
comms layers with no integrity (``versioned``, ``nest_native`` — they accept an
on-path attacker's rolled-back / stripped copies) and PASSES against
``authenticated`` (which recomputes the tag and refuses the forgeries) — driven
both from synthetic traces and from a real simulator run.
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
    validate_comms_authentic_delivery,
    validate_comms_downgrade_resistance,
    validate_trace,
)
from nest_plugins_reference.comms.authenticated import (
    AUTH_TAG_FIELD,
    AuthenticatedComms,
    expected_auth_tag,
)

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
            metadata={"schema_version": "1.1", "kind": "offer", "_unknown": {"x-trace-id": mid}},
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


class TestDowngradeValidator:
    def test_pass_when_tampered_rejected_and_honest_accepted(self) -> None:
        honest = _authentic_envelope("m-honest")
        rolled = _authentic_envelope("m-rollback")
        rolled["schema_version"] = "1.0"  # stale tag no longer covers this
        events = [
            _recv(honest),
            _ack("m-honest", "accepted"),
            _recv(rolled),
            _ack("m-rollback", "rejected_tampered"),
        ]
        results = validate_comms_downgrade_resistance(events)
        assert results[0].passed is True

    def test_fail_when_tampered_accepted(self) -> None:
        """versioned/nest_native behaviour: the forgery is silently accepted."""
        rolled = _authentic_envelope("m-rollback")
        rolled["schema_version"] = "1.0"
        events = [_recv(rolled), _ack("m-rollback", "accepted")]
        results = validate_comms_downgrade_resistance(events)
        assert results[0].passed is False

    def test_fail_when_field_stripped_and_accepted(self) -> None:
        stripped = _authentic_envelope("m-strip")
        del stripped["x-trace-id"]
        events = [_recv(stripped), _ack("m-strip", "accepted")]
        results = validate_comms_downgrade_resistance(events)
        assert results[0].passed is False

    def test_fail_when_honest_rejected(self) -> None:
        """A plugin cannot pass by rejecting everything: honest must be accepted."""
        honest = _authentic_envelope("m-honest")
        events = [_recv(honest), _ack("m-honest", "rejected_tampered")]
        results = validate_comms_authentic_delivery(events)
        assert results[0].passed is False

    def test_authentic_delivery_passes_when_honest_accepted(self) -> None:
        """The liveness check passes when authentic envelopes are accepted."""
        honest = _authentic_envelope("m-honest")
        events = [_recv(honest), _ack("m-honest", "accepted")]
        results = validate_comms_authentic_delivery(events)
        assert results[0].passed is True

    def test_untagged_traffic_is_out_of_scope(self) -> None:
        """Envelopes with no auth_tag are not judged by this validator."""
        env = _authentic_envelope("m-legacy")
        del env[AUTH_TAG_FIELD]
        events = [_recv(env), _ack("m-legacy", "accepted")]
        results = validate_comms_downgrade_resistance(events)
        # No tagged envelopes -> the validator reports it found nothing to judge.
        assert results[0].passed is False
        assert "no tagged envelopes" in results[0].detail

    def test_tamper_detection_matches_recompute(self) -> None:
        """Sanity: an authentic envelope's tag verifies; a mutated one does not."""
        env = _authentic_envelope("m1")
        assert env[AUTH_TAG_FIELD] == expected_auth_tag(env)
        env["kind"] = "evil"
        assert env[AUTH_TAG_FIELD] != expected_auth_tag(env)


# ---------------------------------------------------------------------------
# End-to-end: real simulator run
# ---------------------------------------------------------------------------


def _run(comms: str, out: Path, seed: int = 42) -> None:
    cfg = ScenarioConfig.from_yaml("scenarios/comms_downgrade_attack.yaml")
    cfg.layers.comms = comms
    cfg.seed = seed
    cfg.output.trace = str(out)
    asyncio.run(ScenarioRunner(cfg).run())


class TestScenarioEndToEnd:
    def test_authenticated_passes(self, tmp_path: Path) -> None:
        out = tmp_path / "authenticated.jsonl"
        _run("authenticated", out)
        results = validate_trace(out, "comms_downgrade")
        assert results, "expected validator to run"
        assert all(r.passed for r in results), [r.detail for r in results if not r.passed]

    def test_versioned_fails(self, tmp_path: Path) -> None:
        """The merged versioned plugin has no tag concept -> accepts forgeries."""
        out = tmp_path / "versioned.jsonl"
        _run("versioned", out)
        results = validate_trace(out, "comms_downgrade")
        assert results[0].passed is False

    def test_nest_native_fails(self, tmp_path: Path) -> None:
        out = tmp_path / "native.jsonl"
        _run("nest_native", out)
        results = validate_trace(out, "comms_downgrade")
        assert results[0].passed is False

    def test_deterministic_across_required_seeds(self, tmp_path: Path) -> None:
        for seed in (42, 7, 1337):
            a, b = tmp_path / f"{seed}a.jsonl", tmp_path / f"{seed}b.jsonl"
            _run("authenticated", a, seed=seed)
            _run("authenticated", b, seed=seed)
            assert a.read_bytes() == b.read_bytes(), f"seed {seed} not deterministic"
            assert all(r.passed for r in validate_trace(a, "comms_downgrade"))
