# SPDX-License-Identifier: Apache-2.0
"""Tests for the intent_gated_datafacts discriminator scenario and validators.

The core claim under test: both adversarial validators PASS against the
``intent_facts`` layer (publish is gated on a pre-declared intent) and FAIL
against the default ``datafacts_v1`` layer (no intent concept) -- driven both
from synthetic traces and from a real simulator run.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_core.validators import (
    validate_intent_gate_blocks_attacker,
    validate_intent_no_surprise_publication,
    validate_trace,
)

type Event = dict[str, Any]


def _send(msg: str, agent: str = "supplier-0") -> Event:
    return {"ts": 0.0, "agent": agent, "kind": "send", "to": agent, "msg": msg}


# ---------------------------------------------------------------------------
# Validator unit tests (synthetic traces)
# ---------------------------------------------------------------------------


class TestNoSurprisePublication:
    def test_pass_when_publish_backed_by_intent(self) -> None:
        events = [
            _send("intent_registered|honest|prices|supplier-0"),
            _send("publish_ok|honest|prices|supplier-0|df://sha256-x"),
        ]
        results = validate_intent_no_surprise_publication(events)
        assert results[0].passed is True

    def test_fail_when_publish_has_no_intent(self) -> None:
        # datafacts_v1 behaviour: publish succeeds with no intent declared.
        events = [_send("publish_ok|honest|prices|supplier-0|df://prices")]
        results = validate_intent_no_surprise_publication(events)
        assert results[0].passed is False

    def test_fail_when_nothing_published(self) -> None:
        results = validate_intent_no_surprise_publication([])
        assert results[0].passed is False


class TestGateBlocksAttacker:
    def test_pass_when_attacker_blocked(self) -> None:
        events = [_send("publish_blocked|attacker|surprise_release|attacker-0|no intent")]
        results = validate_intent_gate_blocks_attacker(events)
        assert results[0].passed is True

    def test_fail_when_attacker_slips_through(self) -> None:
        # datafacts_v1 behaviour: surprise publication lands.
        events = [_send("publish_ok|attacker|surprise_release|attacker-0|df://surprise_release")]
        results = validate_intent_gate_blocks_attacker(events)
        assert results[0].passed is False

    def test_fail_when_no_attack_recorded(self) -> None:
        results = validate_intent_gate_blocks_attacker([])
        assert results[0].passed is False


# ---------------------------------------------------------------------------
# End-to-end: real simulator run (the discriminator)
# ---------------------------------------------------------------------------


def _run(datafacts: str, out: Path, seed: int = 42) -> None:
    cfg = ScenarioConfig.from_yaml("scenarios/intent_gated_datafacts.yaml")
    cfg.layers.datafacts = datafacts
    cfg.seed = seed
    cfg.output.trace = str(out)
    asyncio.run(ScenarioRunner(cfg).run())


class TestScenarioEndToEnd:
    def test_intent_facts_passes_all(self, tmp_path: Path) -> None:
        out = tmp_path / "intent_facts.jsonl"
        _run("intent_facts", out)
        results = validate_trace(out, "intent_gated_datafacts")
        assert results, "expected validators to run"
        assert all(r.passed for r in results), [r.detail for r in results if not r.passed]

    def test_datafacts_v1_fails_all(self, tmp_path: Path) -> None:
        out = tmp_path / "v1.jsonl"
        _run("datafacts_v1", out)
        results = {r.name: r.passed for r in validate_trace(out, "intent_gated_datafacts")}
        assert results["intent_no_surprise_publication"] is False
        assert results["intent_gate_blocks_attacker"] is False

    def test_deterministic_across_required_seeds(self, tmp_path: Path) -> None:
        for seed in (42, 7, 1337):
            a, b = tmp_path / f"{seed}a.jsonl", tmp_path / f"{seed}b.jsonl"
            _run("intent_facts", a, seed=seed)
            _run("intent_facts", b, seed=seed)
            assert a.read_bytes() == b.read_bytes(), f"seed {seed} not deterministic"
            assert all(r.passed for r in validate_trace(a, "intent_gated_datafacts"))
