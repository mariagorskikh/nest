# SPDX-License-Identifier: Apache-2.0
"""Tests for the interview-evaluation delivery scenario and its two new validators.

The core claim: pointing ``layers.datafacts`` at ``ogha_facts`` makes every
validator pass, while the reference ``datafacts_v1`` fails all four adversarial
checks plus the two OGHA-specific ones (PII redaction, ACL enforcement). Both
directions are driven from synthetic traces and a real simulator run, and the
run is asserted byte-deterministic across the required seed bank.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_core.validators import (
    validate_evaluation_acl_enforced,
    validate_evaluation_pii_redacted,
    validate_trace,
)

type Event = dict[str, Any]


def _send(msg: str) -> Event:
    return {"ts": 0.0, "agent": "company-acme", "kind": "send", "to": "company-acme", "msg": msg}


# ---------------------------------------------------------------------------
# Validator unit tests (synthetic traces)
# ---------------------------------------------------------------------------


class TestPiiValidator:
    def test_pass_when_no_pii(self) -> None:
        events = [_send("pii_scan|df://sha256-eval|0")]
        assert validate_evaluation_pii_redacted(events)[0].passed is True

    def test_fail_when_pii_survives(self) -> None:
        events = [_send("pii_scan|df://sha256-eval|4")]
        assert validate_evaluation_pii_redacted(events)[0].passed is False

    def test_fail_when_nothing_recorded(self) -> None:
        assert validate_evaluation_pii_redacted([])[0].passed is False


class TestAclValidator:
    def test_pass_when_tiers_match_expected(self) -> None:
        events = [
            _send("acl_result|df://sha256-eval|company-acme|read|read"),
            _send("acl_result|df://sha256-eval|rival-corp|metadata|metadata"),
        ]
        assert validate_evaluation_acl_enforced(events)[0].passed is True

    def test_fail_when_rival_gets_read(self) -> None:
        events = [_send("acl_result|df://sha256-eval|rival-corp|read|metadata")]
        result = validate_evaluation_acl_enforced(events)[0]
        assert result.passed is False
        assert "rival-corp" in result.detail

    def test_fail_when_nothing_recorded(self) -> None:
        assert validate_evaluation_acl_enforced([])[0].passed is False


# ---------------------------------------------------------------------------
# End-to-end: real simulator run
# ---------------------------------------------------------------------------

_SCENARIO = "interview_evaluation_delivery"


def _run(datafacts: str, out: Path, seed: int = 42) -> None:
    cfg = ScenarioConfig.from_yaml("scenarios/interview_evaluation_delivery.yaml")
    cfg.layers.datafacts = datafacts
    cfg.seed = seed
    cfg.output.trace = str(out)
    asyncio.run(ScenarioRunner(cfg).run())


class TestScenarioEndToEnd:
    def test_ogha_facts_passes_all(self, tmp_path: Path) -> None:
        out = tmp_path / "ogha.jsonl"
        _run("ogha_facts", out)
        results = validate_trace(out, _SCENARIO)
        assert results, "expected validators to run"
        assert all(r.passed for r in results), [r.detail for r in results if not r.passed]

    def test_datafacts_v1_fails_every_adversarial_check(self, tmp_path: Path) -> None:
        out = tmp_path / "v1.jsonl"
        _run("datafacts_v1", out)
        results = {r.name: r.passed for r in validate_trace(out, _SCENARIO)}
        # Happy-path lineage still resolves (v1 keeps parents in its metadata).
        assert results["provenance_chain_integrity"] is True
        # Every adversarial + OGHA-specific check must catch v1.
        assert results["provenance_substitution_resistant"] is False
        assert results["provenance_freshness_unforgeable"] is False
        assert results["provenance_chain_unforgeable"] is False
        assert results["evaluation_pii_redacted"] is False
        assert results["evaluation_acl_enforced"] is False

    def test_passed_verdict_configurable(self, tmp_path: Path) -> None:
        # The scenario honours task.config.verdict; both directions stay valid.
        out = tmp_path / "passed.jsonl"
        cfg = ScenarioConfig.from_yaml("scenarios/interview_evaluation_delivery.yaml")
        cfg.layers.datafacts = "ogha_facts"
        cfg.task.config = {"verdict": "PASSED"}
        cfg.output.trace = str(out)
        asyncio.run(ScenarioRunner(cfg).run())
        assert all(r.passed for r in validate_trace(out, _SCENARIO))

    def test_deterministic_across_required_seeds(self, tmp_path: Path) -> None:
        for seed in (42, 7, 1337):
            a, b = tmp_path / f"{seed}a.jsonl", tmp_path / f"{seed}b.jsonl"
            _run("ogha_facts", a, seed=seed)
            _run("ogha_facts", b, seed=seed)
            assert a.read_bytes() == b.read_bytes(), f"seed {seed} not deterministic"
            assert all(r.passed for r in validate_trace(a, _SCENARIO))
