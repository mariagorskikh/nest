# SPDX-License-Identifier: Apache-2.0
"""Tests for the provenance_supply_chain adversarial validators and scenario.

The core claim under test: the three adversarial validators FAIL against the
default ``datafacts_v1`` layer (name-addressed, unauthenticated freshness, no
provenance) and PASS against ``cid_facts`` -- driven both from synthetic traces
and from a real simulator run over a diamond DAG.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_core.validators import (
    validate_provenance_chain_integrity,
    validate_provenance_chain_unforgeable,
    validate_provenance_freshness_unforgeable,
    validate_provenance_substitution_resistant,
    validate_trace,
)

type Event = dict[str, Any]


def _send(msg: str) -> Event:
    return {"ts": 0.0, "agent": "verify-0", "kind": "send", "to": "verify-0", "msg": msg}


# ---------------------------------------------------------------------------
# Validator unit tests (synthetic traces)
# ---------------------------------------------------------------------------


class TestChainIntegrity:
    def test_pass_when_chain_resolves(self) -> None:
        events = [_send("chain_ok|df://sha256-final|3")]
        results = validate_provenance_chain_integrity(events)
        assert results[0].passed is True

    def test_fail_when_chain_broken(self) -> None:
        events = [_send("chain_broken|df://sha256-final|df://sha256-missing")]
        results = validate_provenance_chain_integrity(events)
        assert results[0].passed is False

    def test_fail_when_nothing_recorded(self) -> None:
        results = validate_provenance_chain_integrity([])
        assert results[0].passed is False


class TestSubstitutionResistant:
    def test_pass_when_attacker_lands_on_distinct_url(self) -> None:
        events = [_send("attack_substitution|df://sha256-root|df://sha256-attacker|0")]
        results = validate_provenance_substitution_resistant(events)
        assert results[0].passed is True

    def test_fail_when_attacker_collides_with_source(self) -> None:
        # datafacts_v1 behaviour: name-addressed, so the attacker's republish
        # overwrites the exact same URL as the source.
        events = [_send("attack_substitution|df://raw|df://raw|1")]
        results = validate_provenance_substitution_resistant(events)
        assert results[0].passed is False

    def test_fail_when_no_attack_recorded(self) -> None:
        results = validate_provenance_substitution_resistant([])
        assert results[0].passed is False


class TestFreshnessUnforgeable:
    def test_pass_when_forged_claim_rejected(self) -> None:
        events = [_send("attack_forged_freshness|df://sha256-x|0")]
        results = validate_provenance_freshness_unforgeable(events)
        assert results[0].passed is True

    def test_fail_when_forged_claim_accepted(self) -> None:
        # datafacts_v1 behaviour: wall-clock freshness trusts any republish.
        events = [_send("attack_forged_freshness|df://raw|1")]
        results = validate_provenance_freshness_unforgeable(events)
        assert results[0].passed is False


class TestChainUnforgeable:
    def test_pass_when_phantom_parent_rejected(self) -> None:
        events = [_send("attack_provenance|df://sha256-phantom|1")]
        results = validate_provenance_chain_unforgeable(events)
        assert results[0].passed is True

    def test_fail_when_phantom_parent_accepted(self) -> None:
        # datafacts_v1 behaviour: no provenance concept, publish always succeeds.
        events = [_send("attack_provenance|df://sha256-phantom|0")]
        results = validate_provenance_chain_unforgeable(events)
        assert results[0].passed is False


# ---------------------------------------------------------------------------
# End-to-end: real simulator run
# ---------------------------------------------------------------------------


def _run(datafacts: str, out: Path, seed: int = 42) -> None:
    cfg = ScenarioConfig.from_yaml("scenarios/provenance_supply_chain.yaml")
    cfg.layers.datafacts = datafacts
    cfg.seed = seed
    cfg.output.trace = str(out)
    asyncio.run(ScenarioRunner(cfg).run())


class TestScenarioEndToEnd:
    def test_cid_facts_passes_all(self, tmp_path: Path) -> None:
        out = tmp_path / "cid_facts.jsonl"
        _run("cid_facts", out)
        results = validate_trace(out, "provenance_supply_chain")
        assert results, "expected validators to run"
        assert all(r.passed for r in results), [r.detail for r in results if not r.passed]

    def test_diamond_walk_visits_all_four_nodes(self, tmp_path: Path) -> None:
        """The full DAG walk must count both refiner branches, not just one spine."""
        out = tmp_path / "cid_facts.jsonl"
        _run("cid_facts", out)
        chain_ok = [
            msg
            for line in out.read_text().splitlines()
            if (msg := str(json.loads(line).get("msg", ""))).startswith("chain_ok|")
        ]
        assert chain_ok, "no chain_ok recorded"
        # source + refine-a + refine-b + aggregate = 4 distinct lineage nodes.
        assert chain_ok[0].rsplit("|", 1)[-1] == "4"

    def test_datafacts_v1_fails_all_adversarial_checks(self, tmp_path: Path) -> None:
        out = tmp_path / "v1.jsonl"
        _run("datafacts_v1", out)
        results = {r.name: r.passed for r in validate_trace(out, "provenance_supply_chain")}
        # The happy-path lineage walk still works -- v1 stores parents in its
        # metadata dict even though it never validates them.
        assert results["provenance_chain_integrity"] is True
        assert results["provenance_substitution_resistant"] is False
        assert results["provenance_freshness_unforgeable"] is False
        assert results["provenance_chain_unforgeable"] is False

    def test_deterministic_across_required_seeds(self, tmp_path: Path) -> None:
        for seed in (42, 7, 1337):
            a, b = tmp_path / f"{seed}a.jsonl", tmp_path / f"{seed}b.jsonl"
            _run("cid_facts", a, seed=seed)
            _run("cid_facts", b, seed=seed)
            assert a.read_bytes() == b.read_bytes(), f"seed {seed} not deterministic"
            assert all(r.passed for r in validate_trace(a, "provenance_supply_chain"))
