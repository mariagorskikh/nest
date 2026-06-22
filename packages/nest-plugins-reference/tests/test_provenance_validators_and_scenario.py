# SPDX-License-Identifier: Apache-2.0
"""Validator + end-to-end scenario tests for the content-addressed datafacts plugin.

Three layers of coverage:

1. **Validator unit tests** — hand-built trace lines exercising the pass and
   fail paths of each of the three provenance validators.
2. **Adversarial discrimination** — the *same* ``provenance_supply_chain``
   scenario run through the default ``datafacts_v1`` plugin MUST FAIL all three
   validators (it is name-addressed, unsigned, provenance-blind), and through
   ``content_addressed`` MUST PASS them. This is the charter's bar for "a
   validator that catches a class of attacks the default reference plugin would
   miss."
3. **Determinism** — same seed yields a byte-identical trace, and the validators
   pass under seeds 42, 7, and 1337.
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path
from typing import Any

import pytest
from nest_core.plugins import PluginRegistry
from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_core.validators import (
    ValidationResult,
    validate_datafacts_content_addressing,
    validate_datafacts_freshness_proofs,
    validate_datafacts_provenance_chain,
    validate_events,
)


def _send(agent: str, msg: str) -> dict[str, Any]:
    return {"kind": "send", "agent": agent, "to": "auditor-0", "msg": msg}


def _only(results: list[ValidationResult]) -> ValidationResult:
    assert len(results) == 1
    return results[0]


# ---------------------------------------------------------------------------
# Validator unit tests — content addressing
# ---------------------------------------------------------------------------


def test_content_addressing_passes_on_hashed_urls_and_deflected_substitution() -> None:
    events = [
        _send("supplier-0", "publish:supplier-0:sha256-aaa:-:0.0"),
        _send("byz-0", "attack:substitution:byz-0:sha256-bbb:sha256-ccc"),
    ]
    assert _only(validate_datafacts_content_addressing(events)).passed


def test_content_addressing_fails_on_name_addressed_url() -> None:
    events = [_send("supplier-0", "publish:supplier-0:dataset-supplier-0:-:0.0")]
    result = _only(validate_datafacts_content_addressing(events))
    assert not result.passed
    assert "non-content-addressed" in result.detail


def test_content_addressing_fails_when_substitution_lands_same_address() -> None:
    events = [_send("byz-0", "attack:substitution:byz-0:victim:victim")]
    assert not _only(validate_datafacts_content_addressing(events)).passed


# ---------------------------------------------------------------------------
# Validator unit tests — freshness proofs
# ---------------------------------------------------------------------------


def test_freshness_passes_on_current_signed_proof() -> None:
    events = [_send("supplier-0", "freshness:supplier-0:sha256-aaa:3.0:3.0:ok")]
    assert _only(validate_datafacts_freshness_proofs(events)).passed


def test_freshness_fails_on_unsigned_claim() -> None:
    events = [_send("supplier-0", "freshness:supplier-0:dataset-x:none:3.0:ok")]
    result = _only(validate_datafacts_freshness_proofs(events))
    assert not result.passed
    assert "no signed proof" in result.detail


def test_freshness_fails_on_non_current_ok_claim() -> None:
    events = [_send("byz-0", "freshness:byz-0:sha256-aaa:1.0:3.0:ok")]
    assert not _only(validate_datafacts_freshness_proofs(events)).passed


def test_freshness_accepts_detectable_stale_claim() -> None:
    events = [_send("byz-0", "freshness:byz-0:sha256-aaa:1.0:3.0:stale")]
    assert _only(validate_datafacts_freshness_proofs(events)).passed


# ---------------------------------------------------------------------------
# Validator unit tests — provenance chain
# ---------------------------------------------------------------------------


def test_provenance_passes_on_anchored_chain() -> None:
    events = [
        _send("supplier-0", "publish:supplier-0:sha256-a:-:0.0"),
        _send("manufacturer-0", "publish:manufacturer-0:sha256-b:sha256-a:0.0"),
        _send("byz-0", "attack:broken:byz-0:sha256-ghost:rejected"),
        _send("retailer-0", "verify:retailer-0:sha256-b:ok"),
    ]
    assert _only(validate_datafacts_provenance_chain(events)).passed


def test_provenance_fails_on_dangling_parent() -> None:
    events = [_send("byz-0", "publish:byz-0:sha256-b:sha256-ghost:0.0")]
    result = _only(validate_datafacts_provenance_chain(events))
    assert not result.passed
    assert "unpublished parent" in result.detail


def test_provenance_fails_when_broken_attack_accepted() -> None:
    events = [_send("byz-0", "attack:broken:byz-0:sha256-ghost:accepted")]
    assert not _only(validate_datafacts_provenance_chain(events)).passed


def test_provenance_fails_when_end_to_end_verify_not_ok() -> None:
    events = [_send("retailer-0", "verify:retailer-0:dataset-x:unverifiable")]
    assert not _only(validate_datafacts_provenance_chain(events)).passed


# ---------------------------------------------------------------------------
# Full simulator integration — adversarial discrimination + determinism
# ---------------------------------------------------------------------------

SCENARIO_PATH = Path(__file__).resolve().parents[3] / "scenarios" / "provenance_supply_chain.yaml"


def _run_scenario(seed: int, datafacts: str | None = None) -> tuple[bytes, list[dict[str, Any]]]:
    """Run the scenario; return (raw trace bytes, parsed events)."""
    import json

    config = ScenarioConfig.from_yaml(str(SCENARIO_PATH))
    config = config.model_copy(update={"seed": seed})
    if datafacts is not None:
        config = config.model_copy(
            update={"layers": config.layers.model_copy(update={"datafacts": datafacts})}
        )
    with tempfile.TemporaryDirectory() as tmp:
        trace_path = Path(tmp) / f"prov_{seed}.jsonl"
        config = config.model_copy(
            update={"output": config.output.model_copy(update={"trace": str(trace_path)})}
        )
        runner = ScenarioRunner(config, registry=PluginRegistry())
        asyncio.run(runner.run())
        raw = trace_path.read_bytes()
    events = [json.loads(line) for line in raw.decode().splitlines() if line.strip()]
    return raw, events


@pytest.mark.skipif(not SCENARIO_PATH.exists(), reason="scenario yaml not found")
def test_content_addressed_passes_all_validators() -> None:
    _raw, events = _run_scenario(42)
    results = validate_events(events, "provenance_supply_chain")
    assert len(results) == 3
    assert all(r.passed for r in results), [r.detail for r in results if not r.passed]


@pytest.mark.skipif(not SCENARIO_PATH.exists(), reason="scenario yaml not found")
def test_datafacts_v1_fails_all_validators() -> None:
    """The same scenario on the default plugin fails every provenance validator."""
    _raw, events = _run_scenario(42, datafacts="datafacts_v1")
    results = validate_events(events, "provenance_supply_chain")
    assert len(results) == 3
    assert all(not r.passed for r in results), [r.name for r in results if r.passed]


@pytest.mark.skipif(not SCENARIO_PATH.exists(), reason="scenario yaml not found")
def test_trace_is_byte_identical_under_replay() -> None:
    first, _ = _run_scenario(42)
    second, _ = _run_scenario(42)
    assert first == second


@pytest.mark.skipif(not SCENARIO_PATH.exists(), reason="scenario yaml not found")
@pytest.mark.parametrize("seed", [42, 7, 1337])
def test_validators_pass_under_seed_bank(seed: int) -> None:
    _raw, events = _run_scenario(seed)
    results = validate_events(events, "provenance_supply_chain")
    assert all(r.passed for r in results), [r.detail for r in results if not r.passed]
