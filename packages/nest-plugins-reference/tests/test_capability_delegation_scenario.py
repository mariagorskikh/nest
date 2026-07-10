# SPDX-License-Identifier: Apache-2.0
"""End-to-end scenario test: the capability_delegation tree under all three attacks.

Runs the ``capability_delegation`` scenario against both the ``macaroon`` plugin
(all attacks denied → trace validator passes) and the reference ``jwt`` plugin
(attacks admitted → trace validator fails), and asserts determinism: the same
seed produces a byte-identical trace.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_plugins_reference.validators.capability_delegation_validators import (
    validate_capability_delegation_trace,
)

_YAML = Path(__file__).resolve().parents[3] / "scenarios" / "capability_delegation.yaml"


def _config(auth: str, trace: Path) -> ScenarioConfig:
    cfg = ScenarioConfig.from_yaml(_YAML)
    cfg.layers.auth = auth
    cfg.output.trace = str(trace)
    return cfg


@pytest.mark.asyncio
async def test_macaroon_denies_every_attack(tmp_path: Path) -> None:
    """Under the macaroon plugin, every attack is denied and honest use allowed."""
    trace = tmp_path / "macaroon.jsonl"
    await ScenarioRunner(_config("macaroon", trace)).run()
    reports = validate_capability_delegation_trace(trace)
    assert all(r.passed for r in reports), [r.detail for r in reports if not r.passed]


@pytest.mark.asyncio
async def test_reference_jwt_admits_attacks(tmp_path: Path) -> None:
    """Under the reference jwt plugin, the trace validator fails (adversarial bar)."""
    trace = tmp_path / "jwt.jsonl"
    await ScenarioRunner(_config("jwt", trace)).run()
    reports = validate_capability_delegation_trace(trace)
    assert not all(r.passed for r in reports)


@pytest.mark.asyncio
@pytest.mark.parametrize("auth", ["macaroon", "jwt"])
async def test_trace_is_byte_deterministic(tmp_path: Path, auth: str) -> None:
    """Same seed → byte-identical trace across two runs, in *both* arms.

    The jwt arm matters as much as the macaroon arm: tokens ride in the
    ``present:`` payloads that land in the trace, so an auth plugin left on
    wall-clock time (the ``clock=0.0`` provisioning in ``_provision_auth``)
    would leak nondeterminism into the trace bytes.
    """
    t1, t2 = tmp_path / "a.jsonl", tmp_path / "b.jsonl"
    await ScenarioRunner(_config(auth, t1)).run()
    await ScenarioRunner(_config(auth, t2)).run()
    assert hashlib.sha256(t1.read_bytes()).digest() == hashlib.sha256(t2.read_bytes()).digest()
