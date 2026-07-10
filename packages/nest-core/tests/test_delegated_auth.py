# SPDX-License-Identifier: Apache-2.0
"""Tests for the delegated_auth validators and scenario.

Verifies that the capability delegation validators FAIL when using the default
'jwt' auth plugin (which ignores delegation constraints) and PASS when using
'delegatable'.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_core.validators import validate_trace


def _run(auth: str, out: Path, seed: int = 42) -> None:
    cfg = ScenarioConfig.from_yaml("scenarios/delegated_auth.yaml")
    cfg.layers.auth = auth
    cfg.seed = seed
    cfg.duration = "ticks: 1000"
    cfg.output.trace = str(out)
    asyncio.run(ScenarioRunner(cfg).run())


class TestDelegatedAuthScenario:
    def test_delegatable_passes(self, tmp_path: Path) -> None:
        out = tmp_path / "delegatable.jsonl"
        _run("delegatable_cascading", out)
        results = validate_trace(out, "delegated_auth")
        assert results, "expected validators to run"
        for r in results:
            assert r.passed is True, f"{r.name} failed: {r.detail}"

    def test_jwt_fails_all_checks(self, tmp_path: Path) -> None:
        out = tmp_path / "jwt.jsonl"
        _run("jwt", out)
        results = {r.name: r.passed for r in validate_trace(out, "delegated_auth")}
        assert results["auth_no_scope_escalation"] is False
        assert results["auth_no_stale_parent"] is False
        assert results["auth_no_audience_confusion"] is False

    def test_deterministic_across_seeds(self, tmp_path: Path) -> None:
        for seed in (42, 7, 1337):
            a, b = tmp_path / f"{seed}a.jsonl", tmp_path / f"{seed}b.jsonl"
            _run("delegatable_cascading", a, seed=seed)
            _run("delegatable_cascading", b, seed=seed)
            assert a.read_bytes() == b.read_bytes(), f"seed {seed} not deterministic"
            results = validate_trace(a, "delegated_auth")
            assert all(r.passed for r in results)
