# SPDX-License-Identifier: Apache-2.0
"""End-to-end tests for manifest_delegated_auth scenario + validators.

The headline proof is the plugin swap:

* ``auth: jwt`` FAILS all four adversarial validators, because central
  re-issuance does not preserve manifest binding, delegation caveats,
  revocation ancestry, or presenter audience.
* ``auth: manifest_delegatable`` PASSES all four, while still verifying 12 honest leaves.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_core.validators import validate_trace

_SCENARIO_YAML = Path(__file__).parent.parent.parent.parent / "scenarios" / "manifest_delegated_auth.yaml"


def _config(auth: str, trace: Path, seed: int | None = None) -> ScenarioConfig:
    config = ScenarioConfig.from_yaml(_SCENARIO_YAML)
    config.layers.auth = auth
    config.output.trace = str(trace)
    if seed is not None:
        config.seed = seed
    return config


def _results(trace: Path) -> dict[str, bool]:
    return {r.name: r.passed for r in validate_trace(trace, "manifest_delegated_auth")}


class TestAdversarialProof:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("seed", [1, 7, 42, 123, 9999])
    async def test_validators_pass_under_manifest_delegatable(
        self, tmp_path: Path, seed: int
    ) -> None:
        trace = tmp_path / f"manifest-delegatable-{seed}.jsonl"
        await ScenarioRunner(_config("manifest_delegatable", trace, seed=seed)).run()
        results = _results(trace)
        assert results["manifest_delegated_auth_manifest_binding"] is True
        assert results["manifest_delegated_auth_scope_containment"] is True
        assert results["manifest_delegated_auth_no_stale_parent"] is True
        assert results["manifest_delegated_auth_audience_binding"] is True

    @pytest.mark.asyncio
    async def test_validators_fail_under_jwt(self, tmp_path: Path) -> None:
        trace = tmp_path / "jwt.jsonl"
        await ScenarioRunner(_config("jwt", trace)).run()
        results = _results(trace)
        assert results["manifest_delegated_auth_manifest_binding"] is False
        assert results["manifest_delegated_auth_scope_containment"] is False
        assert results["manifest_delegated_auth_no_stale_parent"] is False
        assert results["manifest_delegated_auth_audience_binding"] is False


class TestDeterminism:
    @pytest.mark.asyncio
    async def test_same_seed_identical_trace(self, tmp_path: Path) -> None:
        t1 = tmp_path / "run1.jsonl"
        t2 = tmp_path / "run2.jsonl"
        await ScenarioRunner(_config("manifest_delegatable", t1)).run()
        await ScenarioRunner(_config("manifest_delegatable", t2)).run()
        h1 = hashlib.sha256(t1.read_bytes()).hexdigest()
        h2 = hashlib.sha256(t2.read_bytes()).hexdigest()
        assert h1 == h2


class TestScenarioShape:
    @pytest.mark.asyncio
    async def test_emits_honest_leaves_and_attack_lines(self, tmp_path: Path) -> None:
        trace = tmp_path / "shape.jsonl"
        await ScenarioRunner(_config("manifest_delegatable", trace)).run()
        text = trace.read_text()
        events = [json.loads(line) for line in text.splitlines()]
        starts = [event["agent"] for event in events if event.get("kind") == "start"]
        assert len(starts) == 17
        assert sum(agent.startswith("intermediary-") for agent in starts) == 3
        assert sum(agent.startswith("leaf-") for agent in starts) == 12
        assert text.count("honest_leaf:") == 24  # send + receive for 12 audit messages
        assert "attack:manifest_tamper:blocked" in text
        assert "attack:scope_escalation:blocked" in text
        assert "attack:stale_parent:blocked" in text
        assert "attack:audience_confusion:blocked" in text
