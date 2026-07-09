# SPDX-License-Identifier: Apache-2.0
"""End-to-end tests for the rogue_trusted_agent scenario + adversarial validator.

The headline assertions are the adversarial contrast the submission needs:

* the ``rogue_trusted_agent`` block validator **FAILS** under
  ``trust: score_average`` (no pre-action gate, so the veteran's reputation buys
  it the treasury and the rogue action executes), and
* **PASSES** under ``trust: aae_permit_gate`` (the request is refused before it
  runs, a signed denial envelope is issued, and the veteran's permit chain
  verifies),

plus a byte-level determinism check (same seed -> identical trace sha256).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_core.validators import validate_trace
from nest_plugins_reference.trust.aae_envelope import order_chain, verify_envelope

_SCENARIO_YAML = (
    Path(__file__).parent.parent.parent.parent / "scenarios" / "rogue_trusted_agent.yaml"
)


def _config(trust: str, trace: Path, seed: int | None = None) -> ScenarioConfig:
    """Load the scenario YAML, override the trust plugin, seed, and trace path."""
    config = ScenarioConfig.from_yaml(_SCENARIO_YAML)
    config.layers.trust = trust
    config.output.trace = str(trace)
    if seed is not None:
        config.seed = seed
    return config


def _results(trace: Path) -> dict[str, bool]:
    return {r.name: r.passed for r in validate_trace(trace, "rogue_trusted_agent")}


def _veteran_envelopes(trace: Path) -> list[dict[str, object]]:
    """Reconstruct the veteran's permit envelopes from ``permit_env:`` lines."""
    envelopes: list[dict[str, object]] = []
    for line in trace.read_text().splitlines():
        if not line.strip():
            continue
        event = json.loads(line)
        msg = str(event.get("msg", ""))
        if event.get("kind") == "broadcast" and msg.startswith("permit_env:"):
            envelopes.append(json.loads(msg[len("permit_env:") :]))
    return envelopes


class TestAdversarialProof:
    @pytest.mark.asyncio
    async def test_validator_fails_under_score_average(self, tmp_path: Path) -> None:
        trace = tmp_path / "baseline.jsonl"
        await ScenarioRunner(_config("score_average", trace)).run()
        # The naive baseline has no pre-action gate: the rogue action executes.
        assert "exec:veteran:spend:town/treasury" in trace.read_text()
        assert _results(trace)["rogue_trusted_agent_blocked"] is False

    @pytest.mark.asyncio
    @pytest.mark.parametrize("seed", [1, 7, 42, 123, 9999])
    async def test_validator_passes_under_permit_gate(self, tmp_path: Path, seed: int) -> None:
        trace = tmp_path / f"ours_{seed}.jsonl"
        await ScenarioRunner(_config("aae_permit_gate", trace, seed=seed)).run()
        results = _results(trace)
        assert results["rogue_trusted_agent_blocked"] is True
        assert results["rogue_trusted_agent_reputation"] is True
        # The rogue action must never have executed.
        assert "exec:veteran:spend:town/treasury" not in trace.read_text()

    @pytest.mark.asyncio
    async def test_signed_denial_and_chain_verify(self, tmp_path: Path) -> None:
        trace = tmp_path / "gate.jsonl"
        await ScenarioRunner(_config("aae_permit_gate", trace)).run()
        envelopes = _veteran_envelopes(trace)
        # Every emitted envelope is a valid signature.
        assert envelopes
        assert all(verify_envelope(env) for env in envelopes)
        # Exactly the treasury spend is the signed refusal.
        denials = [
            env
            for env in envelopes
            if env["outcome"] == "denied"
            and env["action"]
            == {  # type: ignore[comparison-overlap]
                "verb": "spend",
                "resource": "town/treasury",
                "params": {},
            }
        ]
        assert len(denials) == 1
        assert verify_envelope(denials[0])
        # The veteran's full history is one intact, ordered chain.
        assert order_chain(envelopes) is not None


class TestDeterminism:
    @pytest.mark.asyncio
    async def test_same_seed_identical_trace(self, tmp_path: Path) -> None:
        t1 = tmp_path / "run1.jsonl"
        t2 = tmp_path / "run2.jsonl"
        await ScenarioRunner(_config("aae_permit_gate", t1)).run()
        await ScenarioRunner(_config("aae_permit_gate", t2)).run()
        h1 = hashlib.sha256(t1.read_bytes()).hexdigest()
        h2 = hashlib.sha256(t2.read_bytes()).hexdigest()
        assert h1 == h2
