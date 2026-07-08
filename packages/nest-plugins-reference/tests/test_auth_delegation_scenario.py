# SPDX-License-Identifier: Apache-2.0
"""Full-simulator integration for ''delegatable'' auth layer (Problem 04).

Boots ``scenarios/auth_delegation.yaml`` through the real
:class:`~nest_core.runner.ScenarioRunner` to prove the delegatable auth plugin
integrates into an end-to-end run without breaking the simulator, and that the run
stays deterministic under replay (Tier-1). The delegation *mechanics* are exercised
directly in ``test_auth_delegation.py`` and
``test_auth_delegation_properties.py``; here we verify the plugin is discoverable
and simulator-safe.

Example::

    pytest packages/nest-plugins-reference/tests/test_auth_delegation_scenario.py
"""

from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path

import pytest
from nest_core.plugins import PluginRegistry
from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig

SCENARIO_PATH = (
    Path(__file__).resolve().parent.parent
    / "nest_plugins_reference"
    / "scenarios"
    / "auth_delegation.yaml"
)


def test_delegatable_auth_resolves_via_registry() -> None:
    """The registry discovers ``delegatable`` via the built-in map."""
    cls = PluginRegistry().resolve("auth", "delegatable")
    assert cls is not None
    assert cls.__name__ == "DelegatableAuth"


@pytest.mark.parametrize("seed", [42, 7])
def test_scenario_boots_and_runs(seed: int) -> None:
    """The scenario wiring the delegatable auth layer runs to completion."""
    if not SCENARIO_PATH.exists():
        pytest.skip(f"scenario not found at {SCENARIO_PATH}")
    config = ScenarioConfig.from_yaml(str(SCENARIO_PATH))
    assert config.layers.auth == "delegatable"
    config = config.model_copy(update={"seed": seed})
    with tempfile.TemporaryDirectory() as tmp:
        trace_path = Path(tmp) / f"auth_delegation_{seed}.jsonl"
        config = config.model_copy(
            update={"output": config.output.model_copy(update={"trace": str(trace_path)})}
        )
        runner = ScenarioRunner(config, registry=PluginRegistry())
        result = asyncio.run(runner.run())
        assert result.exists()
        assert result.stat().st_size > 0


def test_scenario_is_deterministic_under_replay() -> None:
    """Two seed-42 runs produce structurally identical traces (Tier-1 reproducibility).

    Token IDs are uuid4-based (intentionally non-deterministic per-run) so we
    compare the structural trace — event types, agent identities, timestamps —
    rather than raw bytes.  The token *values* legitimately differ between runs;
    what must be stable is the delegation-graph topology and the event sequence.
    """
    if not SCENARIO_PATH.exists():
        pytest.skip(f"scenario not found at {SCENARIO_PATH}")

    # Fields that differ legitimately between independent runs:
    #   payload/token/data/msg  — embed uuid4 token_id bytes
    #   size                    — byte-length of the token payload; varies because
    #                             time() floats serialize to different decimal widths
    #                             (e.g. 1751234567.12 vs 1751234567.123) which changes
    #                             the base64-encoded token length by ±1 byte.
    _non_deterministic = {"payload", "token", "data", "msg", "size"}

    def run_once() -> list[dict[str, object]]:
        config = ScenarioConfig.from_yaml(str(SCENARIO_PATH)).model_copy(update={"seed": 42})
        with tempfile.TemporaryDirectory() as tmp:
            trace_path = Path(tmp) / "auth_del_replay.jsonl"
            config = config.model_copy(
                update={"output": config.output.model_copy(update={"trace": str(trace_path)})}
            )
            runner = ScenarioRunner(config, registry=PluginRegistry())
            result = asyncio.run(runner.run())
            events: list[dict[str, object]] = [
                json.loads(line) for line in result.read_text().splitlines() if line.strip()
            ]
            # Strip fields that embed opaque, uuid4-keyed token strings.
            return [{k: v for k, v in evt.items() if k not in _non_deterministic} for evt in events]

    run_a = run_once()
    run_b = run_once()
    assert len(run_a) == len(run_b), (
        f"trace event count differs between replays: {len(run_a)} vs {len(run_b)}"
    )
    assert run_a == run_b, "trace structure is not deterministic under replay"
