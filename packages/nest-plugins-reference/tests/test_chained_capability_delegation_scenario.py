# SPDX-License-Identifier: Apache-2.0
"""End-to-end integration test for the ``chained_capability_delegation``
scenario.

Boots the real ``Simulator`` against the real ``chained_capability`` auth
plugin and asserts the delegation tree forms, the adversarial probe's
three attacks are all blocked, the scoped branch revocation only affects
its own subtree, the root revocation takes down everyone else, and the
whole trace is byte-identical across two runs of the same seed (the
plugin must not read wall-clock time or unseeded randomness).

Trace events are recorded twice per broadcast in the raw JSONL -- once as
the sender's own ``kind: "broadcast"`` record, once per recipient as a
``kind: "receive"`` record carrying the same ``msg``. Assertions here
filter to the sender-side ``kind: "broadcast"`` envelope so each logical
event (issue / delegate / verify / revoke / revocation-detected) is
counted exactly once.
"""

from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path
from typing import cast

import pytest
from nest_core.plugins import PluginRegistry
from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig

SCENARIO_PATH = (
    Path(__file__).resolve().parents[3] / "scenarios" / "chained_capability_delegation.yaml"
)


def _run(seed: int, trace_path: Path) -> list[dict[str, object]]:
    """Run the scenario and return the parsed sender-side broadcast events."""
    config = ScenarioConfig.from_yaml(str(SCENARIO_PATH))
    config = config.model_copy(update={"seed": seed})
    config = config.model_copy(
        update={"output": config.output.model_copy(update={"trace": str(trace_path)})}
    )
    runner = ScenarioRunner(config, registry=PluginRegistry())
    asyncio.run(runner.run())

    events: list[dict[str, object]] = []
    with trace_path.open() as f:
        for line in f:
            rec = json.loads(line)
            if rec.get("kind") != "broadcast":
                continue
            try:
                msg = json.loads(rec["msg"])
            except (json.JSONDecodeError, TypeError):
                continue
            if isinstance(msg, dict) and "kind" in msg:
                events.append({**msg, "ts": rec["ts"]})
    return events


@pytest.mark.parametrize("seed", [42, 7, 1337])
def test_delegation_tree_forms_and_cascades_on_revocation(seed: int) -> None:
    if not SCENARIO_PATH.exists():
        pytest.skip(f"scenario not found at {SCENARIO_PATH}")

    with tempfile.TemporaryDirectory() as tmp:
        events = _run(seed, Path(tmp) / f"chained_capability_delegation_{seed}.jsonl")

    by_kind: dict[str, list[dict[str, object]]] = {}
    for e in events:
        by_kind.setdefault(str(e["kind"]), []).append(e)

    # 1 root issuance.
    assert len(by_kind.get("issued", [])) == 1

    # 3 coordinator->intermediary + 12 intermediary->leaf delegations.
    assert len(by_kind.get("delegated", [])) == 15

    # Adversarial probe: all three named attack classes must be blocked.
    audits = {e["attack"]: e["blocked"] for e in by_kind.get("delegation_audit", [])}
    assert audits == {
        "scope_escalation": True,
        "stale_ancestor": True,
        "audience_confusion": True,
    }

    # Every non-coordinator agent (3 intermediaries + 12 leaves) verifies its handoff once.
    verified_agents = {e["agent"] for e in by_kind.get("verified", [])}
    assert len(verified_agents) == 15
    assert "intermediary-1" in verified_agents
    assert "leaf-1-0" in verified_agents

    # Exactly 2 revocations: the scoped branch, then the root.
    revoked_targets = {e["target"] for e in by_kind.get("revoked", [])}
    assert revoked_targets == {"intermediary-1", "root"}

    # Cascading revocation: intermediary-1's subtree (itself + 4 leaves) goes
    # dark at the branch revoke; everyone else (2 intermediaries + 8 leaves)
    # goes dark only at the root revoke.
    detected = by_kind.get("revocation_detected", [])
    assert len(detected) == 15

    branch_subtree = {"intermediary-1", "leaf-1-0", "leaf-1-1", "leaf-1-2", "leaf-1-3"}
    rest_of_tree = {
        "intermediary-0",
        "intermediary-2",
        *[f"leaf-0-{j}" for j in range(4)],
        *[f"leaf-2-{j}" for j in range(4)],
    }
    assert branch_subtree | rest_of_tree == {str(a) for a in verified_agents}

    detected_before_root = {e["agent"] for e in detected if cast("float", e["ts"]) < 500.0}
    detected_at_or_after_root = {e["agent"] for e in detected if cast("float", e["ts"]) >= 500.0}
    assert detected_before_root == branch_subtree
    assert detected_at_or_after_root == rest_of_tree


def test_scenario_deterministic_under_replay() -> None:
    """Two runs with the same seed produce identical event sequences.

    This is the concrete check that the plugin's ``jti`` generation and
    clock are fully seed-driven -- a random UUID or a wall-clock read
    would make this test flaky.
    """
    if not SCENARIO_PATH.exists():
        pytest.skip(f"scenario not found at {SCENARIO_PATH}")

    with tempfile.TemporaryDirectory() as tmp:
        first = _run(42, Path(tmp) / "run_a.jsonl")
        second = _run(42, Path(tmp) / "run_b.jsonl")

    assert first == second
