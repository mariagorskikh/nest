# SPDX-License-Identifier: Apache-2.0
"""End-to-end scenario tests for the streaming payments plugin.

Boots ``streaming_payments`` (and its partition variant) through the real
``Simulator`` and proves:

* all three validators PASS under ``payments: streaming``;
* all three validators FAIL under ``payments: prepaid_credits`` (which has
  no streaming surface and quietly pre-pays) — the adversarial
  discrimination the charter asks for;
* a full buyer/seller partition results in **zero** money flow;
* same seed → byte-identical trace (determinism).
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
from nest_core.validators import validate_trace

_SCENARIOS = Path(__file__).resolve().parents[3] / "scenarios"
SCENARIO_PATH = _SCENARIOS / "streaming_payments.yaml"
PARTITION_PATH = _SCENARIOS / "streaming_payments_partition.yaml"


def _run(yaml_path: Path, plugin_name: str, seed: int = 42) -> Path:
    """Run a scenario YAML with the chosen payments plugin; return the trace path."""
    config = ScenarioConfig.from_yaml(str(yaml_path))
    layers = config.layers.model_copy(update={"payments": plugin_name})
    trace_path = Path(tempfile.mkdtemp()) / f"streaming_{plugin_name}_{seed}.jsonl"
    config = config.model_copy(
        update={
            "layers": layers,
            "seed": seed,
            "output": config.output.model_copy(update={"trace": str(trace_path)}),
        }
    )
    runner = ScenarioRunner(config, registry=PluginRegistry())
    asyncio.run(runner.run())
    return trace_path


@pytest.mark.skipif(not SCENARIO_PATH.exists(), reason=f"scenario not at {SCENARIO_PATH}")
def test_streaming_plugin_passes_all_three_validators() -> None:
    """Under 5% message drop, conservation, close-finality, and ack-gating all hold."""
    trace_path = _run(SCENARIO_PATH, "streaming")
    results = validate_trace(trace_path, "streaming_payments")
    summary = [f"{'PASS' if r.passed else 'FAIL'} {r.name}: {r.detail}" for r in results]
    assert all(r.passed for r in results), "\n".join(summary)


@pytest.mark.skipif(not SCENARIO_PATH.exists(), reason=f"scenario not at {SCENARIO_PATH}")
def test_prepaid_credits_fails_all_three_validators() -> None:
    """The one-shot default plugin cannot fake a streaming lifecycle.

    Buyers fall back to a flat upfront ``pay()``, so the trace carries no
    ``stream:*`` events and every validator reports the absence.
    """
    trace_path = _run(SCENARIO_PATH, "prepaid_credits")
    results = validate_trace(trace_path, "streaming_payments")
    by_name = {r.name: r for r in results}
    assert not by_name["streaming_conservation"].passed
    assert not by_name["streaming_no_drain_after_close"].passed
    assert not by_name["streaming_no_overbill_on_partition"].passed


@pytest.mark.skipif(not PARTITION_PATH.exists(), reason=f"scenario not at {PARTITION_PATH}")
def test_partitioned_buyers_bill_nothing() -> None:
    """Full buyer/seller partition: streams open, but zero money moves.

    No ack can cross the partition, so delivery-gated billing drains
    nothing — the no-overbill property in its purest form. The validators
    still pass: not billing for undelivered work is the correct behavior.
    """
    trace_path = _run(PARTITION_PATH, "streaming")
    results = validate_trace(trace_path, "streaming_payments")
    assert all(r.passed for r in results), [
        f"{r.name}: {r.detail}" for r in results if not r.passed
    ]

    debits = 0
    opened = 0
    for line in trace_path.read_text().splitlines():
        ev = json.loads(line)
        msg = str(ev.get("msg", ""))
        if ev.get("kind") == "broadcast" and msg.startswith("stream:debit:"):
            debits += 1
        if ev.get("kind") == "broadcast" and msg.startswith("stream:opened:"):
            opened += 1
    assert opened > 0, "streams should still open on the buyer side"
    assert debits == 0, f"partitioned payers must bill nothing, saw {debits} debits"


@pytest.mark.skipif(not SCENARIO_PATH.exists(), reason=f"scenario not at {SCENARIO_PATH}")
def test_streaming_scenario_deterministic_under_replay() -> None:
    """Two runs with seed 42 produce identical trace bytes."""
    a = _run(SCENARIO_PATH, "streaming", seed=42).read_bytes()
    b = _run(SCENARIO_PATH, "streaming", seed=42).read_bytes()
    assert a == b


@pytest.mark.skipif(not SCENARIO_PATH.exists(), reason=f"scenario not at {SCENARIO_PATH}")
@pytest.mark.parametrize("seed", [7, 1337])
def test_streaming_scenario_passes_across_seeds(seed: int) -> None:
    """Validator verdicts hold across seeds, not just the YAML default."""
    trace_path = _run(SCENARIO_PATH, "streaming", seed=seed)
    results = validate_trace(trace_path, "streaming_payments")
    assert all(r.passed for r in results), [
        f"{r.name}: {r.detail}" for r in results if not r.passed
    ]
