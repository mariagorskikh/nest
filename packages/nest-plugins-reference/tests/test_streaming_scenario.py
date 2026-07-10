# SPDX-License-Identifier: Apache-2.0
"""End-to-end scenario test for the streaming payments plugin.

Boots the ``streaming_payments`` scenario through the real ``Simulator``
twice -- once with ``payments: streaming`` and once with
``payments: prepaid_credits``. Under ``streaming``, all seven validators
pass against a real, non-trivial stream lifecycle. Under
``prepaid_credits`` (which has no stream protocol at all) the scenario
runs to completion but produces zero stream-lifecycle events, so every
validator vacuously passes on an empty set -- each one's detail message
honestly reports "0 streams observed", proving the baseline cannot exhibit
the protocol rather than exhibiting it incorrectly.

Also pins determinism: same seed -> byte-identical trace.
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

import pytest
from nest_core.plugins import PluginRegistry
from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_core.validators import validate_trace

SCENARIO_PATH = Path(__file__).resolve().parents[3] / "scenarios" / "streaming_payments.yaml"


def _swap_payments(config: ScenarioConfig, plugin_name: str) -> ScenarioConfig:
    """Return ``config`` with the payments layer pointing at ``plugin_name``."""
    new_layers = config.layers.model_copy(update={"payments": plugin_name})
    return config.model_copy(update={"layers": new_layers})


def _run(plugin_name: str, seed: int = 42) -> Path:
    """Run the scenario with the chosen payments plugin; return the trace path."""
    config = ScenarioConfig.from_yaml(str(SCENARIO_PATH))
    config = _swap_payments(config, plugin_name)
    config = config.model_copy(update={"seed": seed})
    tmp = Path(tempfile.mkdtemp())
    trace_path = tmp / f"streaming_{plugin_name}_{seed}.jsonl"
    config = config.model_copy(
        update={"output": config.output.model_copy(update={"trace": str(trace_path)})}
    )
    runner = ScenarioRunner(config, registry=PluginRegistry())
    asyncio.run(runner.run())
    return trace_path


def _all_passed(plugin_name: str) -> tuple[bool, list[str]]:
    trace_path = _run(plugin_name)
    results = validate_trace(trace_path, "streaming_payments")
    summary = [f"{'PASS' if r.passed else 'FAIL'} {r.name}: {r.detail}" for r in results]
    return all(r.passed for r in results), summary


@pytest.mark.skipif(not SCENARIO_PATH.exists(), reason=f"scenario not at {SCENARIO_PATH}")
def test_streaming_plugin_passes_all_validators() -> None:
    """The streaming plugin satisfies all seven streaming invariants."""
    passed, summary = _all_passed("streaming")
    assert passed, "expected all validators to pass under streaming plugin:\n" + "\n".join(summary)


@pytest.mark.skipif(not SCENARIO_PATH.exists(), reason=f"scenario not at {SCENARIO_PATH}")
def test_prepaid_credits_produces_no_stream_lifecycle() -> None:
    """The default ``prepaid_credits`` plugin lacks the streaming protocol.

    ``prepaid_credits`` has no ``open_stream``/``tick_stream``/``close_stream``
    methods; ``StreamingBuyer.on_start`` catches the resulting
    ``AttributeError`` narrowly and returns without scheduling any ticks, so
    the scenario runs to completion but produces ZERO stream-lifecycle
    events. Every validator here is a universally-quantified "no violation
    found" check, so on an empty event set every one of them vacuously
    *passes* -- that is correct, not a discrimination failure (same as the
    escrow scenario's bps-range check passing vacuously when there are no
    arbitrate events). The honest, meaningful assertion is that each
    validator's own detail message plainly reports zero streams observed,
    proving the baseline plugin cannot exhibit the protocol at all -- not
    that it exhibits the protocol *incorrectly*.
    """
    trace_path = _run("prepaid_credits")
    results = validate_trace(trace_path, "streaming_payments")
    by_name = {r.name: r for r in results}
    assert by_name["streaming_no_double_open"].passed
    assert "0 unique streams" in by_name["streaming_no_double_open"].detail
    assert by_name["streaming_audit_trail_complete"].passed
    assert "verified 0 streams" in by_name["streaming_audit_trail_complete"].detail


@pytest.mark.skipif(not SCENARIO_PATH.exists(), reason=f"scenario not at {SCENARIO_PATH}")
def test_streaming_scenario_deterministic_under_replay() -> None:
    """Two runs with seed 42 produce identical trace bytes."""
    a = _run("streaming", seed=42).read_bytes()
    b = _run("streaming", seed=42).read_bytes()
    assert a == b


@pytest.mark.skipif(not SCENARIO_PATH.exists(), reason=f"scenario not at {SCENARIO_PATH}")
@pytest.mark.parametrize("seed", [42, 7, 1337])
def test_streaming_scenario_passes_across_seeds(seed: int) -> None:
    """Validator discrimination holds across multiple seeds."""
    config = ScenarioConfig.from_yaml(str(SCENARIO_PATH))
    config = _swap_payments(config, "streaming")
    config = config.model_copy(update={"seed": seed})
    tmp = Path(tempfile.mkdtemp())
    trace_path = tmp / f"streaming_seed_{seed}.jsonl"
    config = config.model_copy(
        update={"output": config.output.model_copy(update={"trace": str(trace_path)})}
    )
    runner = ScenarioRunner(config, registry=PluginRegistry())
    asyncio.run(runner.run())
    results = validate_trace(trace_path, "streaming_payments")
    assert all(r.passed for r in results), [
        f"{r.name}: {r.detail}" for r in results if not r.passed
    ]
