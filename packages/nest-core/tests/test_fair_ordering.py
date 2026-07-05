# SPDX-License-Identifier: Apache-2.0
"""End-to-end fair-ordering scenario tests.

Boots the ``fair_ordering`` scenario through the real ``Simulator`` under three
coordination plugins and proves the validators discriminate:

* ``fifo_fair``    -> both validators PASS (executes in engine arrival order);
* ``predatory``    -> ``fair_ordering_integrity`` FAILS (reorders = front-run);
* ``contract_net`` -> both FAIL (no fair-ordering API, no ``order:*`` events).

Also pins the load-bearing property: the validator's neutral order is the
engine's ``corr`` order of the ``submit`` broadcasts -- authored by the engine,
not the sequencer -- and it is byte-deterministic under a fixed seed.
"""

from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path

from nest_core.plugins import PluginRegistry
from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_core.validators import validate_trace

SCENARIO_PATH = Path(__file__).resolve().parents[3] / "scenarios" / "fair_ordering.yaml"


def _run(plugin_name: str, seed: int = 42) -> Path:
    """Run the scenario with the chosen coordination plugin; return the trace path."""
    config = ScenarioConfig.from_yaml(str(SCENARIO_PATH))
    new_layers = config.layers.model_copy(update={"coordination": plugin_name})
    config = config.model_copy(update={"layers": new_layers, "seed": seed})
    trace_path = Path(tempfile.mkdtemp()) / f"fair_{plugin_name}_{seed}.jsonl"
    config = config.model_copy(
        update={"output": config.output.model_copy(update={"trace": str(trace_path)})}
    )
    asyncio.run(ScenarioRunner(config, registry=PluginRegistry()).run())
    return trace_path


def _verdicts(plugin_name: str) -> dict[str, bool]:
    results = validate_trace(_run(plugin_name), "fair_ordering")
    return {r.name: r.passed for r in results}


def test_fifo_fair_passes_all() -> None:
    """The survivor passes both integrity and no-injection."""
    v = _verdicts("fifo_fair")
    assert v == {"fair_ordering_integrity": True, "fair_ordering_no_injection": True}


def test_predatory_fails_integrity() -> None:
    """The front-running attacker is caught by the integrity validator."""
    v = _verdicts("predatory")
    assert v["fair_ordering_integrity"] is False
    # it reorders but does not drop/inject, so no-injection still holds
    assert v["fair_ordering_no_injection"] is True


def test_contract_net_fails_all() -> None:
    """The default plugin has no fair-ordering API -> everything fails."""
    v = _verdicts("contract_net")
    assert v["fair_ordering_integrity"] is False
    assert v["fair_ordering_no_injection"] is False


def test_determinism_byte_identical() -> None:
    """Same seed -> byte-identical trace."""
    a = _run("fifo_fair", seed=7).read_bytes()
    b = _run("fifo_fair", seed=7).read_bytes()
    assert a == b


def _submit_order_by_corr(trace: Path) -> list[str]:
    """Reconstruct the neutral arrival order the way the validator does: by ``corr``."""
    submits: list[tuple[int, str]] = []
    for line in trace.read_text().splitlines():
        e = json.loads(line)
        if e.get("kind") == "broadcast" and str(e.get("msg", "")).startswith("order:submit:"):
            corr = int(str(e["corr"]).split("-")[1])
            agent = str(e["msg"]).split("agent=")[1].split(":")[0]
            submits.append((corr, agent))
    return [a for _, a in sorted(submits)]


def _integrity(events: list[dict[str, object]]) -> bool:
    """Run just the integrity validator on hand-crafted in-memory events."""
    from nest_core.validators import validate_events

    results = [
        r for r in validate_events(events, "fair_ordering") if r.name == "fair_ordering_integrity"
    ]
    return results[0].passed


def _ev(msg: str, corr: str) -> dict[str, object]:
    return {"kind": "broadcast", "msg": msg, "corr": corr, "ts": 0.0}


def test_integrity_fails_on_malformed_corr() -> None:
    """A submit with a missing/malformed corr must FAIL, never silently bucket."""
    events = [
        _ev("order:submit:agent=t0:order=buy_1", "corr-1"),
        _ev("order:submit:agent=t1:order=buy_2", "BROKEN"),  # malformed corr
        _ev("order:execute:pos=0:agent=t0", "corr-3"),
        _ev("order:execute:pos=1:agent=t1", "corr-4"),
    ]
    assert _integrity(events) is False


def test_integrity_fails_on_duplicate_pos() -> None:
    """Two executes claiming the same pos are ambiguous -> FAIL (no silent tie)."""
    events = [
        _ev("order:submit:agent=t0:order=buy_1", "corr-1"),
        _ev("order:submit:agent=t1:order=buy_2", "corr-2"),
        _ev("order:execute:pos=0:agent=t1", "corr-3"),  # both claim pos 0
        _ev("order:execute:pos=0:agent=t0", "corr-4"),
    ]
    assert _integrity(events) is False


def test_integrity_fails_on_non_bijection_pos() -> None:
    """Execute pos values must be a clean 0..n-1 permutation; a gap -> FAIL."""
    events = [
        _ev("order:submit:agent=t0:order=buy_1", "corr-1"),
        _ev("order:submit:agent=t1:order=buy_2", "corr-2"),
        _ev("order:execute:pos=0:agent=t0", "corr-3"),
        _ev("order:execute:pos=2:agent=t1", "corr-4"),  # skips pos=1 (not a bijection)
    ]
    assert _integrity(events) is False


def test_integrity_passes_on_wellformed_corr() -> None:
    """The guards do not reject a legitimate, well-formed arrival == execution."""
    events = [
        _ev("order:submit:agent=t0:order=buy_1", "corr-1"),
        _ev("order:submit:agent=t1:order=buy_2", "corr-2"),
        _ev("order:execute:pos=0:agent=t0", "corr-3"),
        _ev("order:execute:pos=1:agent=t1", "corr-4"),
    ]
    assert _integrity(events) is True


def test_neutral_order_is_engine_authored_not_sequencer() -> None:
    """The corr-order of submits is registration order under BOTH plugins.

    Under ``fifo_fair`` and ``predatory`` alike, the traders self-broadcast in
    ``on_start``, so the neutral order the validator keys on (``corr`` of the
    submit events) is the fixed registration order -- the sequencer cannot alter
    it. Only the ``execute`` order differs, which is exactly what the integrity
    validator catches.
    """
    expected = [f"trader-{i}" for i in range(8)]
    assert _submit_order_by_corr(_run("fifo_fair")) == expected
    assert _submit_order_by_corr(_run("predatory")) == expected
