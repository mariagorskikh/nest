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


def _ev(msg: str, corr: str, agent: str | None = None) -> dict[str, object]:
    """Build a broadcast event with the engine's ``agent`` stamp.

    ``agent`` is what the *engine* recorded as the broadcaster -- distinct from any
    ``agent=`` token inside ``msg``, which is only what the message claims. When
    omitted it defaults to an honest trace: a submit is broadcast by the trader it
    names, an execute by ``sequencer``.
    """
    if agent is None:
        agent = msg.split("agent=")[1].split(":")[0] if ":submit:" in msg else "sequencer"
    return {"kind": "broadcast", "msg": msg, "corr": corr, "ts": 0.0, "agent": agent}


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


def _no_injection(events: list[dict[str, object]]) -> bool:
    """Run just the no-injection validator on hand-crafted in-memory events."""
    from nest_core.validators import validate_events

    results = [
        r
        for r in validate_events(events, "fair_ordering")
        if r.name == "fair_ordering_no_injection"
    ]
    return results[0].passed


# --- Evasion tests: the ``agent=``/``corr=`` tokens in ``msg`` are narration. ---
# Each of these was a clean PASS before identities were bound to the engine's
# broadcaster stamp and the engine's fields were made unforgeable from ``msg``.


def test_integrity_fails_on_forged_corr_token_in_msg() -> None:
    """A ``corr=`` token inside ``msg`` must not override the engine's ``corr``.

    The neutral arrival order is the whole verdict. If a submitter can smuggle its
    own ``corr`` into the message body, it rewrites its own arrival position and a
    front-run reads as honest. t0 really arrived first (corr-1) but claims corr-90;
    t1 really arrived second (corr-2) but claims corr-10 -- and the executes then
    run t1 ahead of t0.
    """
    events = [
        _ev("order:submit:agent=t0:corr=corr-90", "corr-1"),
        _ev("order:submit:agent=t1:corr=corr-10", "corr-2"),
        _ev("order:execute:pos=0:agent=t1", "corr-3"),  # t1 front-runs t0
        _ev("order:execute:pos=1:agent=t0", "corr-4"),
    ]
    assert _integrity(events) is False


def test_spoofed_submit_agent_token_fails_both() -> None:
    """A submit must be broadcast BY the trader it names, or the trace is forged.

    Here the sequencer emits a submit attributed to ``t2`` and then executes it --
    a phantom order laundered into the batch. The multiset of submitted vs executed
    agents balances perfectly, so counting alone cannot see it.
    """
    events = [
        _ev("order:submit:agent=t0:order=buy_1", "corr-1"),
        _ev("order:submit:agent=t1:order=buy_2", "corr-2"),
        _ev("order:submit:agent=t2:order=PHANTOM", "corr-3", agent="sequencer"),
        _ev("order:execute:pos=0:agent=t0", "corr-4"),
        _ev("order:execute:pos=1:agent=t1", "corr-5"),
        _ev("order:execute:pos=2:agent=t2", "corr-6"),
    ]
    assert _integrity(events) is False
    assert _no_injection(events) is False


def test_relabeled_narration_frontrun_fails() -> None:
    """A non-sequencer cannot author the execution order.

    ``t0`` narrates the executes itself, ordering itself first. The ``agent=``
    tokens are internally consistent and the counts balance; only the engine's
    broadcaster stamp reveals that a submitter wrote the execution record.
    """
    events = [
        _ev("order:submit:agent=t0:order=buy_1", "corr-1"),
        _ev("order:submit:agent=t1:order=buy_2", "corr-2"),
        _ev("order:execute:pos=0:agent=t0", "corr-3", agent="t0"),
        _ev("order:execute:pos=1:agent=t1", "corr-4", agent="t0"),
    ]
    assert _integrity(events) is False
    assert _no_injection(events) is False


def test_executes_from_multiple_broadcasters_fail() -> None:
    """Executes split across two broadcasters mean there is no single sequencer."""
    events = [
        _ev("order:submit:agent=t0:order=buy_1", "corr-1"),
        _ev("order:submit:agent=t1:order=buy_2", "corr-2"),
        _ev("order:execute:pos=0:agent=t0", "corr-3", agent="sequencer"),
        _ev("order:execute:pos=1:agent=t1", "corr-4", agent="sequencer-2"),
    ]
    assert _integrity(events) is False


def test_no_injection_counts_multisets_not_sets() -> None:
    """A count-preserving drop-one/duplicate-one pair must FAIL and name both agents.

    ``t1`` is censored and ``t0`` is executed twice. The *sets* of submitted and
    executed agents are unequal here only because t1 vanishes; the point of the
    Counter is that the reported diff names t1 as dropped and t0 as injected rather
    than printing an empty diff.
    """
    from nest_core.validators import validate_events

    events = [
        _ev("order:submit:agent=t0:order=buy_1", "corr-1"),
        _ev("order:submit:agent=t1:order=buy_2", "corr-2"),
        _ev("order:execute:pos=0:agent=t0", "corr-3"),
        _ev("order:execute:pos=1:agent=t0", "corr-4"),  # t1 censored, t0 duplicated
    ]
    results = validate_events(events, "fair_ordering")
    result = next(r for r in results if r.name == "fair_ordering_no_injection")
    assert result.passed is False
    assert "dropped=['t1']" in result.detail
    assert "injected=['t0']" in result.detail


def test_duplicate_submit_from_one_trader_fails() -> None:
    """One trader, one order per batch -- a second submit is ambiguous, not free."""
    events = [
        _ev("order:submit:agent=t0:order=buy_1", "corr-1"),
        _ev("order:submit:agent=t0:order=buy_2", "corr-2"),
        _ev("order:execute:pos=0:agent=t0", "corr-3"),
        _ev("order:execute:pos=1:agent=t0", "corr-4"),
    ]
    assert _integrity(events) is False


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
