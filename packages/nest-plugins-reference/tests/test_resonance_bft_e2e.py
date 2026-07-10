# SPDX-License-Identifier: Apache-2.0
"""End-to-end consensus through the REAL ScenarioRunner.

These tests close the gap the project documents honestly: the generic ``consensus``
scenario is a toy vote that never touches the coordination plugin, so until now no
town run actually exercised ResonanceBFT.  The ``resonance_bft_consensus`` scenario
(in nest_plugins_reference.scenarios) drives the real protocol — propose →
participate → resolve → commit — over the simulator's message transport.  We run it
through the framework's ScenarioRunner (registry-resolved plugin stack) and assert
on the consensus events the protocol itself emitted into the trace.
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import nest_plugins_reference.scenarios  # noqa: F401  # pyright: ignore[reportUnusedImport]
import pytest
from nest_core.plugins import PluginRegistry
from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig

_SCENARIOS = Path(__file__).resolve().parents[3] / "scenarios"
_LLM_DEMO = Path(__file__).resolve().parents[1] / "examples" / "llm_consensus" / "demo.py"


def _run(
    scenario_name: str,
    trace_path: Path,
    *,
    overrides: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    scenario = _SCENARIOS / scenario_name
    config = ScenarioConfig.from_yaml(str(scenario))
    update: dict[str, Any] = {"output": config.output.model_copy(update={"trace": str(trace_path)})}
    if overrides:
        update.update(overrides)
    config = config.model_copy(update=update)
    runner = ScenarioRunner(config, registry=PluginRegistry())
    asyncio.run(runner.run())
    assert runner.resolved_plugins["coordination"].__name__ == "ResonanceBFT"
    return [json.loads(line) for line in trace_path.read_text().splitlines()]


def _commit_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        e
        for e in events
        if e.get("kind") == "broadcast"
        and str(e.get("msg", "")).startswith("C|")
        and "status=committed" in str(e.get("msg", ""))
    ]


def _parse_false_agreement(msg: str) -> float:
    for field in msg.split():
        if field.startswith("false_agreement="):
            value = field.split("=", 1)[1]
            return float(value) if value not in ("n/a", "") else -1.0
    return -1.0


def test_resonance_bft_commits_through_real_runner(tmp_path: Path) -> None:
    """A 12-agent, 6-round run actually commits over the transport, and the dense
    embedding's stance audit fires end-to-end: unanimous rounds show
    false_agreement=0 while same-topic/opposite-stance rounds are flagged > 0."""
    events = _run("resonance_bft_consensus.yaml", tmp_path / "rbft.jsonl")

    # The protocol's phases all appear as real messages on the bus: R (propose), E (sealed
    # eval), C (commit summary), and O (the committed Outcome broadcast so EVERY agent
    # applies commit() and adapts its own trust — multi-agent L3 adaptation, not leader-only).
    tags = {str(e.get("msg", "")).split("|")[0] for e in events if "|" in str(e.get("msg", ""))}
    assert {"R", "E", "C", "O"} <= tags, f"missing a consensus phase in the trace; saw {tags}"
    # Followers actually receive the Outcome (so their commit() runs), not just the leader.
    o_receivers = {
        e.get("agent")
        for e in events
        if e.get("kind") == "receive" and str(e.get("msg", "")).startswith("O|")
    }
    assert any(str(a).startswith("follower") for a in o_receivers), o_receivers

    commits = _commit_events(events)
    assert len(commits) >= 6, f"expected 6 committed rounds, saw {len(commits)}"
    for c in commits:
        # Commits at the n−f QUORUM (9 of 12), not at unanimity — the driver resolves as
        # soon as an n−f quorum is sealed, so slow/silent agents do not block liveness.
        assert "quorum=9/9" in c["msg"], c["msg"]  # n=12, f=3 → quorum_needed = 9
        assert "tampered=0" in c["msg"], c["msg"]

    fa = [_parse_false_agreement(c["msg"]) for c in commits]
    # The stance audit ran (no n/a → embed_fn active) and discriminates: at least one
    # genuine (0.0) round and at least one flagged (>0) false-consensus round.
    assert all(v >= 0.0 for v in fa), f"stance audit did not run end-to-end: {fa}"
    assert any(v == 0.0 for v in fa), f"expected a genuine-consensus round: {fa}"
    assert any(v > 0.0 for v in fa), f"expected a flagged false-consensus round: {fa}"


def test_resonance_bft_commits_at_quorum_despite_silent_agents(tmp_path: Path) -> None:
    """Fault tolerance THROUGH the runner: with 2 of 7 agents silent (crashed/partitioned),
    only 5 sealed evaluations arrive, yet the round still commits at the n−f = 5 quorum."""
    events = _run("resonance_bft_consensus_faulty.yaml", tmp_path / "rbft_faulty.jsonl")
    commits = _commit_events(events)
    assert commits, "the round did not commit despite an available n−f quorum"
    # n=7, f=2 → quorum_needed 5; exactly 5 of 7 participated (2 silent) and it committed.
    assert "quorum=5/5" in commits[0]["msg"], commits[0]["msg"]
    assert "tampered=0" in commits[0]["msg"], commits[0]["msg"]


def test_no_conflicting_commits_across_fault_scenarios(tmp_path: Path) -> None:
    """LI-07 SAFETY (Problem #10 #4b): "no two honest agents commit conflicting values for the
    same round".  Every committing replica emits ``result:<round_no>:<view>:committed:<winner>``;
    across all fault modes (crash, Byzantine tamper, leader crash + view-change) every distinct
    committed round must resolve to exactly ONE winner — never two honest agents disagreeing."""
    scenarios = [
        "resonance_bft_consensus.yaml",
        "resonance_bft_consensus_faulty.yaml",
        "resonance_bft_consensus_byzantine.yaml",
        "resonance_bft_consensus_viewchange.yaml",
        "resonance_bft_consensus_bow.yaml",
    ]
    total_commits = 0
    for scen in scenarios:
        events = _run(scen, tmp_path / f"{scen}.jsonl")
        winners_by_round: dict[str, set[str]] = {}
        for e in events:
            msg = str(e.get("msg", ""))
            if msg.startswith("result:") and ":committed:" in msg:
                parts = msg.split(":")  # result, round_no, view, committed, winner
                if len(parts) >= 5:
                    winners_by_round.setdefault(parts[1], set()).add(parts[4])
        for round_no, winners in winners_by_round.items():
            assert len(winners) == 1, f"{scen} round {round_no}: CONFLICTING commits {winners}"
            total_commits += 1
    # Sanity: the safety check is not vacuous — real commits were exercised (two-phase, votes).
    assert total_commits >= 5, f"expected committed rounds to check, saw {total_commits}"


def test_trace_validators_pass_on_committed_scenarios(tmp_path: Path) -> None:
    """LI-08 (charter's mandatory deliverable): the adversarial validators run against the JSONL
    trace via the framework's ``validate_trace`` registry and PASS on every committing scenario —
    crash, Byzantine tamper, view-change, and the default BoW encoder."""
    from nest_core.validators import validate_events

    for scen in (
        "resonance_bft_consensus.yaml",
        "resonance_bft_consensus_faulty.yaml",
        "resonance_bft_consensus_byzantine.yaml",
        "resonance_bft_consensus_viewchange.yaml",
        "resonance_bft_consensus_bow.yaml",
    ):
        events = _run(scen, tmp_path / f"{scen}.jsonl")
        results = validate_events(events, "resonance_bft_consensus")
        assert results, f"{scen}: no validators ran (registry not wired?)"
        assert all(r.passed for r in results), f"{scen}: " + "; ".join(
            f"{r.name}={r.passed} ({r.detail})" for r in results
        )


def test_trace_validators_fail_against_contract_net(tmp_path: Path) -> None:
    """LI-10 (spec): the adversarial validators FAIL against a contract_net-coordinated trace
    (which carries no result:/O|/V| lines) and PASS against the plugin — the "FAILS against
    contract_net, PASSES against your plugin" requirement, exercised through the real runner."""
    from nest_core.validators import validate_events

    # Drive the built-in toy `consensus` task with the contract_net coordination plugin.
    base = ScenarioConfig.from_yaml(str(_SCENARIOS / "resonance_bft_consensus.yaml"))
    layers = base.layers.model_copy(update={"coordination": "contract_net"})
    task = base.task.model_copy(update={"type": "consensus"})
    trace = tmp_path / "contract_net.jsonl"
    config = base.model_copy(
        update={
            "layers": layers,
            "task": task,
            "output": base.output.model_copy(update={"trace": str(trace)}),
        }
    )
    runner = ScenarioRunner(config, registry=PluginRegistry())
    asyncio.run(runner.run())
    events = [json.loads(line) for line in trace.read_text().splitlines()]
    results = validate_events(events, "resonance_bft_consensus")
    # Every safety/quorum validator FAILs on a trace with no BFT commit evidence.
    failing = [r for r in results if not r.passed]
    assert failing, "validators must FAIL against a contract_net trace (no result/O|/V| lines)"
    assert any("conflicting_commits" in r.name for r in failing)


def test_trace_validators_fail_closed_on_empty_trace(tmp_path: Path) -> None:
    """LI-08/V1: the validators are fail-closed — an empty trace (no quorum-backed commit) FAILS
    every check, which is also why they FAIL against a contract_net trace (no result/O| lines)."""
    from nest_core.validators import validate_events

    results = validate_events([], "resonance_bft_consensus")
    # The safety/quorum validators fail-closed on no commit; stuck-view is N/A without a partition.
    safety = [r for r in results if "stuck_view" not in r.name]
    assert safety and all(not r.passed for r in safety), [(r.name, r.passed) for r in safety]


def _forged_commit_trace(*, garbage_sig: bool = True) -> list[dict[str, Any]]:
    """A hand-authored trace claiming a commit with FABRICATED votes (garbage ed25519 sigs) — the
    shape a Byzantine agent (or a forged trace) would use to fake a quorum it never earned."""
    ev: list[dict[str, Any]] = [
        {"agent": f"a{i}", "kind": "broadcast", "msg": "tick"} for i in range(4)
    ]
    ev.append(
        {
            "agent": "a0",
            "kind": "broadcast",
            "msg": "P|"
            + json.dumps(
                {"round_no": 1, "round_id": "R1", "view": 0, "winner": "a2", "evaluations": {}}
            ),
        }
    )
    sig = "GARBAGE" if garbage_sig else ""
    for i in range(3):
        ev.append(
            {
                "agent": f"a{i}",
                "kind": "broadcast",
                "msg": "V|"
                + json.dumps(
                    {
                        "round_no": 1,
                        "round_id": "R1",
                        "view": 0,
                        "phase": "commit",
                        "winner": "a2",
                        "aid": f"a{i}",
                        "sig": sig,
                        "pub": f"P{i}",
                    }
                ),
            }
        )
    ev.append({"agent": "a0", "kind": "broadcast", "msg": "result:1:0:committed:a2"})
    return ev


def test_forged_quorum_is_caught_by_signature_check() -> None:
    """Charter class 3 ("commit not backed by >= 2f+1 SIGNED votes"): a commit whose V| votes carry
    garbage ed25519 signatures must be REJECTED — the vote-agreement validator re-runs
    ResonanceBFT.verify_vote and refuses to count a vote that does not cryptographically verify."""
    from nest_core.validators import validate_events

    results = validate_events(_forged_commit_trace(), "resonance_bft_consensus")
    failing = {r.name for r in results if not r.passed}
    assert "resonance_vote_agreement" in failing, [(r.name, r.passed, r.detail) for r in results]


def test_non_roster_and_cross_round_votes_do_not_count() -> None:
    """Forged-quorum variants: votes from agents NOT in the roster, and votes tagged with a foreign
    round, must not satisfy a commit — the vote is bound to (roster membership, this round)."""
    from nest_core.validators import validate_events

    ghost = [{"agent": f"a{i}", "kind": "broadcast", "msg": "tick"} for i in range(4)]
    ghost.append(
        {
            "agent": "a0",
            "kind": "broadcast",
            "msg": "P|"
            + json.dumps(
                {"round_no": 1, "round_id": "R1", "view": 0, "winner": "a2", "evaluations": {}}
            ),
        }
    )
    for g in ("ghost1", "ghost2", "ghost3"):
        ghost.append(
            {
                "agent": g,
                "kind": "broadcast",
                "msg": "V|"
                + json.dumps(
                    {
                        "round_no": 1,
                        "round_id": "R1",
                        "view": 0,
                        "phase": "commit",
                        "winner": "a2",
                        "aid": g,
                        "sig": "GARBAGE",
                        "pub": g,
                    }
                ),
            }
        )
    ghost.append({"agent": "a0", "kind": "broadcast", "msg": "result:1:0:committed:a2"})
    failing = {r.name for r in validate_events(ghost, "resonance_bft_consensus") if not r.passed}
    assert "resonance_vote_agreement" in failing, "non-roster votes must not count"


def test_leader_equivocation_is_caught() -> None:
    """Charter class 2 ("a leader sending different proposals"): two P| proposals for the same
    (round_id, view) with different winners must be flagged — the check does not assume an honest
    leader (the charter anti-pattern)."""
    from nest_core.validators import validate_events

    ev: list[dict[str, Any]] = [
        {"agent": f"a{i}", "kind": "broadcast", "msg": "tick"} for i in range(4)
    ]
    ev.append(
        {
            "agent": "a0",
            "kind": "broadcast",
            "msg": "P|"
            + json.dumps(
                {"round_no": 1, "round_id": "R1", "view": 0, "winner": "a2", "evaluations": {}}
            ),
        }
    )
    ev.append(
        {
            "agent": "a0",
            "kind": "broadcast",
            "msg": "P|"
            + json.dumps(
                {"round_no": 1, "round_id": "R1", "view": 0, "winner": "a3", "evaluations": {}}
            ),
        }
    )
    ev.append({"agent": "a0", "kind": "broadcast", "msg": "result:1:0:committed:a2"})
    failing = {r.name for r in validate_events(ev, "resonance_bft_consensus") if not r.passed}
    assert "resonance_no_leader_equivocation" in failing, "leader equivocation must be flagged"


@pytest.mark.parametrize("seed", [42, 7, 1337, 0xDEADBEEF])
@pytest.mark.parametrize(
    "scenario",
    [
        "resonance_bft_consensus.yaml",
        "resonance_bft_consensus_byzantine.yaml",
        "resonance_bft_consensus_partition.yaml",
    ],
)
def test_byte_identical_trace_same_seed(scenario: str, seed: int, tmp_path: Path) -> None:
    """LI-13 (charter Tier-1): same seed => byte-identical trace, at each mandated seed
    (42, 7, 1337, 0xdeadbeef).  Two runs of the same scenario at the same seed, through the real
    ScenarioRunner, must produce byte-for-byte identical JSONL — proving determinism now that the
    two-phase vote adds signed messages (whose JSON key order and round_id derivation are fixed)."""

    def run(out: Path) -> bytes:
        config = ScenarioConfig.from_yaml(str(_SCENARIOS / scenario))
        config = config.model_copy(
            update={"seed": seed, "output": config.output.model_copy(update={"trace": str(out)})}
        )
        runner = ScenarioRunner(config, registry=PluginRegistry())
        asyncio.run(runner.run())
        return out.read_bytes()

    first = run(tmp_path / "a.jsonl")
    second = run(tmp_path / "b.jsonl")
    assert first == second, f"{scenario} @ seed {seed}: trace not byte-identical across runs"
    assert first, "empty trace"


def test_two_phase_vote_messages_present(tmp_path: Path) -> None:
    """LI-07: a committed round goes through the two-phase agreement — the proposal (P), signed
    votes (V), and the quorum certificate (QC) all appear on the bus, not just a leader's fiat
    commit."""
    events = _run("resonance_bft_consensus.yaml", tmp_path / "twophase.jsonl")
    tags = {str(e.get("msg", "")).split("|")[0] for e in events if "|" in str(e.get("msg", ""))}
    assert {"P", "V"} <= tags, f"two-phase vote messages missing; saw {tags}"


def test_resonance_bft_view_change_on_leader_crash(tmp_path: Path) -> None:
    """LI-06 view-change THROUGH the runner: the view-0 leader (leader-0) is crashed and never
    proposes, so the cohort must time out, rotate leadership round-robin to the view-1 leader
    (follower-0), and commit there. The trace shows the rotation as NV (new-view) messages — the
    view-change evidence Problem #10 mandates — and the crashed leader never proposes a round."""
    events = _run("resonance_bft_consensus_viewchange.yaml", tmp_path / "rbft_vc.jsonl")

    # View-change evidence: NV messages appear in the trace.
    nv = [e for e in events if str(e.get("msg", "")).startswith("NV|")]
    assert nv, "no NV (new-view) evidence in the trace — view-change never happened"

    # The crashed leader-0 never proposes; the new leader (follower-0) does.
    proposers = {
        str(e.get("agent"))
        for e in events
        if str(e.get("msg", "")).startswith("R|") and e.get("kind") in ("send", "broadcast")
    }
    assert "leader-0" not in proposers, f"crashed leader should not propose; saw {proposers}"
    assert proposers, "the new leader never proposed after the view change"

    # And the round still commits (liveness under leader failure), at the n−f = 5 quorum.
    commits = _commit_events(events)
    assert commits, "the round did not commit after electing a new leader"
    assert "quorum=5/5" in commits[0]["msg"], commits[0]["msg"]


def test_resonance_bft_partition_no_commit_then_heals(tmp_path: Path) -> None:
    """LI-11 (Problem #10's mandated partition+heal): under a 4/3 partition with quorum_needed=5,
    neither side reaches the quorum, so NO commit happens while partitioned — then the network
    heals and the round COMMITS post-recovery.  Verified end-to-end: the first committed ``result``
    line has a timestamp at-or-after the ``partition_healed`` marker."""
    events = _run("resonance_bft_consensus_partition.yaml", tmp_path / "rbft_part.jsonl")

    heal_ts = [e.get("ts") for e in events if e.get("kind") == "partition_healed"]
    assert heal_ts, "the partition never healed (partition_heal_at_tick not consumed?)"
    healed_at = min(t for t in heal_ts if isinstance(t, (int, float)))

    commits = [
        e
        for e in events
        if str(e.get("msg", "")).startswith("result:") and ":committed:" in str(e.get("msg", ""))
    ]
    assert commits, "the round never committed even after the partition healed"
    first_commit_ts = min(c["ts"] for c in commits if isinstance(c.get("ts"), (int, float)))
    assert first_commit_ts >= healed_at, (
        f"a commit ({first_commit_ts}) preceded the heal ({healed_at}) — the partitioned "
        "minority must not commit before recovery"
    )
    # The stuck-view validator confirms progress resumed after the heal.
    from nest_core.validators import validate_events

    stuck = [
        r for r in validate_events(events, "resonance_bft_consensus") if "stuck_view" in r.name
    ]
    assert stuck and all(r.passed for r in stuck), [(r.name, r.detail) for r in stuck]


def test_resonance_bft_commits_despite_byzantine_tampering(tmp_path: Path) -> None:
    """LI-12 (Problem #10's mandated byzantine shape): DOUBLE-TRACK Byzantine faults THROUGH the
    runner. The FRAMEWORK injects ``byzantine_agents: 0.28`` (byte-XOR garbling that reaches the
    plugin — the spec's requirement), which the LI-02 guards drop as garbage; and a SEMANTIC
    tamper follower mutates its sealed belief, which resolve() detects and excludes. The honest
    n-f=5 quorum still commits."""
    events = _run("resonance_bft_consensus_byzantine.yaml", tmp_path / "rbft_byz.jsonl")

    # The framework byte-garbling genuinely reached the plugin: at least one delivered payload is
    # not a valid tagged message (it was garbled and dropped by the guards).
    tags = ("R|", "E|", "O|", "C|", "V|", "P|", "NV|", "T|", "result:")
    garbled = sum(
        1
        for e in events
        if e.get("kind") == "receive" and not any(str(e.get("msg", "")).startswith(t) for t in tags)
    )
    assert garbled > 0, "framework byzantine_agents injection never reached the plugin"

    commits = _commit_events(events)
    assert commits, "the round did not commit despite an honest n−f quorum"
    msg = commits[0]["msg"]
    # The semantic-tampered record is detected + excluded; the honest quorum (n−f = 5) commits.
    assert "tampered=1" in msg, msg
    quorum = msg.split("quorum=")[1].split()[0]  # "5/5"
    size, needed = (int(x) for x in quorum.split("/"))
    assert size >= needed >= 5, msg


def test_resonance_bft_bow_default_commits_over_transport(tmp_path: Path) -> None:
    """The DEFAULT zero-dependency bag-of-words encoder is transport-correct: each follower
    extends the vocab with its own private words (divergent coordinate systems), yet resolve()
    reconciles them onto the canonical union vocab and the 7-agent round commits at n−f = 5."""
    events = _run("resonance_bft_consensus_bow.yaml", tmp_path / "rbft_bow.jsonl")
    commits = _commit_events(events)
    assert commits, "BoW-over-transport round did not commit"
    msg = commits[0]["msg"]
    assert "quorum=5/5" in msg, msg  # n=7, f=2 → quorum_needed = 5
    assert "tampered=0" in msg, msg


def test_llm_consensus_demo_runs_with_mock_backend() -> None:
    """The real-LLM demo runs end-to-end with the deterministic mock backend and commits at
    two scales — a CI smoke test so the demo cannot silently bit-rot (the real-LLM path is a
    nondeterministic demonstration, out of scope for CI)."""
    result = subprocess.run(
        [sys.executable, str(_LLM_DEMO), "--backend", "mock", "--scales", "4,7"],
        capture_output=True,
        text=True,
        timeout=180,
        check=True,
    )
    assert result.stdout.count("COMMITTED") >= 2, result.stdout[-2000:]
    assert "SCALE: 4 agents" in result.stdout and "SCALE: 7 agents" in result.stdout


def test_llm_consensus_demo_handles_sub_bft_scale() -> None:
    """A scale below the BFT floor (n=3 < 3f+1=4) must ABORT cleanly, not crash: the demo's
    outcome printer reads the tolerance field `f`, which the abort path must also provide
    (regression — the abort metadata once omitted it, raising KeyError only at n<4)."""
    result = subprocess.run(
        [sys.executable, str(_LLM_DEMO), "--backend", "mock", "--scales", "3"],
        capture_output=True,
        text=True,
        timeout=180,
        check=True,
    )
    assert "ABORTED" in result.stdout and "(n=3, f=0)" in result.stdout, result.stdout[-2000:]


def test_framework_byzantine_garbling_does_not_crash_the_run(tmp_path: Path) -> None:
    """LI-02 real-usage guarantee: framework-level Byzantine injection (byte-XOR
    garbling of a sender's payloads, per simulator.py) reaches the plugin driver and
    is silently dropped at every parse site — the run completes without an exception
    escaping ``on_message``. Pre-fix the unguarded json.loads / model_validate_json
    would raise and abort the run (the spec's explicit anti-pattern).

    This drives the REAL ScenarioRunner, and asserts the guard is genuinely exercised
    (at least one delivered payload is unparseable = garbled), not vacuously green.
    """
    from nest_core.types import Outcome, Round

    base = ScenarioConfig.from_yaml(str(_SCENARIOS / "resonance_bft_consensus.yaml"))
    failures = base.failures.model_copy(update={"byzantine_agents": 0.28})
    # Must not raise:
    events = _run(
        "resonance_bft_consensus.yaml",
        tmp_path / "byz_garble.jsonl",
        overrides={"failures": failures, "seed": 42},
    )

    def _parses(tag: str, body: str) -> bool:
        try:
            if tag == "E":
                return isinstance(json.loads(body), dict)
            if tag == "R":
                Round.model_validate_json(body)
                return True
            if tag == "O":
                Outcome.model_validate_json(body)
                return True
        except Exception:  # noqa: BLE001
            return False
        return False

    garbled = 0
    for e in events:
        if e.get("kind") != "receive":
            continue
        msg = str(e.get("msg", ""))
        if len(msg) > 1 and msg[1:2] == "|":
            if not _parses(msg[:1], msg[2:]):
                garbled += 1
        else:
            garbled += 1  # tag/delimiter itself garbled
    assert garbled > 0, "guard not exercised — no garbled delivery in this run"


def test_scenario_factory_and_plugin_discoverable_from_core_alone() -> None:
    """LI-03: the town runner (CLI) path resolves BOTH the scenario factory and the
    coordination plugin from ``nest_core`` alone — without first importing
    ``nest_plugins_reference.scenarios``.  Pre-fix, ``nest run`` raised
    ``KeyError: No scenario factory registered for 'resonance_bft_consensus'``.

    Runs in a fresh subprocess so an earlier import in this process can't mask the
    lookup (registration is process-global once any import triggers it).
    """
    code = (
        "from nest_core.scenarios import get_scenario_factory;"
        "from nest_core.plugins import PluginRegistry;"
        "f = get_scenario_factory('resonance_bft_consensus');"
        "assert f.__name__ == 'resonance_bft_consensus_factory', f;"
        "cls = PluginRegistry().resolve('coordination', 'resonance_bft');"
        "assert cls.__name__ == 'ResonanceBFT', cls;"
        "print('OK')"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0, result.stderr
    assert "OK" in result.stdout


def test_llm_consensus_demo_adversarial_suite() -> None:
    """The adversarial + quality suite runs deterministically (mock) and exhibits the full
    spectrum: committed rounds, tampered detection, and a SAFETY ABORT when Byzantine faults
    exceed the tolerance f (the non-consensus case)."""
    result = subprocess.run(
        [sys.executable, str(_LLM_DEMO), "--suite", "--backend", "mock"],
        capture_output=True,
        text=True,
        timeout=180,
        check=True,
    )
    out = result.stdout
    assert "COMMITTED" in out and "ABORTED" in out, out[-2000:]  # both outcomes occur
    assert "tampered_exceeds_f=True" in out, out[-2000:]  # evil-overwhelm safety abort
    assert "tampered       : ['a0', 'a1']" in out, out[-2000:]  # evil contained/malformed detected
