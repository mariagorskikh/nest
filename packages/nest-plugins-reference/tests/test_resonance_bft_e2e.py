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
from nest_core.plugins import PluginRegistry
from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig

_SCENARIOS = Path(__file__).resolve().parents[3] / "scenarios"
_LLM_DEMO = Path(__file__).resolve().parents[1] / "examples" / "llm_consensus" / "demo.py"


def _run(scenario_name: str, trace_path: Path) -> list[dict[str, Any]]:
    scenario = _SCENARIOS / scenario_name
    config = ScenarioConfig.from_yaml(str(scenario))
    config = config.model_copy(
        update={"output": config.output.model_copy(update={"trace": str(trace_path)})}
    )
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


def test_resonance_bft_partition_does_not_commit(tmp_path: Path) -> None:
    """Under a 4/3 partition with quorum_needed=5, the leader's side can gather only 4
    sealed evaluations, so NO commit is broadcast — liveness/safety, observed e2e."""
    events = _run("resonance_bft_consensus_partition.yaml", tmp_path / "rbft_part.jsonl")

    # The round was proposed (R tags present) but never committed (no committed C).
    tags = {str(e.get("msg", "")).split("|")[0] for e in events if "|" in str(e.get("msg", ""))}
    assert "R" in tags, "the leader never even proposed the round"
    assert not _commit_events(events), "a partitioned minority must NOT reach a commit"


def test_resonance_bft_commits_despite_byzantine_tampering(tmp_path: Path) -> None:
    """Byzantine (lying) fault THROUGH the runner: 2 of 10 agents submit TAMPERED records
    (mutated belief without recomputing the seal). resolve() detects the seal mismatch, flags
    them tampered, excludes them, and the honest quorum still commits — the real Byzantine
    fault mode, distinct from a crash (silent) or a partition."""
    events = _run("resonance_bft_consensus_byzantine.yaml", tmp_path / "rbft_byz.jsonl")
    commits = _commit_events(events)
    assert commits, "the round did not commit despite an honest n−f quorum"
    msg = commits[0]["msg"]
    # The 2 Byzantine records are detected and excluded; the honest quorum (n−f = 7) commits.
    assert "tampered=2" in msg, msg
    quorum = msg.split("quorum=")[1].split()[0]  # "7/7"
    size, needed = (int(x) for x in quorum.split("/"))
    assert size >= needed >= 7, msg


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
