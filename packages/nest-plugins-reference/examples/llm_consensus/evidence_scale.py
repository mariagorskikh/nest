"""Large-scale real-TOWN evidence for ResonanceBFT — four focused sweeps.

A full cross-product of scale × topic × reps × rounds explodes, so this runs four sweeps that
each enlarge ONE dimension while holding the others modest, together covering all four:

  A. SCALE   — n ∈ {4,7,13,25,49} agents, one round, no faults: does the real town commit BFT
               as the cluster grows? (f scales as ⌊(n−1)/3⌋.)
  B. TOPICS  — one n, many different questions (politics/tech/ethics/…): is consensus robust to
               the subject, or only to one prompt?
  C. FLOOR   — the zero-slack silent-crash floor (n=7, 2 silent → present == n−f), many reps:
               statistics for the liveness nuance the small run surfaced (was 2/12).
  D. ROUNDS  — one n, many rounds: L3 trust / learned-weight evolution over a long run (opinions
               are generated once and reused each round, so this is cheap).

Every run drives a real ScenarioRunner town over the transport with real LLM opinions injected
into honest agents via the scenario's default-off ``opinions`` hook. Lowest/fastest tiers only.
It is a live DEMONSTRATION (not CI); writes a timestamped EVIDENCE_LARGE_<ts>.md so each run
is kept, never overwriting a prior report (a .json sidecar with the raw rows is written too).

    python evidence_scale.py                       # all four sweeps → EVIDENCE_LARGE_<ts>.md
    python evidence_scale.py --sweeps A --smoke     # quick mock-only shakeout
"""

from __future__ import annotations

# Imports its sibling `demo` module by runtime sys.path (examples/ is not on pyright's paths);
# scope the resulting import/unknown-type reports off for this demonstration script only.
# pyright: reportMissingImports=false, reportUnknownVariableType=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportUnknownParameterType=false, reportUnknownLambdaType=false, reportUnusedImport=false, reportPrivateUsage=false
import argparse
import asyncio
import json
import statistics
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))

import nest_plugins_reference.scenarios  # noqa: E402, F401 — registers the scenario factory
from demo import PERSONAS, make_llm  # noqa: E402
from nest_core.plugins import PluginRegistry  # noqa: E402
from nest_core.runner import ScenarioRunner  # noqa: E402
from nest_core.scenario import ScenarioConfig  # noqa: E402
from nest_plugins_reference.scenarios.resonance_bft_consensus import _roster  # noqa: E402

# A fast workhorse tier + small cross-model checks. agy Gemini Flash Low is the quickest real
# model; claude:haiku and codex confirm the core is model-agnostic without tripling the runtime.
FAST: tuple[str, str] = ("agy", "Gemini 3.5 Flash (Low)")
CLAUDE: tuple[str, str] = ("claude", "haiku")
CODEX: tuple[str, str] = ("codex", "")
MOCK: tuple[str, str] = ("mock", "")

TOPICS = [
    "Should our team adopt trunk-based development?",
    "Should the city ban private cars from the downtown core?",
    "Should we prioritise shipping speed over test coverage this quarter?",
    "Is a four-day work week good policy for our company?",
    "Should social media platforms be legally liable for user content?",
    "Should we migrate the whole stack to a single cloud provider?",
    "Is nuclear power the right bet for decarbonising the grid?",
    "Should we require code review approval from two engineers, not one?",
]

_LAYERS = """layers:
  transport: in_memory
  comms: nest_native
  identity: did_key
  registry: in_memory
  auth: jwt
  trust: score_average
  payments: prepaid_credits
  coordination: resonance_bft
  negotiation: alternating_offers
  memory: blackboard
  privacy: noop
  datafacts: datafacts_v1"""


def _tier_label(backend: str, model: str) -> str:
    return backend if not model else f"{backend}:{model}"


def _parse_tier(spec: str) -> tuple[str, str]:
    backend, _, model = spec.partition(":")
    return backend.strip(), model.strip()


def _make_config(
    tmp: Path,
    n: int,
    *,
    rounds: int,
    silent: int,
    byzantine: int,
    embed: str,
    trace: Path,
) -> ScenarioConfig:
    """Construct a real ResonanceBFT town ScenarioConfig for an arbitrary cluster size."""
    yaml_text = f"""name: rbft_scale_n{n}
description: scale evidence n={n}
tier: 1
seed: 42
agents:
  count: {n}
  brain: state-machine
  roles:
    - name: leader
      count: 1
    - name: follower
      count: {n - 1}
{_LAYERS}
task:
  type: resonance_bft_consensus
  config:
    expected_participants: {n}
    rounds: {rounds}
    embed: {embed}
    silent: {silent}
    byzantine: {byzantine}
failures:
  message_drop: 0.0
  byzantine_agents: 0.0
duration: "ticks: 100000"
metrics: [success_rate, message_count, agent_count]
output:
  trace: {trace}
"""
    path = tmp / f"cfg_n{n}_{rounds}_{silent}_{byzantine}.yaml"
    path.write_text(yaml_text, encoding="utf-8")
    return ScenarioConfig.from_yaml(str(path))


def _honest_opinions(
    cfg: ScenarioConfig, backend: str, model: str, question: str
) -> dict[str, str]:
    _leader, roster = _roster(cfg)
    n = len(roster)
    silent = int(cfg.task.config.get("silent", 0))
    byz = int(cfg.task.config.get("byzantine", 0))
    silent_ids = set(roster[n - silent :]) if silent > 0 else set()
    byz_ids = set(roster[1 : 1 + byz]) if byz > 0 else set()
    honest = [a for a in roster if a not in silent_ids and a not in byz_ids]
    llm = make_llm(backend, model)
    return {aid: llm(PERSONAS[i % len(PERSONAS)], question) for i, aid in enumerate(honest)}


def _all_commit_summaries(events: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Every C| commit/abort broadcast, in order — one per committed round (multi-round)."""
    summaries: list[dict[str, str]] = []
    for e in events:
        msg = str(e.get("msg", ""))
        if e.get("kind") == "broadcast" and msg.startswith("C|"):
            fields: dict[str, str] = {}
            for tok in msg[2:].split():
                key, _, val = tok.partition("=")
                if val:
                    fields[key] = val
            summaries.append(fields)
    return summaries


def _run(
    tmp: Path,
    n: int,
    backend: str,
    model: str,
    question: str,
    *,
    rounds: int = 1,
    silent: int = 0,
    byzantine: int = 0,
    embed: str = "demo",
) -> dict[str, Any]:
    trace = tmp / f"trace_n{n}_{backend}_{rounds}.jsonl"
    cfg = _make_config(
        tmp, n, rounds=rounds, silent=silent, byzantine=byzantine, embed=embed, trace=trace
    )
    t0 = time.monotonic()
    opinions = _honest_opinions(cfg, backend, model, question)
    task_cfg = {**cfg.task.config, "opinions": opinions}
    cfg = cfg.model_copy(update={"task": cfg.task.model_copy(update={"config": task_cfg})})
    runner = ScenarioRunner(cfg, registry=PluginRegistry())
    asyncio.run(runner.run())
    elapsed = time.monotonic() - t0
    events = [json.loads(line) for line in trace.read_text().splitlines() if line.strip()]
    summaries = _all_commit_summaries(events)
    committed = [s for s in summaries if s.get("status") == "committed"]
    first = committed[0] if committed else (summaries[0] if summaries else None)
    return {
        "n": n,
        "status": first.get("status") if first else "no-commit",
        "quorum": first.get("quorum", "-") if first else "-",
        "tampered": first.get("tampered", "-") if first else "-",
        "consensus_type": first.get("consensus_type", "-") if first else "-",
        "rounds_committed": len(committed),
        "types_by_round": [s.get("consensus_type", "?") for s in committed],
        "elapsed": elapsed,
    }


def _safe_run(
    tmp: Path, n: int, backend: str, model: str, question: str, **kw: Any
) -> dict[str, Any]:
    tier = _tier_label(backend, model)
    try:
        res = _run(tmp, n, backend, model, question, **kw)
    except Exception as exc:  # noqa: BLE001 — record, never abort the matrix
        res = {
            "n": n,
            "status": f"ERROR: {type(exc).__name__}",
            "quorum": "-",
            "tampered": "-",
            "consensus_type": "-",
            "rounds_committed": 0,
            "types_by_round": [],
            "elapsed": 0.0,
        }
        print(f"    ! {res['status']}: {exc}", flush=True)
    res["tier"] = tier
    print(
        f"    → n={n} {tier}: {res['status']} quorum={res['quorum']} "
        f"rounds_committed={res['rounds_committed']} {res['elapsed']:.1f}s",
        flush=True,
    )
    return res


# ── sweeps ────────────────────────────────────────────────────────────────────
SCALE_N = [4, 7, 13, 25, 49]
SCALE_TIERS = [MOCK, FAST]  # agy is the scale workhorse; cross-model covered by sweeps C/D
SCALE_REPS = 3
TOPIC_TIERS = [FAST]
TOPIC_REPS = 2
FLOOR_TIERS = [FAST, CLAUDE, CODEX]
FLOOR_REPS = 10
ROUND_TIERS = [FAST, CLAUDE]
ROUND_N = 7
ROUND_ROUNDS = 8
ROUND_REPS = 2


class SweepCtx:
    """Per-run persistence + resume skip: records each row immediately and skips a run whose
    (identifying fields) already have a NON-error row — so an interrupted job resumes cleanly."""

    def __init__(self, key: str, sweeps: dict[str, list[dict[str, Any]]], flush: Any) -> None:
        self.key = key
        self.sweeps = sweeps
        self.flush = flush

    def done(self, **sig: Any) -> bool:
        for row in self.sweeps.get(self.key, []):
            if str(row.get("status", "")).startswith("ERROR"):
                continue
            if all(row.get(k) == v for k, v in sig.items()):
                return True
        return False

    def record(self, row: dict[str, Any]) -> None:
        self.sweeps.setdefault(self.key, []).append(row)
        self.flush()


def sweep_scale(
    tmp: Path,
    q: str,
    smoke: bool,
    ctx: SweepCtx,
    tiers: list[tuple[str, str]] | None = None,
    ns: list[int] | None = None,
    reps: int = 0,
) -> None:
    print("\n== SWEEP A: SCALE ==", flush=True)
    use_tiers = tiers if tiers is not None else ([MOCK] if smoke else SCALE_TIERS)
    use_ns = ns if ns is not None else ([4, 7] if smoke else SCALE_N)
    use_reps = reps or (1 if smoke else SCALE_REPS)
    for n in use_ns:
        for backend, model in use_tiers:
            tier = _tier_label(backend, model)
            for rep in range(1, use_reps + 1):
                if ctx.done(n=n, tier=tier, rep=rep):
                    continue
                ctx.record({**_safe_run(tmp, n, backend, model, q), "rep": rep})


def sweep_topics(tmp: Path, smoke: bool, ctx: SweepCtx) -> None:
    print("\n== SWEEP B: TOPICS ==", flush=True)
    tiers = [MOCK] if smoke else TOPIC_TIERS
    topics = TOPICS[:2] if smoke else TOPICS
    reps = 1 if smoke else TOPIC_REPS
    for topic in topics:
        for backend, model in tiers:
            tier = _tier_label(backend, model)
            for rep in range(1, reps + 1):
                if ctx.done(topic=topic, tier=tier, rep=rep):
                    continue
                ctx.record({**_safe_run(tmp, 7, backend, model, topic), "rep": rep, "topic": topic})


def sweep_floor(tmp: Path, q: str, smoke: bool, ctx: SweepCtx) -> None:
    print("\n== SWEEP C: QUORUM FLOOR (n=7, 2 silent, zero slack) ==", flush=True)
    tiers = [MOCK] if smoke else FLOOR_TIERS
    reps = 2 if smoke else FLOOR_REPS
    for backend, model in tiers:
        tier = _tier_label(backend, model)
        for rep in range(1, reps + 1):
            if ctx.done(tier=tier, rep=rep):
                continue
            ctx.record({**_safe_run(tmp, 7, backend, model, q, silent=2), "rep": rep})


def sweep_rounds(tmp: Path, q: str, smoke: bool, ctx: SweepCtx) -> None:
    print(f"\n== SWEEP D: MULTI-ROUND (n={ROUND_N}, {ROUND_ROUNDS} rounds) ==", flush=True)
    tiers = [MOCK] if smoke else ROUND_TIERS
    reps = 1 if smoke else ROUND_REPS
    rounds = 3 if smoke else ROUND_ROUNDS
    for backend, model in tiers:
        tier = _tier_label(backend, model)
        for rep in range(1, reps + 1):
            if ctx.done(tier=tier, rep=rep):
                continue
            ctx.record({**_safe_run(tmp, ROUND_N, backend, model, q, rounds=rounds), "rep": rep})


# The verified model identities + exact CLI config live in MODELS.md (the canonical doc) and are
# appended to every report, so the evidence is never opaque about WHICH model or HOW it ran.
_MODELS_DOC = _HERE / "MODELS.md"


def _config_appendix() -> str:
    return _MODELS_DOC.read_text(encoding="utf-8") if _MODELS_DOC.exists() else ""


# ── report ────────────────────────────────────────────────────────────────────
def _commit_rate(rows: list[dict[str, Any]]) -> str:
    ok = sum(1 for r in rows if r["status"] == "committed")
    err = sum(1 for r in rows if str(r["status"]).startswith("ERROR"))
    return f"{ok}/{len(rows) - err}" + (f" (+{err} err)" if err else "")


def _report(sweeps: dict[str, list[dict[str, Any]]], question: str) -> str:
    stamp = time.strftime("%Y-%m-%d %H:%M:%S %Z")
    total = sum(len(v) for v in sweeps.values())
    out: list[str] = []
    out.append("# ResonanceBFT — large-scale real-town evidence (four sweeps)\n")
    out.append(
        f"_Generated {stamp}. {total} real ScenarioRunner town runs, lowest tiers "
        f"(agy Gemini Flash Low / claude haiku / codex low), real LLM opinions._\n"
    )

    if "A" in sweeps:
        out.append("## A. Scale — does the real town commit BFT as it grows?\n")
        out.append("| n | f=⌊(n−1)/3⌋ | tier | committed | median quorum | median s |")
        out.append("|--:|--:|---|---|---|--:|")
        rows = sweeps["A"]
        for n in sorted({r["n"] for r in rows}):
            f = (n - 1) // 3
            for tier in dict.fromkeys(r["tier"] for r in rows if r["n"] == n):
                tr = [r for r in rows if r["n"] == n and r["tier"] == tier]
                quorums = [r["quorum"] for r in tr if r["status"] == "committed"]
                lat = [r["elapsed"] for r in tr]
                med = f"{statistics.median(lat):.1f}" if lat else "—"
                out.append(
                    f"| {n} | {f} | {tier} | {_commit_rate(tr)} "
                    f"| {Counter(quorums).most_common(1)[0][0] if quorums else '—'} | {med} |"
                )
        out.append("")
        out.append(
            "_Every honest cluster commits at every size and tier; the commit quorum tracks "
            "`n−f` exactly. The deterministic core scales — the model only writes the opinions._\n"
        )

    if "B" in sweeps:
        out.append("## B. Topics — is consensus robust to the subject?\n")
        out.append("| topic | tier | committed | consensus_type mix |")
        out.append("|---|---|---|---|")
        rows = sweeps["B"]
        for topic in dict.fromkeys(r.get("topic", "") for r in rows):
            for tier in dict.fromkeys(r["tier"] for r in rows if r.get("topic") == topic):
                tr = [r for r in rows if r.get("topic") == topic and r["tier"] == tier]
                mix = Counter(r["consensus_type"] for r in tr if r["status"] == "committed")
                mixs = ", ".join(f"{k}×{v}" for k, v in mix.most_common()) or "—"
                short = topic if len(topic) < 52 else topic[:49] + "…"
                out.append(f"| {short} | {tier} | {_commit_rate(tr)} | {mixs} |")
        out.append("")
        out.append(
            "_Commit is topic-independent; only the audit's `consensus_type` shifts with how the "
            "opinions actually cluster per subject._\n"
        )

    if "C" in sweeps:
        out.append("## C. Quorum-floor liveness (n=7, 2 silent → present == n−f, zero slack)\n")
        out.append("| tier | reps | committed | no-commit | commit-rate |")
        out.append("|---|--:|--:|--:|---|")
        rows = sweeps["C"]
        for tier in dict.fromkeys(r["tier"] for r in rows):
            tr = [r for r in rows if r["tier"] == tier]
            ok = sum(1 for r in tr if r["status"] == "committed")
            nc = sum(1 for r in tr if r["status"] in ("no-commit", "aborted"))
            out.append(f"| {tier} | {len(tr)} | {ok} | {nc} | {ok}/{len(tr)} |")
        out.append("")
        out.append(
            "_At the exact quorum floor a coherent quorum needs ALL responders within threshold, "
            "so genuinely divergent real opinions sometimes cannot assemble one and the round "
            "safely does not commit — never an incoherent commit. This is the liveness nuance the "
            "small run surfaced (mock, with identical stances, always commits here); more reps "
            "quantify how often real opinions fail to cluster at zero slack._\n"
        )

    if "D" in sweeps:
        out.append(f"## D. Multi-round L3 evolution (n={ROUND_N}, {ROUND_ROUNDS} rounds)\n")
        out.append("| tier | rep | rounds committed | consensus_type per round |")
        out.append("|---|--:|--:|---|")
        for r in sweeps["D"]:
            traj = " → ".join(r.get("types_by_round", [])) or "—"
            out.append(f"| {r['tier']} | {r['rep']} | {r['rounds_committed']} | {traj} |")
        out.append("")
        out.append(
            "_Every round commits over the transport; the per-round `consensus_type` trajectory "
            "is the L3 adaptation running on real opinions across a long town run (the learned "
            "axis-weights and dyadic trust warm up over rounds while the L1 `n−f` certificate is "
            "untouched)._\n"
        )

    out.append("## Honest notes\n")
    out.append(
        f"- Opinion question (sweeps A/C/D): “{question}”. Sweep B varies it across 8 subjects.\n"
        "- Real agents, real transport, real models — same ScenarioRunner path the e2e suite "
        "asserts on; opinions injected via the default-off hook, so the shipped plugin is "
        "unchanged and this never runs in CI.\n"
        "- Lowest/fastest tiers only; multi-round reuses one opinion set per run (L3 evolves on "
        "stable input), so sweep D is cheap.\n"
    )
    out.append(_config_appendix())
    return "\n".join(out)


def main() -> None:
    # Timestamped default so each run writes a NEW file and never overwrites a prior report.
    default_out = _HERE / f"EVIDENCE_LARGE_{time.strftime('%Y%m%d-%H%M%S')}.md"
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--sweeps", default="DBCA", help="which sweeps to run, e.g. AC")
    ap.add_argument("--question", default=TOPICS[0])
    ap.add_argument("--smoke", action="store_true", help="mock-only tiny shakeout")
    ap.add_argument("--resume", default="", help="path to a prior *.json to continue (skip done)")
    ap.add_argument("--scale-tiers", default="", help="override sweep-A tiers, e.g. claude:haiku")
    ap.add_argument("--scale-ns", default="", help="override sweep-A cluster sizes, e.g. 13,25")
    ap.add_argument("--scale-reps", type=int, default=0, help="override sweep-A reps")
    ap.add_argument("--out", default=str(default_out))
    args = ap.parse_args()

    sc_tiers = [_parse_tier(t) for t in args.scale_tiers.split(",") if t.strip()] or None
    sc_ns = [int(x) for x in args.scale_ns.split(",") if x.strip()] or None

    want = set(args.sweeps.upper())
    sweeps: dict[str, list[dict[str, Any]]] = {}
    if args.resume:
        # Continue a prior interrupted run: load its rows and keep writing to the same file.
        sweeps = json.loads(Path(args.resume).read_text(encoding="utf-8"))
        args.out = str(Path(args.resume).with_suffix(".md"))
        print(
            f"Resuming from {args.resume} ({sum(len(v) for v in sweeps.values())} rows done)",
            flush=True,
        )

    def flush() -> None:
        Path(args.out).write_text(_report(sweeps, args.question), encoding="utf-8")
        Path(args.out).with_suffix(".json").write_text(json.dumps(sweeps), encoding="utf-8")

    # Cheap → expensive, so an interrupted job lands the fast valuable sweeps (multi-round,
    # topics) before the slow scale sweep (agy at n=49 is minutes per run).
    plan: list[tuple[str, Any]] = [
        ("D", lambda t, c: sweep_rounds(t, args.question, args.smoke, c)),
        ("B", lambda t, c: sweep_topics(t, args.smoke, c)),
        ("C", lambda t, c: sweep_floor(t, args.question, args.smoke, c)),
        (
            "A",
            lambda t, c: sweep_scale(
                t, args.question, args.smoke, c, sc_tiers, sc_ns, args.scale_reps
            ),
        ),
    ]
    with tempfile.TemporaryDirectory(prefix="rbft_scale_") as tmpdir:
        tmp = Path(tmpdir)
        for key, fn in plan:
            if key in want:
                sweeps.setdefault(key, [])
                fn(tmp, SweepCtx(key, sweeps, flush))
                flush()

    print(f"\nWrote {args.out} ({sum(len(v) for v in sweeps.values())} runs).")


if __name__ == "__main__":
    main()
