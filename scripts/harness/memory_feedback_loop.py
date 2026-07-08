# SPDX-License-Identifier: Apache-2.0
"""Local feedback loop for the PN-Counter memory hackathon branch.

The loop runs the memory scenarios across a small seed bank, executes focused
quality gates, and feeds the local branch diff through the same judge
aggregation path used by the hackathon scoreboard with deterministic mock
judges.

Example::

    python -m scripts.harness.memory_feedback_loop
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_core.validators import validate_trace

from scripts.judge.judge_pr import (
    JudgeVerdict,
    PRContext,
    _build_user_prompt,  # pyright: ignore[reportPrivateUsage]
    _system_blocks,  # pyright: ignore[reportPrivateUsage]
    aggregate,
    load_rubric,
    parse_verdict,
)
from scripts.judge.run_all import MockJudgeClient

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BASE = "upstream/main"
MEMORY_SCENARIOS = (
    Path("scenarios/memory_pn_counter_reports.yaml"),
    Path("scenarios/memory_basis_fusion_calculator.yaml"),
)
SEEDS = (42, 7, 1337, 2025)


@dataclass(frozen=True)
class GateResult:
    """One command or scenario gate result.

    Example::

        result = GateResult("pytest", True, "ok")
    """

    name: str
    passed: bool
    detail: str


def _run(cmd: Sequence[str], *, env: dict[str, str] | None = None) -> GateResult:
    proc = subprocess.run(
        list(cmd),
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
        check=False,
    )
    detail = _last_lines(proc.stdout)
    return GateResult(" ".join(cmd), proc.returncode == 0, detail)


def _last_lines(text: str, limit: int = 12) -> str:
    lines = [line.rstrip() for line in text.splitlines() if line.strip()]
    return "\n".join(lines[-limit:]) if lines else ""


def _git(args: Sequence[str]) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def _changed_python_files(base: str) -> list[str]:
    files = {
        *_git(["diff", "--name-only", f"{base}...HEAD"]).splitlines(),
        *_git(["diff", "--name-only"]).splitlines(),
        *_git(["diff", "--cached", "--name-only"]).splitlines(),
        *_git(["ls-files", "--others", "--exclude-standard"]).splitlines(),
    }
    return [name for name in files if name.endswith(".py")]


def run_quality_gates(base: str, *, contrib: bool, full: bool) -> list[GateResult]:
    """Run CI-like checks over the changed Python surface.

    Example::

        gates = run_quality_gates("upstream/main", contrib=False, full=False)
    """
    if contrib:
        uv = _uv_executable()
        if uv is None:
            return [
                GateResult(
                    "uv executable",
                    False,
                    "uv is not available; install with `python -m pip install --user uv`",
                )
            ]
        env = _uv_environment()
        return [
            _run([str(uv), "sync"], env=env),
            _run([str(uv), "run", "ruff", "check", "."], env=env),
            _run([str(uv), "run", "ruff", "format", "--check", "."], env=env),
            _run([str(uv), "run", "pyright"], env=env),
            _run([str(uv), "run", "pytest", "-v"], env=env),
        ]

    changed = _changed_python_files(base)
    py_files = ["."] if full else changed or ["packages", "scripts"]
    pytest_cmd = (
        ["python", "-m", "pytest", "-q"]
        if full
        else [
            "python",
            "-m",
            "pytest",
            "packages/nest-plugins-reference/tests/test_pn_counter.py",
            "packages/nest-core/tests/test_pn_counter_memory_scenario.py",
            "packages/nest-core/tests/test_basis_fusion_memory_scenario.py",
            "-q",
        ]
    )
    gates = [
        run_setup_probe(),
        _run(["python", "-m", "nest_core.cli", "doctor"]),
        _run(["python", "-m", "ruff", "check", *py_files]),
        _run(["python", "-m", "ruff", "format", "--check", *py_files]),
        _run(["python", "-m", "pyright", *(py_files if not full else [])]),
        _run(pytest_cmd),
    ]
    return gates


def _uv_executable() -> Path | None:
    found = shutil.which("uv")
    if found:
        return Path(found)
    appdata = Path.home() / "AppData" / "Roaming" / "Python" / "Python312" / "Scripts" / "uv.exe"
    return appdata if appdata.exists() else None


def _uv_environment() -> dict[str, str]:
    env = dict(os.environ)
    env.setdefault(
        "UV_PROJECT_ENVIRONMENT",
        str(Path.home() / "AppData" / "Local" / "nanda-town-memory-uv-venv"),
    )
    return env


def run_setup_probe() -> GateResult:
    """Report whether the contributing-document tooling is available.

    Example::

        result = run_setup_probe()
    """
    uv_exe = _uv_executable()
    uv_path = str(uv_exe) if uv_exe is not None else None
    make_path = shutil.which("make")
    if uv_path and make_path:
        return GateResult("contrib tools", True, f"uv={uv_path}; make={make_path}")
    missing: list[str] = []
    if uv_path is None:
        missing.append("uv")
    if make_path is None:
        missing.append("make")
    return GateResult(
        "contrib tools",
        True,
        "not installed in this shell: "
        + ", ".join(missing)
        + "; using python -m equivalents plus nest doctor",
    )


async def run_memory_seed_sweep() -> list[GateResult]:
    """Run memory scenarios across the deterministic seed bank.

    Example::

        results = asyncio.run(run_memory_seed_sweep())
    """
    results: list[GateResult] = []
    with tempfile.TemporaryDirectory() as tmp:
        out_dir = Path(tmp)
        for scenario_path in MEMORY_SCENARIOS:
            for seed in SEEDS:
                config = ScenarioConfig.from_yaml(ROOT / scenario_path)
                config.seed = seed
                config.output.trace = str(out_dir / f"{scenario_path.stem}-{seed}.jsonl")
                try:
                    trace_path = await ScenarioRunner(config).run()
                    validations = validate_trace(trace_path, str(config.task.type))
                except Exception as exc:  # noqa: BLE001 - keep loop diagnostic
                    results.append(
                        GateResult(
                            f"{scenario_path.name} seed={seed}",
                            False,
                            f"{type(exc).__name__}: {exc}",
                        )
                    )
                    continue
                failed = [f"{r.name}: {r.detail}" for r in validations if not r.passed]
                if failed:
                    results.append(
                        GateResult(f"{scenario_path.name} seed={seed}", False, "; ".join(failed))
                    )
                else:
                    results.append(
                        GateResult(
                            f"{scenario_path.name} seed={seed}",
                            True,
                            f"{len(validations)} validator(s) passed",
                        )
                    )
    return results


async def run_mock_judge(base: str, checks_summary: str) -> dict[str, Any]:
    """Score the local diff through the judge aggregator with mock judges.

    Example::

        result = asyncio.run(run_mock_judge("upstream/main", "checks passed"))
    """
    head_sha = _git(["rev-parse", "HEAD"])
    head_ref = _git(["branch", "--show-current"])
    diff = _git(["diff", f"{base}...HEAD"])
    ctx = PRContext(
        number=0,
        title="[Hackathon] jmuslu: PN-Counter memory with basis fusion invariants",
        body=_local_pr_body(),
        author="jmuslu",
        head_sha=head_sha,
        head_ref=head_ref,
        diff=diff,
        diff_truncated=False,
        checks_summary=checks_summary,
    )
    rubric = load_rubric()
    system_blocks = _system_blocks(rubric)
    user_prompt = _build_user_prompt(ctx)
    verdicts: list[JudgeVerdict] = []
    for judge_id in range(3):
        client = MockJudgeClient(judge_id=judge_id, head_sha=head_sha)
        raw = await client.judge(system_blocks=system_blocks, user=user_prompt)
        verdicts.append(parse_verdict(raw, judge_id))
    return aggregate(verdicts, ctx, model="mock:local", persona="jmuslu").to_dict()


def _local_pr_body() -> str:
    return """## Piece picked

Layer 10 -- Memory. This branch adds `memory:pn_counter` plus a
basis-restricted calculator fusion scenario.

## Why

LWW-style convergence is not the right mathematical object for signed
evidence aggregation: it can converge while discarding concurrent evidence.
The PN-Counter keeps positive and negative evidence as grow-only coordinates,
with merge as pointwise max, so every accepted delta survives reordering,
duplication, and gossip.

## Applied-math object

The second scenario treats memory as a typed gluing problem. Reports fuse into
the `calculator` node only when they restrict onto a declared basis dimension
(`add`, `subtract`, `multiply`, `divide`). Raw context saturation has no legal
overlap, and off-basis claims are rejected, so the memory layer acts only on
fusable evidence.

## Verification

Run:

```bash
python -m scripts.harness.memory_feedback_loop --contrib
```

The loop runs the CONTRIBUTING.md uv gates, memory scenario seed sweeps, and
the built-in judge aggregation path with deterministic mock judges.
"""


def _print_gate(result: GateResult) -> None:
    status = "PASS" if result.passed else "FAIL"
    print(f"{status} {result.name}")
    if result.detail:
        print(result.detail)


async def _main_async(args: argparse.Namespace) -> int:
    gates = run_quality_gates(
        str(args.base),
        contrib=bool(args.contrib),
        full=bool(args.full or args.contrib),
    )
    sweep = await run_memory_seed_sweep()
    all_results = [*gates, *sweep]
    checks_summary = "; ".join(
        f"{item.name}={'pass' if item.passed else 'fail'}" for item in all_results
    )
    judge = await run_mock_judge(str(args.base), checks_summary)

    for result in all_results:
        _print_gate(result)
    print("MOCK_JUDGE", json.dumps(judge["scores"], sort_keys=True))
    print("MOCK_JUDGE_MEDIAN", judge["median"])
    print("MOCK_JUDGE_CONSENSUS", judge["consensus"])
    return 0 if all(result.passed for result in all_results) else 1


def main(argv: Sequence[str] | None = None) -> int:
    """Run the local feedback loop.

    Example::

        raise SystemExit(main(["--full"]))
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default=DEFAULT_BASE, help="Base ref for the local diff.")
    parser.add_argument(
        "--contrib",
        action="store_true",
        help="Run the uv-based CONTRIBUTING.md definition-of-done gates.",
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="Run full pytest instead of focused tests.",
    )
    args = parser.parse_args(argv)
    return asyncio.run(_main_async(args))


if __name__ == "__main__":
    sys.exit(main())
