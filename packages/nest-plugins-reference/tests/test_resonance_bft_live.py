# SPDX-License-Identifier: Apache-2.0
"""Live real-LLM town consensus — REAL nandatown agents driven by a subscription-CLI model.

These tests are ``live``-marked, so they are EXCLUDED from the default suite
(``addopts = -m "not live"``) and never run in CI: they shell out to a key-free subscription
CLI (claude/codex/agy) that only exists on a developer machine. They therefore do not affect
the hackathon submission — they are opt-in evidence that the town commits with a real model.

Run manually, e.g.::

    uv run pytest packages/nest-plugins-reference/tests/test_resonance_bft_live.py -m live -q
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

_RUNNER = Path(__file__).resolve().parents[1] / "examples" / "llm_consensus" / "evidence_town.py"


@pytest.mark.live
def test_town_commits_with_real_llm(tmp_path: Path) -> None:
    """The genuine + fault scenarios, driven through the REAL ScenarioRunner with a real LLM
    (claude haiku, lowest tier) generating each honest agent's opinion, reach the outcomes the
    scenarios are designed for: commits where expected, no-commit under partition."""
    out = tmp_path / "EVIDENCE.md"
    result = subprocess.run(
        [sys.executable, str(_RUNNER), "--tiers", "claude:haiku", "--reps", "1", "--out", str(out)],
        capture_output=True,
        text=True,
        timeout=900,
        check=True,
    )
    stdout = result.stdout
    # Genuine, silent-crash, byzantine and bag-of-words rounds committed over the transport…
    assert stdout.count("committed") >= 4, stdout[-3000:]
    # …and the partitioned 4/3 split correctly did NOT commit.
    assert "no-commit" in stdout, stdout[-3000:]
    assert out.exists() and "real-town evidence" in out.read_text(encoding="utf-8")
