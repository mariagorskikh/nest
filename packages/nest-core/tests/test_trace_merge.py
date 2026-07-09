# SPDX-License-Identifier: Apache-2.0
"""Tests for distributed trace merge."""

from __future__ import annotations
import json
from pathlib import Path
from nest_core.sim.trace_merge import merge_traces


def test_merge_skips_corrupt_lines(tmp_path: Path) -> None:
    a = tmp_path / "a.jsonl"
    b = tmp_path / "b.jsonl"
    out = tmp_path / "merged.jsonl"
    a.write_text('{"ts": 1.0, "agent": "a1", "kind": "send"}\n', encoding="utf-8")
    good = '{"ts": 2.0, "agent": "a2", "kind": "receive"}\n'
    b.write_text("{not json\n" + good, encoding="utf-8")
    merge_traces([a, b], out)
    lines = out.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    events = [json.loads(line) for line in lines]
    kinds = {ev["kind"] for ev in events}
    assert kinds == {"send", "receive"}
