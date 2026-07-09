# SPDX-License-Identifier: Apache-2.0
"""Merge per-worker JSONL traces into one canonical trace file.

Example::

    merge_traces([Path("w0.jsonl"), Path("w1.jsonl")], Path("merged.jsonl"))
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from nest_core.log import LazyLogger

log = LazyLogger(__name__)


def _load_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    if not path.exists():
        return events
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError as exc:
            if os.environ.get("NEST_LOG", "").strip():
                try:
                    log.warning(
                        "trace_merge_skip_bad_line",
                        path=str(path),
                        line=line_no,
                        error=str(exc),
                    )
                except TypeError:
                    log.warning(
                        "trace_merge_skip_bad_line path=%s line=%s error=%s",
                        path,
                        line_no,
                        exc,
                    )
            continue
    return events


def merge_traces(paths: list[Path], output: Path) -> Path:
    """Load worker traces, sort by timestamp, and write a canonical JSONL trace.

    Events are ordered by ``ts`` then original file order. Each event receives
    a monotonic ``sequence`` field for stable ordering within equal timestamps.

    Example::

        out = merge_traces([Path("a.jsonl"), Path("b.jsonl")], Path("out.jsonl"))
    """
    combined: list[tuple[float, int, dict[str, Any]]] = []
    for file_idx, path in enumerate(paths):
        for event in _load_events(path):
            ts = float(event.get("ts", 0.0))
            combined.append((ts, file_idx, event))

    combined.sort(key=lambda item: (item[0], item[1]))

    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as fh:
        for seq, (_ts, _file_idx, event) in enumerate(combined):
            merged = dict(event)
            merged["sequence"] = seq
            fh.write(json.dumps(merged, sort_keys=True, separators=(",", ":")) + "\n")
    return output
