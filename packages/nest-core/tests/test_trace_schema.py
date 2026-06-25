# SPDX-License-Identifier: Apache-2.0
"""Tests for trace schema header and event filtering."""

from __future__ import annotations

import json
from pathlib import Path

from nest_core.sim.trace import (
    TRACE_HEADER_KIND,
    TRACE_SCHEMA_VERSION,
    TraceWriter,
    filter_simulation_events,
    is_simulation_event,
)


class TestTraceSchema:
    def test_header_written_first(self, tmp_path: Path) -> None:
        path = tmp_path / "t.jsonl"
        with TraceWriter(path) as writer:
            writer.record({"ts": 0.0, "agent": "a1", "kind": "start"})

        lines = path.read_text().strip().split("\n")
        assert len(lines) == 2
        header = json.loads(lines[0])
        assert header["kind"] == TRACE_HEADER_KIND
        assert header["schema_version"] == TRACE_SCHEMA_VERSION
        assert header["generator"] == "nest-core"
        assert "generator_version" in header

    def test_filter_simulation_events(self) -> None:
        events = [
            {"kind": "trace_header", "schema_version": "1.0"},
            {"kind": "start", "agent": "a1", "ts": 0.0},
        ]
        filtered = filter_simulation_events(events)
        assert len(filtered) == 1
        assert filtered[0]["kind"] == "start"
        assert is_simulation_event(events[0]) is False
        assert is_simulation_event(events[1]) is True
