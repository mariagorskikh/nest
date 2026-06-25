# SPDX-License-Identifier: Apache-2.0
"""Trace file inspection and analysis.

Example::

    summary = analyze_trace("traces/marketplace.jsonl")
    print(summary.total_events)
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from nest_core.sim.trace import is_simulation_event


@dataclass
class AgentStats:
    """Per-agent statistics extracted from a trace."""

    sends: int = 0
    receives: int = 0
    started: bool = False
    stopped: bool = False


@dataclass
class TraceSummary:
    """Summary statistics for a JSONL trace file."""

    total_events: int = 0
    duration: float = 0.0
    event_kinds: dict[str, int] = field(default_factory=lambda: dict[str, int]())
    agent_count: int = 0
    message_count: int = 0
    unique_correlations: int = 0
    agents: dict[str, AgentStats] = field(default_factory=lambda: dict[str, AgentStats]())


def analyze_trace(path: str | Path) -> TraceSummary:
    """Analyze a JSONL trace file and return summary statistics.

    Example::

        summary = analyze_trace("trace.jsonl")
    """
    path = Path(path)
    summary = TraceSummary()
    kind_counter: Counter[str] = Counter()
    agents_seen: set[str] = set()
    corr_ids: set[str] = set()
    min_ts = float("inf")
    max_ts = float("-inf")

    with path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            event = json.loads(line)
            summary.total_events += 1

            kind = event.get("kind", "unknown")
            kind_counter[kind] += 1

            if not is_simulation_event(event):
                continue

            ts = event.get("ts", 0.0)
            if ts < min_ts:
                min_ts = ts
            if ts > max_ts:
                max_ts = ts

            agent = event.get("agent", "")
            if agent:
                agents_seen.add(agent)
                if agent not in summary.agents:
                    summary.agents[agent] = AgentStats()

                stats = summary.agents[agent]
                if kind == "send":
                    stats.sends += 1
                elif kind == "receive":
                    stats.receives += 1
                elif kind == "start":
                    stats.started = True
                elif kind == "stop":
                    stats.stopped = True

            corr = event.get("corr")
            if corr is not None:
                corr_ids.add(str(corr))

            if kind in ("send", "receive"):
                summary.message_count += 1

    summary.event_kinds = dict(kind_counter)
    summary.agent_count = len(agents_seen)
    summary.unique_correlations = len(corr_ids)
    if max_ts > min_ts:
        summary.duration = max_ts - min_ts

    return summary


def format_summary(summary: TraceSummary) -> str:
    """Format a TraceSummary as a human-readable report.

    Example::

        print(format_summary(summary))
    """
    lines: list[str] = []
    lines.append("Nanda Town Trace Summary")
    lines.append("=" * 40)
    lines.append(f"  Total events:       {summary.total_events}")
    lines.append(f"  Agents:             {summary.agent_count}")
    lines.append(f"  Messages:           {summary.message_count}")
    lines.append(f"  Correlation IDs:    {summary.unique_correlations}")
    lines.append(f"  Duration:           {summary.duration:.1f} ticks")
    lines.append("")
    lines.append("Event breakdown:")
    for kind, count in sorted(summary.event_kinds.items()):
        lines.append(f"  {kind:20s} {count:>6d}")

    lines.append("")
    lines.append("Top agents by sends:")
    top_senders = sorted(
        summary.agents.items(),
        key=lambda kv: kv[1].sends,
        reverse=True,
    )[:10]
    for agent_name, stats in top_senders:
        lines.append(f"  {agent_name:20s} sent={stats.sends:>4d}  recv={stats.receives:>4d}")

    return "\n".join(lines)
