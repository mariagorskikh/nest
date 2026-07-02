# SPDX-License-Identifier: Apache-2.0
"""Validate a streaming-payments trace and print the verdict.

Replaces the inline ``python -c`` used during development. Runs the
``outcome_verified_settlement`` validators against a JSONL trace, prints PASS/FAIL per
check, optionally prints a per-stream drained/reason summary, and exits non-zero
if any validator failed.

Example::

    uv run python scripts/chainaim/validate_streaming.py TRACE.jsonl --streams
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from nest_core.validators import validate_trace


def _print_streams(trace_path: Path) -> None:
    """Print each stream's final drained total and close reason."""
    for line in trace_path.read_text().splitlines():
        if not line.strip():
            continue
        ev = json.loads(line)
        msg = str(ev.get("msg", ""))
        if ev.get("kind") == "send" and msg.startswith("stream-close:"):
            parts = msg.split(":")
            print(f"  {parts[1]}  drained={parts[3]}  reason={parts[5]}")


def main(argv: list[str] | None = None) -> int:
    """Validate the trace named on the command line; return a process exit code.

    Example::

        raise SystemExit(main(["traces/chainaim_outcome_verified_settlement.jsonl"]))
    """
    parser = argparse.ArgumentParser(description="Validate a streaming-payments trace.")
    parser.add_argument("trace", help="Path to a JSONL trace file.")
    parser.add_argument(
        "--scenario-type",
        default="outcome_verified_settlement",
        help="Validator key to dispatch (default: outcome_verified_settlement).",
    )
    parser.add_argument(
        "--streams",
        action="store_true",
        help="Also print a per-stream drained/reason summary.",
    )
    args = parser.parse_args(argv)

    trace_path = Path(args.trace)
    if not trace_path.exists():
        print(f"Error: trace not found: {trace_path}", file=sys.stderr)
        return 2

    results = validate_trace(trace_path, args.scenario_type)
    for r in results:
        print(f"{'PASS' if r.passed else 'FAIL'} {r.name} - {r.detail}")

    if args.streams:
        print("--- per-stream ---")
        _print_streams(trace_path)

    return 0 if all(r.passed for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
