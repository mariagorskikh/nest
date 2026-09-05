"""The local leaderboard over verified recorded evidence.

Scans a runs directory for evidence bundles and shows, per profile or
scenario, how many runs exist and how many passed. Rankings derive from
evidence bundles anyone can verify; the board is a view, never a
record.
"""

from __future__ import annotations

import os
from typing import Any

from .bundle import load_bundle, verify_bundle


def scan_bundles(directory: str) -> list[dict[str, Any]]:
    rows = []
    if not os.path.isdir(directory):
        return rows
    for entry in sorted(os.listdir(directory)):
        bundle_dir = os.path.join(directory, entry)
        manifest_path = os.path.join(bundle_dir, "manifest.json")
        if not os.path.lexists(manifest_path):
            continue
        problems = verify_bundle(bundle_dir)
        if problems:
            rows.append({"run_id": entry, "verified": False,
                         "problems": problems, "profile": "unverified",
                         "mode": "unknown", "verdict": "unverified", "at": 0.0})
            continue
        bundle = load_bundle(bundle_dir)
        run, result = bundle["run"], bundle["result"]
        rows.append({
            "run_id": run.run_id,
            "profile": run.profile_name,
            "mode": bundle["mode"],
            "verdict": result.verdict,
            "at": run.created_at,
            "verified": True,
            "problems": [],
        })
    return rows


def render_board(directory: str) -> str:
    rows = scan_bundles(directory)
    if not rows:
        return (f"no evidence bundles under {directory}; run one with:"
                " nandatown run\n")
    groups: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not row["verified"]:
            continue
        g = groups.setdefault(row["profile"],
                              {"mode": row["mode"], "runs": 0,
                               "passed": 0, "last_verdict": "",
                               "last_at": 0.0})
        g["runs"] += 1
        g["passed"] += row["verdict"] == "passed"
        if row["at"] >= g["last_at"]:
            g["last_at"] = row["at"]
            g["last_verdict"] = row["verdict"]
    width = max((len(name) for name in groups), default=0)
    lines = [f"Town board over {directory} ({len(rows)} bundles)",
             "=" * 40]
    ranked = sorted(groups.items(),
                    key=lambda kv: (-kv[1]["passed"] / kv[1]["runs"],
                                    kv[0]))
    for name, g in ranked:
        rate = 100.0 * g["passed"] / g["runs"]
        lines.append(f"{name.ljust(width)}  {g['mode']:<5}"
                     f" {g['passed']}/{g['runs']} passed"
                     f" ({rate:5.1f}%), last {g['last_verdict']}")
    lines.append("")
    unverified = [row for row in rows if not row["verified"]]
    if unverified:
        lines.append("Unverified bundles (excluded from rankings):")
        for row in unverified:
            lines.append(f"  {row['run_id']}: {'; '.join(row['problems'])}")
        lines.append("")
    lines.append("Rankings include only bundles verified with the local evaluator."
                 " Verification checks recorded evidence, not independent truth."
                 " The board is a view, not a record.")
    return "\n".join(lines) + "\n"
