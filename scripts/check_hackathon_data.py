# SPDX-License-Identifier: Apache-2.0
"""Verify hackathon-data.json matches fixture + scores (CI drift check).
Usage::
    uv run python scripts/check_hackathon_data.py
"""

from __future__ import annotations
import argparse
import json
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_FIXTURE = REPO_ROOT / "fixtures" / "hackathon_prs.json"
DEFAULT_SCORES = REPO_ROOT / "docs" / "hackathon" / "scores.json"
DEFAULT_OUT = REPO_ROOT / "apps" / "nest-dashboard" / "public" / "hackathon-data.json"


def _build_to(path: Path, *, fixture: Path, scores: Path) -> None:
    from nest_marketplace.build_data import main as build_main

    argv = [
        "--prs-fixture",
        str(fixture),
        "--scores",
        str(scores),
        "--out",
        str(path),
    ]
    code = build_main(argv)
    if code != 0:
        msg = f"build_data failed with exit code {code}"
        raise RuntimeError(msg)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, default=DEFAULT_FIXTURE)
    parser.add_argument("--scores", type=Path, default=DEFAULT_SCORES)
    parser.add_argument("--committed", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args(argv)
    if not args.fixture.exists():
        print(f"Missing fixture: {args.fixture}", file=sys.stderr)
        return 1
    if not args.committed.exists():
        print(f"Missing committed data: {args.committed}", file=sys.stderr)
        return 1
    with tempfile.TemporaryDirectory() as tmp:
        generated = Path(tmp) / "hackathon-data.json"
        _build_to(generated, fixture=args.fixture, scores=args.scores)
        gen_obj = json.loads(generated.read_text(encoding="utf-8"))
        committed_obj = json.loads(args.committed.read_text(encoding="utf-8"))
        gen_obj.pop("generated_at", None)
        committed_obj.pop("generated_at", None)
        if gen_obj != committed_obj:
            print(
                f"{args.committed} is out of date.\n"
                "Regenerate with:\n"
                f"  uv run python -m nest_marketplace.build_data "
                f"--prs-fixture {args.fixture} "
                f"--scores {args.scores} "
                f"--out {args.committed}",
                file=sys.stderr,
            )
            return 1
    print(f"{args.committed} matches fixture + scores.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
