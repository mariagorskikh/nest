# SPDX-License-Identifier: Apache-2.0
"""Build `apps/nest-dashboard/public/hackathon-data.json`.

This is the only place in the marketplace stack that performs network
I/O. It:

1. Lists open PRs on the public Nanda Town repo via the anonymous GitHub REST
   API (no token, no secrets in the build pipeline).
2. For each `hackathon/*` PR, fetches the per-PR detail endpoint so we
   pick up `additions` / `deletions` / `changed_files`.
3. Hands the raw JSON to `nest_marketplace.adapter.build_dataset`.
4. Writes the resulting JSON to the Next.js `public/` directory so the
   `/hackathon` routes can serve it as a static asset.

If GitHub is unreachable the script still writes a well-formed empty
dataset so the UI shows its graceful error state instead of crashing
the Next.js build.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from nest_marketplace.adapter import build_dataset, load_scores, to_jsonable

DEFAULT_OWNER = "projnanda"
DEFAULT_REPO = "nandatown"
DEFAULT_USER_AGENT = "nest-marketplace-build/0.1 (+https://github.com/projnanda/nandatown)"
DEFAULT_TIMEOUT = 15.0


def _fetch_json(url: str, timeout: float = DEFAULT_TIMEOUT) -> object:
    """GET `url` and parse JSON. Raises on non-2xx responses."""

    req = urllib.request.Request(  # noqa: S310 — fixed api.github.com hosts only
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": DEFAULT_USER_AGENT,
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310  # nosec B310
        body = resp.read().decode("utf-8")
    return cast("object", json.loads(body))


def fetch_hackathon_prs(
    owner: str = DEFAULT_OWNER,
    repo: str = DEFAULT_REPO,
    *,
    timeout: float = DEFAULT_TIMEOUT,
) -> list[dict[str, Any]]:
    """Fetch open `hackathon/*` PRs with per-PR diff stats."""

    list_url = f"https://api.github.com/repos/{owner}/{repo}/pulls?state=open&per_page=100"
    raw = _fetch_json(list_url, timeout=timeout)
    if not isinstance(raw, list):
        return []
    raw_list = cast("list[object]", raw)

    hack_prs: list[dict[str, Any]] = []
    for raw_pr in raw_list:
        if not isinstance(raw_pr, dict):
            continue
        pr = cast("dict[str, Any]", raw_pr)
        raw_head = pr.get("head")
        if not isinstance(raw_head, dict):
            continue
        head = cast("dict[str, Any]", raw_head)
        ref = head.get("ref")
        if not isinstance(ref, str) or not ref.startswith("hackathon/"):
            continue
        number = pr.get("number")
        if not isinstance(number, int):
            continue
        # Per-PR detail endpoint exposes additions / deletions / changed_files.
        detail_url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{number}"
        try:
            detail = _fetch_json(detail_url, timeout=timeout)
        except (urllib.error.URLError, json.JSONDecodeError, TimeoutError):
            # Fall back to the list-endpoint payload — we still get
            # title/body/branch, just without diff stats.
            detail = pr
        if isinstance(detail, dict):
            hack_prs.append(cast("dict[str, Any]", detail))
    return hack_prs


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owner", default=DEFAULT_OWNER)
    parser.add_argument("--repo", default=DEFAULT_REPO)
    parser.add_argument(
        "--scores",
        default="docs/hackathon/scores.json",
        help="Path to the judge-panel scores JSON (default: docs/hackathon/scores.json).",
    )
    parser.add_argument(
        "--out",
        default="apps/nest-dashboard/public/hackathon-data.json",
        help="Where to write the generated dataset.",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Skip the network fetch and emit an empty dataset (uses scores file only).",
    )
    parser.add_argument(
        "--prs-fixture",
        default=None,
        help="Read PRs from a local JSON file instead of GitHub (useful in CI).",
    )
    args = parser.parse_args(argv)

    raw_prs: list[dict[str, Any]] = []
    if args.prs_fixture:
        parsed: object = json.loads(Path(args.prs_fixture).read_text(encoding="utf-8"))
        if isinstance(parsed, list):
            for item in cast("list[object]", parsed):
                if isinstance(item, dict):
                    raw_prs.append(cast("dict[str, Any]", item))
    elif not args.offline:
        try:
            raw_prs = fetch_hackathon_prs(args.owner, args.repo)
        except (urllib.error.URLError, json.JSONDecodeError, TimeoutError) as exc:
            print(
                f"warning: GitHub fetch failed ({exc}); writing empty dataset",
                file=sys.stderr,
            )
            raw_prs = []

    scores = load_scores(args.scores)
    dataset = build_dataset(
        raw_prs,
        scores,
        generated_at=datetime.now(UTC).isoformat(timespec="seconds"),
    )

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(to_jsonable(dataset), indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )
    print(
        f"wrote {out_path} ({dataset.stats['total_submissions']} submissions, "
        f"{dataset.stats['layers_covered']}/{dataset.stats['layers_total']} layers)",
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
