# SPDX-License-Identifier: Apache-2.0
"""Tests for the hackathon marketplace data adapter."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from nest_marketplace.adapter import (
    AGENT_HANDLES,
    KNOWN_LAYERS,
    build_dataset,
    classify_layer,
    extract_handle_and_theme,
    is_agent_handle,
    load_scores,
    parse_pull_requests,
    scrub_session_links,
    short_description,
    to_jsonable,
)


def _pr(
    number: int,
    *,
    branch: str,
    title: str = "Test submission",
    body: str = "## Piece picked\n\nA short description of what was built.",
    login: str = "mariagorskikh",
    additions: int | None = 120,
    deletions: int | None = 4,
    changed_files: int | None = 3,
) -> dict[str, Any]:
    """Helper that mirrors the shape of a GitHub REST pulls payload."""

    return {
        "number": number,
        "title": title,
        "body": body,
        "html_url": f"https://github.com/projnanda/nandatown/pull/{number}",
        "diff_url": f"https://github.com/projnanda/nandatown/pull/{number}.diff",
        "user": {
            "login": login,
            "avatar_url": f"https://avatars.githubusercontent.com/u/{number}?v=4",
        },
        "head": {"ref": branch},
        "created_at": f"2026-05-26T19:0{number}:00Z",
        "additions": additions,
        "deletions": deletions,
        "changed_files": changed_files,
    }


# ---------------------------------------------------------------------------
# scores file handling
# ---------------------------------------------------------------------------


def test_load_scores_returns_empty_dict_when_file_missing(tmp_path: Path) -> None:
    """The judge track may not have written `scores.json` yet — the
    adapter must degrade to "unscored" instead of crashing the build."""

    missing = tmp_path / "definitely-not-here.json"
    assert load_scores(missing) == {}


def test_load_scores_returns_empty_dict_when_path_is_none() -> None:
    assert load_scores(None) == {}


def test_load_scores_returns_empty_dict_on_malformed_json(tmp_path: Path) -> None:
    path = tmp_path / "scores.json"
    path.write_text("this is not json", encoding="utf-8")
    assert load_scores(path) == {}


def test_load_scores_returns_empty_dict_on_non_object_root(tmp_path: Path) -> None:
    path = tmp_path / "scores.json"
    path.write_text("[1, 2, 3]", encoding="utf-8")
    assert load_scores(path) == {}


def test_load_scores_parses_valid_breakdown(tmp_path: Path) -> None:
    """The judge panel writes scores.json in the PR #14 scoreboard shape:
    `{version, generated_at, mock, submissions: [{pr, scores: {...},
    median, consensus, ...}]}`. ``load_scores`` projects it into
    ``{pr_number: JudgeScore}`` for the marketplace."""

    path = tmp_path / "scores.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "generated_at": "2026-05-26T20:00:00+00:00",
                "mock": True,
                "submissions": [
                    {
                        "pr": 11,
                        "scores": {
                            "correctness": 4.0,
                            "test_rigor": 3.0,
                            "api_fit": 4.0,
                            "docs_quality": 5.0,
                            "novelty": 3.0,
                            "persona_fidelity": 4.0,
                        },
                        "median": 23.0,
                        "consensus": "Solid SRE framing.",
                    },
                    "ignored-non-object",
                ],
            }
        ),
        encoding="utf-8",
    )
    scores = load_scores(path)
    assert set(scores.keys()) == {"11"}
    s = scores["11"]
    assert s.total == 23.0  # canonical median, in [6, 30]
    assert s.correctness == 4.0
    assert s.test_rigor == 3.0
    assert s.api_fit == 4.0
    assert s.docs_quality == 5.0
    assert s.novelty == 3.0
    assert s.persona_fidelity == 4.0
    assert s.notes == "Solid SRE framing."


def test_load_scores_ignores_unknown_top_level_shape(tmp_path: Path) -> None:
    """An old-style flat ``{<pr>: {...}}`` file (the schema-drift case
    this module guards against) should degrade to an empty mapping
    rather than smuggling stale per-dim numbers into the UI."""

    path = tmp_path / "scores.json"
    path.write_text(
        json.dumps({"11": {"correctness": 8.5, "total": 7.6}}),
        encoding="utf-8",
    )
    assert load_scores(path) == {}


# ---------------------------------------------------------------------------
# branch + layer classification
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("handle", AGENT_HANDLES)
def test_extract_handle_recognises_every_agent_handle(handle: str) -> None:
    parsed_handle, theme = extract_handle_and_theme(f"hackathon/{handle}-some-theme")
    assert parsed_handle == handle
    assert theme == "some-theme"
    assert is_agent_handle(handle)


def test_extract_handle_returns_none_for_non_hackathon_branch() -> None:
    assert extract_handle_and_theme("main") == (None, None)
    assert extract_handle_and_theme("claude/foo-bar") == (None, None)
    assert extract_handle_and_theme("hackathon/") == (None, None)


def test_extract_handle_human_branch_returns_first_segment() -> None:
    handle, theme = extract_handle_and_theme("hackathon/some-human-thing")
    assert handle == "some"
    assert theme == "human-thing"
    assert not is_agent_handle(handle or "")


def test_classify_layer_uses_theme_first() -> None:
    assert classify_layer("eigentrust") == "trust"
    assert classify_layer("htlc-escrow") == "payments"
    assert classify_layer("sealed-bid-coordination") == "coordination"
    assert classify_layer("netem-transport") == "transport"
    assert classify_layer("semantic-memory") == "memory"
    assert classify_layer("dpop-auth") == "auth"


def test_classify_layer_falls_back_to_title_then_body() -> None:
    assert classify_layer(None, title="Privacy: zk proof") == "privacy"
    assert classify_layer(None, title="random", body="Builds on the registry layer") == "registry"


def test_classify_layer_returns_unclassified_when_nothing_matches() -> None:
    assert classify_layer(None, title="no idea", body="really, nothing here") == "unclassified"


# ---------------------------------------------------------------------------
# short_description
# ---------------------------------------------------------------------------


def test_short_description_skips_headings_and_blockquotes() -> None:
    body = "# Heading\n> a quote\n\nThe real first line of prose."
    assert short_description(body) == "The real first line of prose."


def test_short_description_truncates_long_paragraphs() -> None:
    long = "Sentence one is short. " + ("word " * 200)
    out = short_description(long, max_len=80)
    assert len(out) <= 81  # +1 for ellipsis
    assert out.startswith("Sentence one is short.")


def test_short_description_empty_input() -> None:
    assert short_description("") == ""
    assert short_description("# only-headings\n## still headings") == ""


# ---------------------------------------------------------------------------
# scrub_session_links — private Claude Code session links must not leak
# ---------------------------------------------------------------------------

# The exact attribution block agent PRs carry: a bare session-URL line, a
# horizontal rule, then an italic footer linking the same private session.
_CLAUDE_FOOTER = (
    "https://claude.ai/code/session_01C5j2D4MgCkPgsjSCqBVpWW\n"
    "\n"
    "---\n"
    "_Generated by [Claude Code]"
    "(https://claude.ai/code/session_01C5j2D4MgCkPgsjSCqBVpWW)_"
)


def test_scrub_session_links_removes_footer_at_end_of_body() -> None:
    body = "## Piece picked\n\nReal prose about the build.\n\n" + _CLAUDE_FOOTER
    out = scrub_session_links(body)
    assert "claude.ai" not in out
    assert "Generated by" not in out
    # Genuine content survives, with no dangling rule or trailing blanks.
    assert out == "## Piece picked\n\nReal prose about the build."


def test_scrub_session_links_preserves_content_after_footer() -> None:
    # Bots (e.g. Sourcery) sometimes append a summary *after* the Claude
    # footer — that content must be kept, only the session link removed.
    trailer = "## Summary by Sourcery\n\nIntroduce an escrow plugin."
    body = "Real prose.\n\n" + _CLAUDE_FOOTER + "\n\n" + trailer
    out = scrub_session_links(body)
    assert "claude.ai" not in out
    assert trailer in out
    assert out.startswith("Real prose.")


def test_scrub_session_links_is_noop_without_session_link() -> None:
    # A body with no session link — including a legitimate horizontal
    # rule — must be returned byte-for-byte unchanged.
    body = "## Piece picked\n\nNothing private here.\n\n---\n\nNotes follow."
    assert scrub_session_links(body) == body


def test_scrub_session_links_handles_empty_body() -> None:
    assert scrub_session_links("") == ""


# ---------------------------------------------------------------------------
# parse_pull_requests + build_dataset
# ---------------------------------------------------------------------------


def test_parse_pull_requests_scrubs_session_link_from_body_markdown() -> None:
    body = "## Piece picked\n\nWhat got built.\n\n" + _CLAUDE_FOOTER
    prs = [_pr(7, branch="hackathon/coinbase-crypto-htlc-escrow", body=body)]
    [sub] = parse_pull_requests(prs)
    assert "claude.ai" not in sub.body_markdown
    # short_description (first prose line) stays clean and unaffected.
    assert sub.short_description == "What got built."


def test_parse_pull_requests_filters_non_hackathon_branches() -> None:
    prs = [
        _pr(1, branch="main"),
        _pr(2, branch="claude/foo"),
        _pr(3, branch="hackathon/mit-undergrad-eigentrust"),
    ]
    out = parse_pull_requests(prs)
    assert [s.pr_number for s in out] == [3]


def test_parse_pull_requests_tags_agent_vs_human() -> None:
    prs = [
        _pr(10, branch="hackathon/meta-backend-realistic-transport"),
        _pr(11, branch="hackathon/some-random-human-build"),
    ]
    by_id = {s.pr_number: s for s in parse_pull_requests(prs)}
    assert by_id[10].tag == "agent-authored"
    assert by_id[10].author.kind == "agent"
    assert by_id[10].author.handle == "meta-backend"
    assert by_id[11].tag == "human-authored"
    assert by_id[11].author.kind == "human"


def test_parse_pull_requests_attaches_scores_by_pr_number() -> None:
    # Build a tiny inline scores mapping via the same dataclass.
    from nest_marketplace.adapter import JudgeScore

    scores = {"7": JudgeScore(total=21.0, correctness=4.0)}
    prs = [_pr(7, branch="hackathon/coinbase-crypto-htlc-escrow")]
    [sub] = parse_pull_requests(prs, scores)
    assert sub.score is not None
    assert sub.score.total == 21.0
    assert sub.score.correctness == 4.0


def test_build_dataset_aggregates_layer_stats_and_top_score() -> None:
    from nest_marketplace.adapter import JudgeScore

    prs = [
        _pr(3, branch="hackathon/mit-undergrad-eigentrust", additions=200),
        _pr(6, branch="hackathon/stanford-ml-phd-eigentrust", additions=300),
        _pr(7, branch="hackathon/coinbase-crypto-htlc-escrow", additions=500),
    ]
    # `total` is the canonical median in [6, 30] — same number the judge
    # panel writes as `median` to scores.json.
    scores = {
        "3": JudgeScore(total=19.0),
        "6": JudgeScore(total=27.0),
        "7": JudgeScore(total=22.0),
    }
    ds = build_dataset(prs, scores, generated_at="t")

    assert ds.stats["total_submissions"] == 3
    assert ds.stats["unique_participants"] == 3
    assert ds.stats["layers_covered"] == 2  # trust + payments
    assert ds.stats["layers_total"] == 12
    assert ds.stats["total_lines_added"] == 1000

    layer_map = {ls.key: ls for ls in ds.layers}
    assert set(layer_map.keys()) == set(KNOWN_LAYERS)
    assert layer_map["trust"].submission_count == 2
    assert layer_map["trust"].top_score == 27.0
    assert layer_map["payments"].submission_count == 1
    assert layer_map["payments"].top_score == 22.0
    assert layer_map["privacy"].is_open is True
    assert layer_map["privacy"].submission_count == 0


def test_build_dataset_handles_missing_scores_gracefully() -> None:
    """The judge track may not have written `scores.json` yet. When
    `load_scores` returns `{}` every submission must still appear, just
    with `score=None`."""

    prs = [_pr(3, branch="hackathon/mit-undergrad-eigentrust")]
    ds = build_dataset(prs, load_scores(None), generated_at="t")
    [sub] = ds.submissions
    assert sub.score is None
    # The layer aggregate must not crash on an absent top score.
    trust_layer = next(ls for ls in ds.layers if ls.key == "trust")
    assert trust_layer.top_score is None
    assert trust_layer.submission_count == 1


def test_to_jsonable_round_trips_through_json() -> None:
    prs = [_pr(3, branch="hackathon/mit-undergrad-eigentrust")]
    ds = build_dataset(prs, {}, generated_at="t")
    blob = to_jsonable(ds)
    # Must be JSON-serialisable.
    encoded = json.dumps(blob)
    parsed = json.loads(encoded)
    assert parsed["stats"]["total_submissions"] == 1
    assert parsed["submissions"][0]["author"]["handle"] == "mit-undergrad"
    assert parsed["submissions"][0]["score"] is None


# ---------------------------------------------------------------------------
# Route smoke test — assert the Next.js routes exist and export a page.
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[3]
APP_DIR = REPO_ROOT / "apps" / "nest-dashboard" / "src" / "app" / "hackathon"

ROUTE_FILES = (
    APP_DIR / "page.tsx",
    APP_DIR / "layers" / "page.tsx",
    APP_DIR / "layers" / "[layer]" / "page.tsx",
    APP_DIR / "submissions" / "[id]" / "page.tsx",
)


@pytest.mark.parametrize("route", ROUTE_FILES, ids=lambda p: str(p.relative_to(REPO_ROOT)))
def test_route_file_exists_and_exports_default(route: Path) -> None:
    """Each /hackathon route file must exist and export a default
    component — this is the file-system convention Next.js relies on
    to actually serve the route."""

    assert route.exists(), f"missing route file: {route}"
    text = route.read_text(encoding="utf-8")
    assert "export default" in text, f"route {route} has no default export"


def test_navbar_links_to_hackathon() -> None:
    navbar = REPO_ROOT / "apps" / "nest-dashboard" / "src" / "components" / "navbar.tsx"
    text = navbar.read_text(encoding="utf-8")
    assert "/hackathon" in text, "navbar must link to /hackathon"
