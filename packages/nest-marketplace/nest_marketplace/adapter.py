# SPDX-License-Identifier: Apache-2.0
"""Hackathon marketplace data adapter.

Pure functions that take raw GitHub PR JSON + an optional judge-scores
mapping and produce the shape consumed by the `/hackathon` Next.js routes.

The adapter never performs network I/O on its own — the caller hands it
the PR list. `build_data.py` is the thin CLI shim that does the actual
`urllib.request` call and writes the JSON file.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, cast

# The ten known agent handles. Branches `hackathon/<handle>-*` are tagged
# `agent-authored`; everything else is `human-authored`.
AGENT_HANDLES: tuple[str, ...] = (
    "mit-undergrad",
    "harvard-phd",
    "cybersec-blackhat",
    "google-staff",
    "stanford-ml-phd",
    "coinbase-crypto",
    "meta-backend",
    "openai-llm",
    "cmu-robotics",
    "linux-kernel",
)

# Canonical layer ordering — must match `docs/concepts.md` and the
# layer pages under `docs/layers/`.
KNOWN_LAYERS: tuple[str, ...] = (
    "transport",
    "communication",
    "identity",
    "registry",
    "auth",
    "trust",
    "payments",
    "coordination",
    "negotiation",
    "memory",
    "privacy",
    "datafacts",
)

# Display labels for layers.
LAYER_LABELS: dict[str, str] = {
    "transport": "Transport",
    "communication": "Communication",
    "identity": "Identity",
    "registry": "Registry",
    "auth": "Auth",
    "trust": "Trust",
    "payments": "Payments",
    "coordination": "Coordination",
    "negotiation": "Negotiation",
    "memory": "Memory",
    "privacy": "Privacy",
    "datafacts": "Data Facts",
}

# One-line blurbs lifted from `docs/concepts.md` so the UI doesn't have
# to round-trip back through the docs at render time.
LAYER_BLURBS: dict[str, str] = {
    "transport": "How bytes move between agents.",
    "communication": "Message framing and request/response semantics.",
    "identity": "Sign and verify per-agent payloads.",
    "registry": "Publish and discover agent cards.",
    "auth": "Issue, verify, and revoke capability tokens.",
    "trust": "Reputation scores, attestations, reports.",
    "payments": "Quote, pay, verify, refund.",
    "coordination": "Group decisions and task allocation.",
    "negotiation": "Bilateral bargaining.",
    "memory": "Shared key-value with subscribe and CAS.",
    "privacy": "Encryption and zero-knowledge proofs.",
    "datafacts": "Dataset publish, fetch, and ACL.",
}

# Map free-form theme slugs into our canonical layer keys. Authors put
# everything from "eigentrust" to "htlc-escrow" in the branch name; the
# regexes below pick a layer from the slug or the PR title/body.
# `\b` works for both hyphen-separated theme slugs and prose because
# `-` is a non-word character.
_THEME_TO_LAYER: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\btransport\b"), "transport"),
    (re.compile(r"\b(?:netem|latency|tail-latency)\b"), "transport"),
    (re.compile(r"\bcomm(?:unication)?\b"), "communication"),
    (re.compile(r"\bidentity\b|\bdid[-_]?key\b|\bsigning\b"), "identity"),
    (re.compile(r"\bregistry\b"), "registry"),
    (re.compile(r"\bauth\b|\bdpop\b|\bjwt\b|\bcapability\b"), "auth"),
    (re.compile(r"\beigentrust\b|\breputation\b|\btrust\b"), "trust"),
    (re.compile(r"\bescrow\b|\bpayment\b|\bhtlc\b|\bprepaid\b"), "payments"),
    (re.compile(r"\bsealed-bid\b|\bauction\b|\bcoordination\b|\bcontract-net\b"), "coordination"),
    (re.compile(r"\bnegotiat"), "negotiation"),
    (re.compile(r"\bmemory\b|\bsemantic\b|\bblackboard\b"), "memory"),
    (re.compile(r"\bprivacy\b|\bzk\b|\bencrypt"), "privacy"),
    (re.compile(r"\bdatafact|\bdataset\b"), "datafacts"),
)


@dataclass(frozen=True)
class SubmissionAuthor:
    """Author identity for a submission card."""

    handle: str
    avatar_url: str
    profile_url: str
    kind: str  # "agent" or "human"


@dataclass(frozen=True)
class JudgeScore:
    """Per-dimension score breakdown and a derived total.

    The six dimensions mirror ``scripts/judge/rubric.md`` (the source of
    truth — do not invent new ones here). Each dimension is on the 1-5
    integer scale the judges actually score against; ``total`` is the
    sum and therefore lives in ``[6, 30]``. ``total`` is taken verbatim
    from the ``median`` field that the judge panel writes to
    ``docs/hackathon/scores.json`` (which is ``median_low`` of the
    per-judge totals, not ``sum`` of per-dim medians — they differ).
    """

    correctness: float | None = None
    test_rigor: float | None = None
    api_fit: float | None = None
    docs_quality: float | None = None
    novelty: float | None = None
    persona_fidelity: float | None = None
    total: float | None = None
    notes: str | None = None


@dataclass(frozen=True)
class Submission:
    """One hackathon submission, ready for serialisation to the UI."""

    id: str  # PR number as a string
    pr_number: int
    title: str
    short_description: str
    body_markdown: str
    layer: str  # one of KNOWN_LAYERS or "unclassified"
    branch: str
    author: SubmissionAuthor
    pr_url: str
    diff_url: str
    additions: int | None
    deletions: int | None
    changed_files: int | None
    created_at: str
    score: JudgeScore | None
    # Tagging — convenient for the UI.
    tag: str  # "agent-authored" or "human-authored"


def is_agent_handle(handle: str) -> bool:
    """Return True if `handle` is one of the ten known agent handles."""

    return handle in AGENT_HANDLES


def extract_handle_and_theme(branch: str) -> tuple[str | None, str | None]:
    """Parse `hackathon/<handle>-<theme>` into (handle, theme).

    Returns (None, None) for branches that don't follow the convention,
    so the caller can treat them as human-authored with no classified
    theme.
    """

    if not branch.startswith("hackathon/"):
        return None, None
    rest = branch[len("hackathon/") :]
    if not rest:
        return None, None
    # Greedy match against known agent handles first — they contain
    # hyphens, so a simple `split('-', 1)` would mis-split things like
    # "mit-undergrad-eigentrust".
    for handle in AGENT_HANDLES:
        prefix = f"{handle}-"
        if rest.startswith(prefix):
            return handle, rest[len(prefix) :]
    # Fall back: the first segment up to the first '-' is the handle.
    head, _, tail = rest.partition("-")
    return head, tail or None


def classify_layer(theme: str | None, title: str = "", body: str = "") -> str:
    """Pick a layer key from the theme slug, then title, then body.

    Returns "unclassified" if nothing matches.
    """

    for source in (theme or "", title.lower(), body.lower()):
        if not source:
            continue
        for pattern, layer in _THEME_TO_LAYER:
            if pattern.search(source):
                return layer
    return "unclassified"


def short_description(body: str, max_len: int = 240) -> str:
    """Pull a short blurb out of a PR body.

    Skips markdown heading lines and pull-quotes, then truncates at the
    first sentence boundary or `max_len`.
    """

    if not body:
        return ""
    for raw_line in body.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("#"):
            continue
        if line.startswith(">"):
            continue
        if line.startswith("```"):
            continue
        # Drop bold markers and inline code backticks for the blurb.
        cleaned = line.replace("**", "").replace("`", "")
        if len(cleaned) <= max_len:
            return cleaned
        # Truncate at the last sentence boundary inside max_len, then
        # fall back to a word boundary.
        cut = cleaned[:max_len]
        for sep in (". ", "? ", "! "):
            idx = cut.rfind(sep)
            if idx >= max_len // 2:
                return cut[: idx + 1].strip()
        space = cut.rfind(" ")
        if space >= max_len // 2:
            return cut[:space].rstrip() + "…"
        return cut + "…"
    return ""


# Some agent-authored PR bodies carry a "Generated by Claude Code"
# attribution that embeds a `claude.ai/code/session_…` link. That link
# is 403 for everyone but the author, so it must never reach the public
# marketplace — neither the rendered submission page nor the
# downloadable `hackathon-data.json`. Scrub it at the adapter boundary
# so every build (live GitHub or fixture) is clean regardless of source.
_SESSION_LINK_MARK = "claude.ai/code/session"
_TRAILING_RULE_RE = re.compile(r"(?:\n[ \t]*(?:-{3,}|\*{3,}|_{3,})[ \t]*)+\s*\Z")
_BLANK_RUN_RE = re.compile(r"\n{3,}")


def scrub_session_links(body: str) -> str:
    """Strip any private ``claude.ai/code/session_…`` attribution.

    Drops the bare session-URL line and the ``_Generated by [Claude
    Code](…)_`` footer that embed it, then tidies the now-dangling
    horizontal rule and collapsed blank runs. Real content that happens
    to follow the footer (e.g. a bot-appended PR summary) is preserved.
    No-op for bodies that never mention a session link.
    """

    if not body or _SESSION_LINK_MARK not in body:
        return body
    kept = [line for line in body.splitlines() if _SESSION_LINK_MARK not in line]
    cleaned = _BLANK_RUN_RE.sub("\n\n", "\n".join(kept))
    cleaned = _TRAILING_RULE_RE.sub("", cleaned)
    return cleaned.rstrip()


def _get(d: Mapping[str, object], key: str) -> object:
    """Type-narrowing helper — pyright strict mode is unhappy with
    `dict[str, Any]`, so we keep raw JSON typed as ``object`` and
    funnel field access through this single helper."""

    return d.get(key)


def load_scores(scores_path: Path | str | None) -> dict[str, JudgeScore]:
    """Load `docs/hackathon/scores.json` if it exists.

    The judge track (PR #14) owns this file. The on-disk shape is::

        {
          "version": 1,
          "generated_at": "2026-05-26T...",
          "mock": true,
          "submissions": [
            {
              "pr": 2,
              "scores": {
                "correctness": 3.0,
                "test_rigor": 2.0,
                "api_fit": 3.0,
                "docs_quality": 5.0,
                "novelty": 3.0,
                "persona_fidelity": 4.0
              },
              "median": 21.0,           // sum-equivalent total in [6, 30]
              "consensus": "...",
              ...
            },
            ...
          ]
        }

    We project each entry into ``{pr_number: JudgeScore}`` where the
    six dimensions are scaled 1-5 and ``total`` carries the ``median``
    field verbatim. The ``consensus`` prose (when present) is stashed
    on ``notes`` so the detail view can quote it.

    Missing keys mean the submission is unscored — the UI shows
    "unscored — judging in progress" for those.

    A missing or unreadable file returns an empty dict; never raises.
    The PR #16-era flat ``{<pr>: {...}}`` shape is no longer supported
    on disk (the judge panel never wrote it); the function still
    degrades to an empty dict for anything it does not recognise.
    """

    if scores_path is None:
        return {}
    path = Path(scores_path)
    if not path.exists():
        return {}
    try:
        raw: object = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    if not isinstance(raw, dict):
        return {}
    raw_map = cast("dict[str, object]", raw)
    submissions_obj = _get(raw_map, "submissions")
    if not isinstance(submissions_obj, list):
        return {}
    out: dict[str, JudgeScore] = {}
    for entry_obj in cast("list[object]", submissions_obj):
        if not isinstance(entry_obj, dict):
            continue
        entry = cast("dict[str, object]", entry_obj)
        pr_value = _get(entry, "pr")
        pr_number = _coerce_int(pr_value)
        if pr_number is None:
            continue
        scores_obj = _get(entry, "scores")
        scores_map: Mapping[str, object] = (
            cast("dict[str, object]", scores_obj) if isinstance(scores_obj, dict) else {}
        )
        out[str(pr_number)] = JudgeScore(
            correctness=_coerce_float(_get(scores_map, "correctness")),
            test_rigor=_coerce_float(_get(scores_map, "test_rigor")),
            api_fit=_coerce_float(_get(scores_map, "api_fit")),
            docs_quality=_coerce_float(_get(scores_map, "docs_quality")),
            novelty=_coerce_float(_get(scores_map, "novelty")),
            persona_fidelity=_coerce_float(_get(scores_map, "persona_fidelity")),
            # `median` is the canonical headline number written by the
            # judge panel (median_low of per-judge totals in [6, 30]).
            total=_coerce_float(_get(entry, "median")),
            notes=_coerce_str(_get(entry, "consensus")),
        )
    return out


def _coerce_float(v: object) -> float | None:
    if isinstance(v, bool):  # bool is an int subclass; reject explicitly
        return None
    if isinstance(v, (int, float)):
        return float(v)
    return None


def _coerce_str(v: object) -> str | None:
    if isinstance(v, str) and v.strip():
        return v
    return None


def _as_mapping(value: object) -> Mapping[str, object]:
    """Best-effort cast for nested GitHub PR sub-objects."""

    if isinstance(value, dict):
        return cast("dict[str, object]", value)
    return {}


def parse_pull_requests(
    prs: list[dict[str, Any]],
    scores: dict[str, JudgeScore] | None = None,
) -> list[Submission]:
    """Convert raw GitHub PR JSON into `Submission` records.

    Only PRs whose `head.ref` starts with `hackathon/` are kept.
    """

    scores = scores or {}
    out: list[Submission] = []
    for raw_pr in prs:
        pr: Mapping[str, object] = cast("dict[str, object]", raw_pr)
        head = _as_mapping(_get(pr, "head"))
        branch = _coerce_str(_get(head, "ref")) or ""
        if not branch.startswith("hackathon/"):
            continue

        user = _as_mapping(_get(pr, "user"))
        handle, theme = extract_handle_and_theme(branch)
        login = _coerce_str(_get(user, "login"))
        author_login = login or handle or "unknown"
        avatar = _coerce_str(_get(user, "avatar_url")) or f"https://github.com/{author_login}.png"
        profile = _coerce_str(_get(user, "profile_url")) or f"https://github.com/{author_login}"

        # Whether the branch is agent-authored is decided by the branch
        # slug, not the GitHub login (per spec). The login still drives
        # the avatar so judges see who actually pushed.
        kind = "agent" if (handle and is_agent_handle(handle)) else "human"
        display_handle = handle if (handle and is_agent_handle(handle)) else author_login

        title = _coerce_str(_get(pr, "title")) or ""
        body = scrub_session_links(_coerce_str(_get(pr, "body")) or "")
        layer = classify_layer(theme, title, body)

        number = _coerce_int(_get(pr, "number")) or 0
        html_url = _coerce_str(_get(pr, "html_url")) or ""
        diff_url = _coerce_str(_get(pr, "diff_url")) or (html_url + ".diff" if html_url else "")

        score = scores.get(str(number))

        author = SubmissionAuthor(
            handle=display_handle,
            avatar_url=avatar,
            profile_url=profile,
            kind=kind,
        )
        out.append(
            Submission(
                id=str(number),
                pr_number=number,
                title=title,
                short_description=short_description(body),
                body_markdown=body,
                layer=layer,
                branch=branch,
                author=author,
                pr_url=html_url,
                diff_url=diff_url,
                additions=_coerce_int(_get(pr, "additions")),
                deletions=_coerce_int(_get(pr, "deletions")),
                changed_files=_coerce_int(_get(pr, "changed_files")),
                created_at=_coerce_str(_get(pr, "created_at")) or "",
                score=score,
                tag="agent-authored" if kind == "agent" else "human-authored",
            )
        )
    # Newest first; deterministic for tests.
    out.sort(key=lambda s: (s.created_at, s.pr_number), reverse=True)
    return out


def _coerce_int(v: object) -> int | None:
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    return None


@dataclass(frozen=True)
class LayerStats:
    """Per-layer aggregates the landing + layers grid pages render."""

    key: str
    label: str
    blurb: str
    submission_count: int
    top_score: float | None
    is_open: bool  # True when there are zero submissions


def _empty_submissions() -> list[Submission]:
    return []


def _empty_layers() -> list[LayerStats]:
    return []


def _empty_stats() -> dict[str, int]:
    return {}


@dataclass(frozen=True)
class Dataset:
    """The shape the Next.js routes consume."""

    generated_at: str
    submissions: list[Submission] = field(default_factory=_empty_submissions)
    layers: list[LayerStats] = field(default_factory=_empty_layers)
    stats: dict[str, int] = field(default_factory=_empty_stats)


def build_dataset(
    prs: list[dict[str, Any]],
    scores: dict[str, JudgeScore] | None = None,
    generated_at: str = "",
) -> Dataset:
    """Produce a complete dataset from raw inputs.

    Pure: no I/O, fully deterministic given the inputs.
    """

    submissions = parse_pull_requests(prs, scores)
    by_layer: dict[str, list[Submission]] = {layer: [] for layer in KNOWN_LAYERS}
    for sub in submissions:
        if sub.layer in by_layer:
            by_layer[sub.layer].append(sub)

    layer_stats: list[LayerStats] = []
    for layer in KNOWN_LAYERS:
        bucket = by_layer.get(layer, [])
        top = max(
            (s.score.total for s in bucket if s.score and s.score.total is not None),
            default=None,
        )
        layer_stats.append(
            LayerStats(
                key=layer,
                label=LAYER_LABELS[layer],
                blurb=LAYER_BLURBS[layer],
                submission_count=len(bucket),
                top_score=top,
                is_open=len(bucket) == 0,
            )
        )

    unique_authors = {s.author.handle for s in submissions}
    layers_covered = sum(1 for ls in layer_stats if ls.submission_count > 0)
    total_added = sum(s.additions or 0 for s in submissions)
    total_files = sum(s.changed_files or 0 for s in submissions)

    stats = {
        "total_submissions": len(submissions),
        "unique_participants": len(unique_authors),
        "layers_covered": layers_covered,
        "layers_total": len(KNOWN_LAYERS),
        "total_lines_added": total_added,
        "total_files_changed": total_files,
    }

    return Dataset(
        generated_at=generated_at,
        submissions=submissions,
        layers=layer_stats,
        stats=stats,
    )


def to_jsonable(dataset: Dataset) -> dict[str, Any]:
    """Flatten the dataclass tree into a JSON-serialisable dict."""

    return {
        "generated_at": dataset.generated_at,
        "stats": dataset.stats,
        "layers": [asdict(layer) for layer in dataset.layers],
        "submissions": [_submission_to_dict(sub) for sub in dataset.submissions],
    }


def _submission_to_dict(sub: Submission) -> dict[str, Any]:
    out = asdict(sub)
    if sub.score is None:
        out["score"] = None
    return out
