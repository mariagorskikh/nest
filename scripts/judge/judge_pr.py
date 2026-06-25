# SPDX-License-Identifier: Apache-2.0
"""Score a single hackathon PR with N independent LLM judges.

Each judge sees the rubric, the PR body, and the (possibly truncated) diff.
They return a structured JSON with per-dimension 1-5 scores and a rationale.
The aggregator computes the median per dimension and a synthesized 3-sentence
consensus narrative across judges.

The Anthropic SDK is imported lazily so the module can be imported in CI
environments where the SDK is not installed; the actual ``judge_pr`` call
will raise a clear error if the SDK is missing or the API key is unset.

Example::

    result = asyncio.run(judge_pr(2))
    print(result.median, result.consensus)
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import statistics
import sys
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Protocol, cast

RUBRIC_PATH = Path(__file__).parent / "rubric.md"
RUBRIC_VERSION = 1

DIMENSIONS: tuple[str, ...] = (
    "correctness",
    "test_rigor",
    "api_fit",
    "docs_quality",
    "novelty",
    "persona_fidelity",
)

# Per-file diff lines above this are truncated; the rest are replaced by a marker.
MAX_FILE_DIFF_LINES = 5000

GITHUB_API = "https://api.github.com"


def _judge_telemetry_enabled() -> bool:
    return os.environ.get("NEST_LLM_TELEMETRY", "1") != "0"


def _log_judge_usage(
    *,
    provider: str,
    model: str,
    response: Any,
    judge_id: int | None = None,
) -> None:
    if not _judge_telemetry_enabled():
        return
    usage = getattr(response, "usage", None)
    ctx = f"judge_id={judge_id}" if judge_id is not None else "judge"
    parts = [f"nest-llm-telemetry provider={provider} model={model} context={ctx}"]
    if usage is not None:
        inp = getattr(usage, "input_tokens", None) or getattr(usage, "prompt_tokens", None)
        out = getattr(usage, "output_tokens", None) or getattr(usage, "completion_tokens", None)
        if inp is not None:
            parts.append(f"input_tokens={inp}")
        if out is not None:
            parts.append(f"output_tokens={out}")
    print(" ".join(parts), file=sys.stderr)


# --------------------------------------------------------------------------- #
# Data classes
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class PRContext:
    """Everything a judge needs to score a PR.

    Example::

        ctx = fetch_pr_context(2, owner="projnanda", repo="nandatown")
    """

    number: int
    title: str
    body: str
    author: str
    head_sha: str
    head_ref: str
    diff: str
    diff_truncated: bool
    checks_summary: str


@dataclass
class JudgeVerdict:
    """One judge's verdict on one PR.

    Example::

        v = JudgeVerdict(judge_id=0, scores={...}, rationale="...")
    """

    judge_id: int
    scores: dict[str, int]
    rationale: str
    raw_response: str = ""
    error: str | None = None

    @property
    def total(self) -> int:
        """Sum of dimension scores (max 30)."""
        return sum(self.scores.values()) if self.scores else 0


@dataclass
class JudgeResult:
    """Aggregated result across N judges for one PR.

    Example::

        result = aggregate(verdicts, ctx, model="claude-opus-4-7")
        print(result.median)
    """

    pr_number: int
    head_sha: str
    head_ref: str
    title: str
    author: str
    model: str
    rubric_version: int
    diff_truncated: bool
    medians: dict[str, float]
    total_median: float
    consensus: str
    judges: list[JudgeVerdict] = field(default_factory=lambda: [])

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation.

        Example::

            json.dumps(result.to_dict())
        """
        return {
            "pr": self.pr_number,
            "head_sha": self.head_sha,
            "head_ref": self.head_ref,
            "title": self.title,
            "author": self.author,
            "model": self.model,
            "rubric_version": self.rubric_version,
            "diff_truncated": self.diff_truncated,
            "scores": self.medians,
            "median": self.total_median,
            "consensus": self.consensus,
            "judges": [asdict(j) for j in self.judges],
        }


# --------------------------------------------------------------------------- #
# Aggregation (pure-Python, no SDK required)
# --------------------------------------------------------------------------- #


def median_score(values: list[int]) -> float:
    """Median that uses the low value on even-count ties (deterministic).

    Returns ``float('nan')`` for an empty list.

    Example::

        median_score([3, 4, 5]) == 4.0
        median_score([3, 4]) == 3.0  # tie-break low
    """
    if not values:
        return float("nan")
    if len(values) == 1:
        return float(values[0])
    return float(statistics.median_low(values))


def aggregate(
    verdicts: list[JudgeVerdict],
    ctx: PRContext,
    *,
    model: str,
    persona: str = "",
) -> JudgeResult:
    """Combine N judge verdicts into a single result.

    Missing judges (``error is not None`` or empty ``scores``) are skipped.
    If every judge errored, medians are NaN and consensus reports the error.

    Example::

        aggregate(verdicts, ctx, model="claude-opus-4-7")
    """
    good = [v for v in verdicts if v.error is None and v.scores]
    medians: dict[str, float] = {}
    for dim in DIMENSIONS:
        medians[dim] = median_score([v.scores.get(dim, 0) for v in good])
    totals = [v.total for v in good]
    total_median = median_score(totals)

    if not good:
        consensus = (
            "No judges returned a valid score for this PR; see per-judge "
            "errors. The submission was not evaluated. Re-run after the "
            "underlying issue is resolved."
        )
    else:
        consensus = _build_consensus(good, ctx, persona, total_median=total_median)
    return JudgeResult(
        pr_number=ctx.number,
        head_sha=ctx.head_sha,
        head_ref=ctx.head_ref,
        title=ctx.title,
        author=ctx.author,
        model=model,
        rubric_version=RUBRIC_VERSION,
        diff_truncated=ctx.diff_truncated,
        medians=medians,
        total_median=total_median,
        consensus=consensus,
        judges=verdicts,
    )


def _build_consensus(
    verdicts: list[JudgeVerdict],
    ctx: PRContext,
    persona: str,
    *,
    total_median: float,
) -> str:
    """Three-sentence consensus narrative stitched from per-dimension medians.

    Deliberately deterministic: derived from the numeric verdicts so the
    consensus is reproducible without a second LLM call. The reported total
    (``total_median``) is taken verbatim from the aggregator so the prose
    always agrees with the ``median`` field that ends up in ``scores.json``;
    historically this was recomputed as ``sum(per-dim medians)`` which
    diverges from ``median_low(per-judge totals)`` in any non-degenerate
    case (see PR #14 schema-drift fix).

    Example::

        _build_consensus(verdicts, ctx, "harvard-phd", total_median=21.0)
    """
    medians = {dim: median_score([v.scores.get(dim, 0) for v in verdicts]) for dim in DIMENSIONS}
    strong = sorted(medians.items(), key=lambda kv: -kv[1])[:2]
    weak = sorted(medians.items(), key=lambda kv: kv[1])[:2]
    persona_clause = f" from the {persona} persona" if persona else ""
    s1 = (
        f"PR #{ctx.number}{persona_clause} scored "
        f"{total_median:.1f}/30 across {len(verdicts)} judges, "
        f"with strongest dimensions {strong[0][0]} ({strong[0][1]:.1f}) "
        f"and {strong[1][0]} ({strong[1][1]:.1f})."
    )
    s2 = (
        f"Judges flagged {weak[0][0]} ({weak[0][1]:.1f}) and "
        f"{weak[1][0]} ({weak[1][1]:.1f}) as the weakest areas."
    )
    # Pull a representative sentence from the strongest judge's rationale.
    best = max(verdicts, key=lambda v: v.total)
    snippet = best.rationale.strip().split(".")[0].strip()
    if len(snippet) > 240:
        snippet = snippet[:237] + "..."
    s3 = f'Lead judge summary: "{snippet}."' if snippet else "No rationale snippet available."
    return f"{s1} {s2} {s3}"


# --------------------------------------------------------------------------- #
# GitHub fetch (stdlib only — no extra dependency)
# --------------------------------------------------------------------------- #


def _gh_get(url: str, *, accept: str = "application/vnd.github+json") -> bytes:
    """GET a GitHub URL with optional auth via GITHUB_TOKEN.

    Example::

        body = _gh_get("https://api.github.com/repos/o/r/pulls/1")
    """
    req = urllib.request.Request(url, headers={"Accept": accept, "User-Agent": "nest-judge/1.0"})
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
            return cast("bytes", resp.read())
    except urllib.error.HTTPError as exc:  # pragma: no cover - network-dependent
        raise RuntimeError(f"GitHub API GET {url} failed: {exc.code} {exc.reason}") from exc


def fetch_pr_context(pr_number: int, *, owner: str, repo: str) -> PRContext:
    """Fetch PR body, author, head SHA, diff, and checks summary.

    Example::

        ctx = fetch_pr_context(2, owner="projnanda", repo="nandatown")
    """
    pr_url = f"{GITHUB_API}/repos/{owner}/{repo}/pulls/{pr_number}"
    pr_json = json.loads(_gh_get(pr_url).decode("utf-8"))
    diff_bytes = _gh_get(pr_url, accept="application/vnd.github.v3.diff")
    diff = diff_bytes.decode("utf-8", errors="replace")
    diff, truncated = truncate_diff(diff, max_lines=MAX_FILE_DIFF_LINES)

    head_sha = str(pr_json["head"]["sha"])
    checks_url = f"{GITHUB_API}/repos/{owner}/{repo}/commits/{head_sha}/check-runs"
    try:
        checks_json = json.loads(_gh_get(checks_url).decode("utf-8"))
        runs = checks_json.get("check_runs", [])
        if runs:
            checks_summary = "; ".join(
                f"{r.get('name', '?')}={r.get('conclusion') or r.get('status') or '?'}"
                for r in runs
            )
        else:
            checks_summary = "no check runs reported"
    except RuntimeError as exc:  # pragma: no cover - network-dependent
        checks_summary = f"checks unavailable: {exc}"

    return PRContext(
        number=pr_number,
        title=str(pr_json.get("title", "")),
        body=str(pr_json.get("body") or ""),
        author=str(pr_json.get("user", {}).get("login", "")),
        head_sha=head_sha,
        head_ref=str(pr_json["head"]["ref"]),
        diff=diff,
        diff_truncated=truncated,
        checks_summary=checks_summary,
    )


def truncate_diff(diff: str, *, max_lines: int = MAX_FILE_DIFF_LINES) -> tuple[str, bool]:
    """Truncate any per-file diff section exceeding ``max_lines``.

    Walks ``diff --git`` boundaries; for each oversized file, keeps the
    first ``max_lines`` and replaces the rest with a marker.

    Example::

        truncated, was_truncated = truncate_diff(diff)
    """
    if not diff:
        return diff, False
    file_re = re.compile(r"^diff --git ", re.MULTILINE)
    matches = list(file_re.finditer(diff))
    if not matches:
        return diff, False
    chunks: list[str] = []
    any_truncated = False
    for i, m in enumerate(matches):
        start = m.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(diff)
        chunk = diff[start:end]
        lines = chunk.splitlines(keepends=True)
        if len(lines) > max_lines:
            any_truncated = True
            kept = "".join(lines[:max_lines])
            chunks.append(
                kept
                + f"\n... [truncated {len(lines) - max_lines} lines "
                + f"(file diff exceeded {max_lines} lines)] ...\n"
            )
        else:
            chunks.append(chunk)
    return "".join(chunks), any_truncated


# --------------------------------------------------------------------------- #
# Persona inference
# --------------------------------------------------------------------------- #


def infer_persona(head_ref: str, title: str = "") -> str:
    """Pull the persona handle from PR metadata.

    Prefers the ``[Hackathon] <persona>: ...`` title prefix (explicit) and
    falls back to the ``hackathon/<persona>-<slug>`` branch heuristic.

    Example::

        infer_persona("hackathon/harvard-phd-eigentrust") == "harvard-phd"
        infer_persona("foo", "[Hackathon] stanford-ml-phd: ...") == "stanford-ml-phd"
    """
    m = re.match(r"\s*\[Hackathon\]\s+([a-z0-9][a-z0-9-]*)\s*:", title, re.IGNORECASE)
    if m:
        return m.group(1).lower()
    if not head_ref.startswith("hackathon/"):
        return ""
    tail = head_ref[len("hackathon/") :]
    parts = tail.split("-")
    # Heuristic: persona is the first two hyphen-joined tokens (e.g. "harvard-phd").
    if len(parts) >= 2:
        return f"{parts[0]}-{parts[1]}"
    return parts[0] if parts else ""


def infer_layer(title: str, body: str) -> str:
    """Infer the Nanda Town layer (trust/payments/...) from PR text.

    Example::

        infer_layer("[Hackathon] eigentrust plugin", "trust layer") == "trust"
    """
    text = f"{title}\n{body}".lower()
    layers = (
        "trust",
        "payments",
        "coordination",
        "transport",
        "identity",
        "memory",
        "auth",
        "discovery",
        "observability",
        "policy",
        "lifecycle",
        "negotiation",
    )
    for layer in layers:
        if layer in text:
            return layer
    return "unknown"


# --------------------------------------------------------------------------- #
# Judge call (Anthropic / OpenAI providers, lazy imports)
# --------------------------------------------------------------------------- #


# Default model per provider.
DEFAULT_ANTHROPIC_MODEL = "claude-opus-4-7"
# As of May 2026, OpenAI's current best reasoning model on chat.completions is
# gpt-5.5. Callers can override with --model on the CLI.
DEFAULT_OPENAI_MODEL = "gpt-5.5"


class _JudgeClient(Protocol):
    async def judge(self, *, system_blocks: list[dict[str, Any]], user: str) -> str: ...


def load_rubric() -> str:
    """Return the rubric markdown as a string.

    Example::

        rubric = load_rubric()
    """
    return RUBRIC_PATH.read_text(encoding="utf-8")


def _build_user_prompt(ctx: PRContext) -> str:
    """Pack the PR context into the user turn of the judge prompt.

    Example::

        prompt = _build_user_prompt(ctx)
    """
    persona = infer_persona(ctx.head_ref, ctx.title)
    layer = infer_layer(ctx.title, ctx.body)
    header = (
        f"PR #{ctx.number}: {ctx.title}\n"
        f"Author: {ctx.author}\n"
        f"Persona (inferred): {persona or 'unknown'}\n"
        f"Layer (inferred): {layer}\n"
        f"Head ref: {ctx.head_ref}\n"
        f"Head SHA: {ctx.head_sha}\n"
        f"Checks: {ctx.checks_summary}\n"
        f"Diff truncated: {ctx.diff_truncated}\n"
    )
    body = ctx.body.strip() or "(empty PR body)"
    diff = ctx.diff or "(no diff)"
    return (
        f"{header}\n"
        f"--- PR body ---\n{body}\n\n"
        f"--- Unified diff ---\n{diff}\n\n"
        f"Score this PR per the rubric. Return JSON only."
    )


class AnthropicJudgeClient:
    """Thin wrapper over ``anthropic.AsyncAnthropic`` with prompt caching.

    The rubric is sent as a cached system block (``cache_control:
    ephemeral``), so the rubric tokens are billed once per 5-min window
    even when we run N judges back-to-back.

    Example::

        client = AnthropicJudgeClient(model="claude-opus-4-7")
        response = await client.judge(system_blocks=[...], user="...")
    """

    def __init__(self, *, model: str, api_key: str | None = None) -> None:
        self._model = model
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not self._api_key:
            raise RuntimeError(
                "ANTHROPIC_API_KEY is not set. Export it before calling judge_pr(), "
                "or pass api_key= explicitly. The judge will not run without it."
            )
        self._client: Any | None = None

    def _get_client(self) -> Any:
        if self._client is None:
            try:
                import anthropic  # pyright: ignore[reportMissingImports]
            except ImportError as exc:  # pragma: no cover - env-dependent
                raise RuntimeError(
                    "The 'anthropic' package is not installed. "
                    "Install it with: uv pip install anthropic"
                ) from exc
            self._client = cast(
                "Any",
                anthropic.AsyncAnthropic(api_key=self._api_key),  # pyright: ignore[reportUnknownMemberType,reportUnknownVariableType]
            )
        return cast("Any", self._client)

    async def judge(self, *, system_blocks: list[dict[str, Any]], user: str) -> str:
        client = self._get_client()
        response: Any = await client.messages.create(
            model=self._model,
            system=system_blocks,
            messages=[{"role": "user", "content": user}],
            temperature=0.0,
            max_tokens=2048,
        )
        _log_judge_usage(provider="anthropic", model=self._model, response=response)
        content_blocks = cast("list[Any]", getattr(response, "content", []))
        parts: list[str] = []
        for block in content_blocks:
            text = getattr(block, "text", None)
            if isinstance(text, str):
                parts.append(text)
        return "".join(parts)


# Public alias matching the Provider naming used in newer callers / docs.
# The original ``AnthropicJudgeClient`` name is retained for back-compat.
AnthropicProvider = AnthropicJudgeClient


class OpenAIProvider:
    """Thin wrapper over ``openai.AsyncOpenAI`` chat.completions.

    The rubric is flattened from the Anthropic-style ``system_blocks`` list
    into a single ``system`` message — OpenAI's chat.completions endpoint
    handles caching implicitly per its docs, so we don't try to be clever
    with any explicit cache marker. JSON mode is requested via
    ``response_format={"type": "json_object"}`` to match the rubric's
    ``Return JSON only.`` contract.

    Example::

        provider = OpenAIProvider(model="gpt-5.5")
        response = await provider.judge(system_blocks=[...], user="...")
    """

    def __init__(self, *, model: str, api_key: str | None = None) -> None:
        self._model = model
        self._api_key = api_key or os.environ.get("OPENAI_API_KEY")
        if not self._api_key:
            raise RuntimeError(
                "OPENAI_API_KEY is not set. Export it before calling judge_pr() "
                "with provider='openai', or pass api_key= explicitly. The judge "
                "will not run without it."
            )
        self._client: Any | None = None

    def _get_client(self) -> Any:
        if self._client is None:
            try:
                import openai  # pyright: ignore[reportMissingImports]
            except ImportError as exc:  # pragma: no cover - env-dependent
                raise RuntimeError(
                    "The 'openai' package is not installed. Install it with: uv pip install openai"
                ) from exc
            self._client = cast(
                "Any",
                openai.AsyncOpenAI(api_key=self._api_key),  # pyright: ignore[reportUnknownMemberType,reportUnknownVariableType]
            )
        return cast("Any", self._client)

    @staticmethod
    def _flatten_system(system_blocks: list[dict[str, Any]]) -> str:
        """Concatenate Anthropic-style system blocks into a single string.

        The judge_pr module hands every provider the same shape: a list of
        ``{"type": "text", "text": "...", ...}`` blocks. OpenAI doesn't
        accept that array form, so we join the ``text`` fields with blank
        lines — semantically equivalent for the rubric prompt.
        """
        parts: list[str] = []
        for block in system_blocks:
            text = block.get("text")
            if isinstance(text, str):
                parts.append(text)
        return "\n\n".join(parts)

    async def judge(self, *, system_blocks: list[dict[str, Any]], user: str) -> str:
        client = self._get_client()
        system_text = self._flatten_system(system_blocks)
        kwargs: dict[str, Any] = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": system_text},
                {"role": "user", "content": user},
            ],
            "response_format": {"type": "json_object"},
        }
        # Newer OpenAI reasoning models (gpt-5.x family) reject any temperature
        # value other than the default (1). Older chat models accept temperature=0
        # for determinism. Only pass temperature when the model accepts it.
        if not self._model.startswith("gpt-5"):
            kwargs["temperature"] = 0.0
        response: Any = await client.chat.completions.create(**kwargs)
        _log_judge_usage(provider="openai", model=self._model, response=response)
        choices = cast("list[Any]", getattr(response, "choices", []))
        if not choices:
            return ""
        message = getattr(choices[0], "message", None)
        content = getattr(message, "content", None) if message is not None else None
        return content if isinstance(content, str) else ""


def make_provider(
    name: str,
    *,
    model: str | None = None,
    api_key: str | None = None,
) -> _JudgeClient:
    """Build a judge client for the given provider name.

    Defaults to the provider's recommended model when ``model`` is None
    (``claude-opus-4-7`` for anthropic, ``gpt-5.5`` for openai).

    Example::

        provider = make_provider("openai")
        provider = make_provider("anthropic", model="claude-opus-4-7")
    """
    key = name.lower().strip()
    if key == "anthropic":
        return AnthropicProvider(model=model or DEFAULT_ANTHROPIC_MODEL, api_key=api_key)
    if key == "openai":
        return OpenAIProvider(model=model or DEFAULT_OPENAI_MODEL, api_key=api_key)
    raise ValueError(
        f"Unknown judge provider {name!r}; supported providers are 'anthropic' and 'openai'."
    )


def default_model_for(provider: str) -> str:
    """Return the default model name for a provider.

    Example::

        default_model_for("openai") == "gpt-5.5"
    """
    key = provider.lower().strip()
    if key == "anthropic":
        return DEFAULT_ANTHROPIC_MODEL
    if key == "openai":
        return DEFAULT_OPENAI_MODEL
    raise ValueError(
        f"Unknown judge provider {provider!r}; supported providers are 'anthropic' and 'openai'."
    )


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #


def parse_verdict(raw: str, judge_id: int) -> JudgeVerdict:
    """Extract the JSON verdict from a judge's response.

    Tolerates surrounding text or a fenced code block. Validates that all
    six dimensions are present as ints in [1, 5]. Errors are captured on
    the verdict rather than raised — one bad judge should not nuke the run.

    Example::

        v = parse_verdict('{"scores": {...}, "rationale": "..."}', 0)
    """
    text = raw.strip()
    # Strip fenced code blocks if present.
    fence_match = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.DOTALL)
    if fence_match:
        text = fence_match.group(1)
    # Find the first balanced JSON object.
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return JudgeVerdict(
            judge_id=judge_id,
            scores={},
            rationale="",
            raw_response=raw,
            error="no JSON object in response",
        )
    try:
        parsed: Any = json.loads(text[start : end + 1])
    except json.JSONDecodeError as exc:
        return JudgeVerdict(
            judge_id=judge_id,
            scores={},
            rationale="",
            raw_response=raw,
            error=f"JSON decode error: {exc}",
        )
    if not isinstance(parsed, dict):
        return JudgeVerdict(
            judge_id=judge_id,
            scores={},
            rationale="",
            raw_response=raw,
            error="response is not a JSON object",
        )
    data: dict[str, Any] = cast("dict[str, Any]", parsed)
    raw_scores: Any = data.get("scores")
    if not isinstance(raw_scores, dict):
        return JudgeVerdict(
            judge_id=judge_id,
            scores={},
            rationale="",
            raw_response=raw,
            error="missing 'scores' object",
        )
    raw_scores_dict: dict[str, Any] = cast("dict[str, Any]", raw_scores)
    scores: dict[str, int] = {}
    for dim in DIMENSIONS:
        value: Any = raw_scores_dict.get(dim)
        if not isinstance(value, int) or isinstance(value, bool) or value < 1 or value > 5:
            return JudgeVerdict(
                judge_id=judge_id,
                scores={},
                rationale="",
                raw_response=raw,
                error=f"dimension {dim!r} missing or out of range 1-5: {value!r}",
            )
        scores[dim] = value
    rationale_value: Any = data.get("rationale", "")
    rationale: str = rationale_value if isinstance(rationale_value, str) else str(rationale_value)
    return JudgeVerdict(
        judge_id=judge_id,
        scores=scores,
        rationale=rationale,
        raw_response=raw,
    )


# --------------------------------------------------------------------------- #
# Top-level entry point
# --------------------------------------------------------------------------- #


def _system_blocks(rubric: str) -> list[dict[str, Any]]:
    """Build the Anthropic ``system`` array with a cache_control marker on the rubric.

    Example::

        blocks = _system_blocks(load_rubric())
    """
    return [
        {
            "type": "text",
            "text": rubric,
            "cache_control": {"type": "ephemeral"},
        }
    ]


async def judge_pr(
    pr_number: int,
    *,
    n_judges: int = 3,
    model: str = "claude-opus-4-7",
    owner: str = "projnanda",
    repo: str = "nandatown",
    client: _JudgeClient | None = None,
    ctx: PRContext | None = None,
    provider: str = "anthropic",
) -> JudgeResult:
    """Run N parallel judges on a PR and return the aggregated result.

    The provider client is created lazily on first use. If ``ctx`` is
    provided, it is used directly; otherwise the PR is fetched from GitHub.
    If ``client`` is provided, it is used in place of the live provider
    client (this is what tests use to inject a mock judge). When ``client``
    is None, the provider is chosen by ``provider`` ("anthropic" or
    "openai") and the ``model`` is passed through.

    Example::

        result = await judge_pr(2, n_judges=3)
        result = await judge_pr(2, n_judges=3, provider="openai", model="gpt-5.5")
    """
    if n_judges < 1:
        raise ValueError(f"n_judges must be >= 1, got {n_judges}")
    if ctx is None:
        ctx = fetch_pr_context(pr_number, owner=owner, repo=repo)
    rubric = load_rubric()
    system_blocks = _system_blocks(rubric)
    user_prompt = _build_user_prompt(ctx)
    judge_client: _JudgeClient = (
        client if client is not None else make_provider(provider, model=model)
    )

    async def run_one(judge_id: int) -> JudgeVerdict:
        try:
            raw = await judge_client.judge(system_blocks=system_blocks, user=user_prompt)
        except Exception as exc:  # noqa: BLE001 - judge isolation by design
            return JudgeVerdict(
                judge_id=judge_id,
                scores={},
                rationale="",
                raw_response="",
                error=f"judge call failed: {exc}",
            )
        return parse_verdict(raw, judge_id)

    verdicts = await asyncio.gather(*(run_one(i) for i in range(n_judges)))
    persona = infer_persona(ctx.head_ref, ctx.title)
    return aggregate(list(verdicts), ctx, model=model, persona=persona)
