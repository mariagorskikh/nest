# SPDX-License-Identifier: Apache-2.0
"""Unit tests for ``scripts.judge``.

Real Anthropic API calls live behind ``@pytest.mark.live`` and are skipped
unless the user runs ``pytest -m live``.

Example::

    uv run pytest scripts/judge/tests/ -v
"""

from __future__ import annotations

import asyncio
import json
import math
from pathlib import Path
from typing import Any

import pytest

from scripts.judge.judge_pr import (
    DEFAULT_ANTHROPIC_MODEL,
    DEFAULT_OPENAI_MODEL,
    DIMENSIONS,
    RUBRIC_VERSION,
    AnthropicProvider,
    JudgeResult,
    JudgeVerdict,
    OpenAIProvider,
    PRContext,
    aggregate,
    default_model_for,
    infer_layer,
    infer_persona,
    judge_pr,
    log_judge_usage,
    make_provider,
    median_score,
    parse_verdict,
    truncate_diff,
)
from scripts.judge.run_all import MockJudgeClient, load_existing


def _ctx(**overrides: Any) -> PRContext:
    """Build a minimal PRContext for tests.

    Example::

        ctx = _ctx(number=42)
    """
    defaults: dict[str, Any] = {
        "number": 1,
        "title": "test",
        "body": "body",
        "author": "alice",
        "head_sha": "deadbeef",
        "head_ref": "hackathon/harvard-phd-eigentrust",
        "diff": "",
        "diff_truncated": False,
        "checks_summary": "no check runs reported",
    }
    defaults.update(overrides)
    return PRContext(**defaults)


def _verdict(judge_id: int, score: int) -> JudgeVerdict:
    return JudgeVerdict(
        judge_id=judge_id,
        scores=dict.fromkeys(DIMENSIONS, score),
        rationale=f"judge {judge_id} thinks score is {score}",
    )


# --------------------------------------------------------------------------- #
# median_score
# --------------------------------------------------------------------------- #


class TestMedianScore:
    def test_odd_count(self) -> None:
        assert median_score([1, 3, 5]) == 3.0

    def test_even_count_picks_low(self) -> None:
        # The function uses statistics.median_low for determinism.
        assert median_score([3, 4]) == 3.0
        assert median_score([1, 2, 3, 4]) == 2.0

    def test_empty(self) -> None:
        assert math.isnan(median_score([]))

    def test_single(self) -> None:
        assert median_score([5]) == 5.0

    def test_unsorted(self) -> None:
        assert median_score([5, 1, 3]) == 3.0


# --------------------------------------------------------------------------- #
# aggregate
# --------------------------------------------------------------------------- #


class TestAggregate:
    def test_three_judges_median_per_dimension(self) -> None:
        verdicts = [_verdict(0, 3), _verdict(1, 5), _verdict(2, 4)]
        result = aggregate(verdicts, _ctx(), model="m")
        for dim in DIMENSIONS:
            assert result.medians[dim] == 4.0
        assert result.total_median == 4 * 6
        assert result.rubric_version == RUBRIC_VERSION
        assert "strongest" in result.consensus
        assert "weakest" in result.consensus
        assert len(result.judges) == 3

    def test_tie_breaking_low(self) -> None:
        verdicts = [_verdict(0, 3), _verdict(1, 5)]  # even count
        result = aggregate(verdicts, _ctx(), model="m")
        for dim in DIMENSIONS:
            assert result.medians[dim] == 3.0  # median_low

    def test_missing_judge_is_skipped(self) -> None:
        verdicts = [
            _verdict(0, 4),
            JudgeVerdict(judge_id=1, scores={}, rationale="", error="boom"),
            _verdict(2, 4),
        ]
        result = aggregate(verdicts, _ctx(), model="m")
        for dim in DIMENSIONS:
            assert result.medians[dim] == 4.0
        # The errored judge is still surfaced in the per-judge list.
        assert len(result.judges) == 3
        assert any(j.error == "boom" for j in result.judges)

    def test_all_judges_errored(self) -> None:
        verdicts = [
            JudgeVerdict(judge_id=i, scores={}, rationale="", error="boom") for i in range(3)
        ]
        result = aggregate(verdicts, _ctx(), model="m")
        for dim in DIMENSIONS:
            assert math.isnan(result.medians[dim])
        assert math.isnan(result.total_median)
        assert "No judges" in result.consensus

    def test_consensus_uses_total_median_not_sum_of_medians(self) -> None:
        # Three judges with divergent dimension totals; per-dim medians
        # come from one set, per-judge totals from another. The bug being
        # guarded against: _build_consensus used to report
        # sum(per-dim medians), which differs from median_low(per-judge totals)
        # whenever the medians don't line up on the same judge.
        v0 = JudgeVerdict(
            judge_id=0,
            scores={
                "correctness": 5,
                "test_rigor": 3,
                "api_fit": 4,
                "docs_quality": 5,
                "novelty": 3,
                "persona_fidelity": 5,
            },
            rationale="strong overall.",
        )
        v1 = JudgeVerdict(
            judge_id=1,
            scores={
                "correctness": 2,
                "test_rigor": 2,
                "api_fit": 2,
                "docs_quality": 5,
                "novelty": 2,
                "persona_fidelity": 4,
            },
            rationale="weak.",
        )
        v2 = JudgeVerdict(
            judge_id=2,
            scores={
                "correctness": 3,
                "test_rigor": 2,
                "api_fit": 3,
                "docs_quality": 5,
                "novelty": 4,
                "persona_fidelity": 4,
            },
            rationale="middle.",
        )
        result = aggregate([v0, v1, v2], _ctx(number=2), model="m", persona="harvard-phd")
        # Per-dim medians sum: 3+2+3+5+3+4 = 20. Per-judge totals: 25, 17, 21
        # -> median_low = 21. The two differ. The prose must agree with
        # the JSON `median` field (total_median), not the buggy sum.
        assert result.total_median == 21.0
        assert f"{result.total_median:.1f}/30" in result.consensus
        assert "21.0/30" in result.consensus
        assert "20.0/30" not in result.consensus


# --------------------------------------------------------------------------- #
# parse_verdict
# --------------------------------------------------------------------------- #


class TestParseVerdict:
    def _payload(self, **overrides: Any) -> dict[str, Any]:
        scores: dict[str, Any] = dict.fromkeys(DIMENSIONS, 3)
        scores.update(overrides)
        return {"scores": scores, "rationale": "looks fine."}

    def test_plain_json(self) -> None:
        verdict = parse_verdict(json.dumps(self._payload()), judge_id=0)
        assert verdict.error is None
        assert verdict.scores == dict.fromkeys(DIMENSIONS, 3)
        assert verdict.total == 18

    def test_fenced_json(self) -> None:
        wrapped = f"sure here is my verdict:\n```json\n{json.dumps(self._payload())}\n```\n"
        verdict = parse_verdict(wrapped, judge_id=1)
        assert verdict.error is None
        assert verdict.scores["correctness"] == 3

    def test_garbage(self) -> None:
        verdict = parse_verdict("I refuse to comply.", judge_id=2)
        assert verdict.error is not None
        assert verdict.scores == {}

    def test_out_of_range(self) -> None:
        bad = self._payload(correctness=7)
        verdict = parse_verdict(json.dumps(bad), judge_id=3)
        assert verdict.error is not None
        assert "correctness" in (verdict.error or "")

    def test_missing_dimension(self) -> None:
        scores = dict.fromkeys(DIMENSIONS, 3)
        del scores["novelty"]
        verdict = parse_verdict(json.dumps({"scores": scores, "rationale": ""}), judge_id=4)
        assert verdict.error is not None

    def test_non_int_score(self) -> None:
        bad: dict[str, Any] = dict.fromkeys(DIMENSIONS, 3)
        bad["correctness"] = "five"
        verdict = parse_verdict(json.dumps({"scores": bad, "rationale": ""}), judge_id=5)
        assert verdict.error is not None


# --------------------------------------------------------------------------- #
# truncate_diff
# --------------------------------------------------------------------------- #


class TestTruncateDiff:
    def test_short_diff_untouched(self) -> None:
        diff = "diff --git a/x b/x\n@@\n+a\n+b\n"
        out, was = truncate_diff(diff, max_lines=10)
        assert out == diff
        assert was is False

    def test_long_file_truncated(self) -> None:
        body = "diff --git a/big b/big\n" + "\n".join(f"+line{i}" for i in range(50)) + "\n"
        out, was = truncate_diff(body, max_lines=10)
        assert was is True
        assert "truncated" in out
        # The trailing 40 lines should be gone.
        assert "line49" not in out

    def test_multi_file_only_big_truncated(self) -> None:
        small = "diff --git a/s b/s\n+only\n"
        big = "diff --git a/b b/b\n" + "\n".join(f"+l{i}" for i in range(50)) + "\n"
        out, was = truncate_diff(small + big, max_lines=10)
        assert was is True
        assert "+only" in out
        assert "truncated" in out

    def test_empty(self) -> None:
        out, was = truncate_diff("", max_lines=10)
        assert out == ""
        assert was is False


# --------------------------------------------------------------------------- #
# Persona / layer inference
# --------------------------------------------------------------------------- #


class TestInference:
    def test_persona_two_token(self) -> None:
        assert infer_persona("hackathon/harvard-phd-eigentrust") == "harvard-phd"
        assert infer_persona("hackathon/meta-backend-realistic-transport") == "meta-backend"

    def test_persona_from_title_wins(self) -> None:
        # Title gives a 3-token persona that branch heuristic would miss.
        ref = "hackathon/stanford-ml-phd-eigentrust"
        title = "[Hackathon] stanford-ml-phd: EigenTrust plugin"
        assert infer_persona(ref, title) == "stanford-ml-phd"

    def test_persona_non_hackathon(self) -> None:
        assert infer_persona("main") == ""
        assert infer_persona("feature/foo") == ""

    def test_layer(self) -> None:
        assert infer_layer("[Hackathon] EigenTrust plugin", "trust layer") == "trust"
        assert infer_layer("payments thing", "htlc") == "payments"
        assert infer_layer("nothing relevant", "") == "unknown"


# --------------------------------------------------------------------------- #
# JSON schema round-trip
# --------------------------------------------------------------------------- #


class TestSchemaRoundTrip:
    def test_judge_result_to_json_and_back(self) -> None:
        verdicts = [_verdict(0, 3), _verdict(1, 4), _verdict(2, 5)]
        result = aggregate(verdicts, _ctx(), model="m", persona="harvard-phd")
        as_dict = result.to_dict()
        # JSON round-trips cleanly.
        roundtripped = json.loads(json.dumps(as_dict))
        assert roundtripped["pr"] == 1
        assert roundtripped["rubric_version"] == RUBRIC_VERSION
        for dim in DIMENSIONS:
            assert dim in roundtripped["scores"]
        assert len(roundtripped["judges"]) == 3
        assert roundtripped["model"] == "m"

    def test_load_existing_handles_missing(self, tmp_path: Path) -> None:
        existing = load_existing(tmp_path / "nope.json")
        assert existing["version"] == 1
        assert existing["submissions"] == []

    def test_load_existing_handles_bad_json(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.json"
        path.write_text("{not json", encoding="utf-8")
        existing = load_existing(path)
        assert existing["submissions"] == []


# --------------------------------------------------------------------------- #
# Mock judge call (full judge_pr flow with no Anthropic SDK)
# --------------------------------------------------------------------------- #


class _FakeClient:
    """A fake _JudgeClient that returns a canned JSON verdict.

    Example::

        client = _FakeClient([{"correctness": 5, ...}, ...])
    """

    def __init__(self, score_payloads: list[dict[str, int]]) -> None:
        self._payloads = score_payloads
        self._i = 0

    async def judge(self, *, system_blocks: list[dict[str, Any]], user: str) -> str:
        del system_blocks, user
        scores = self._payloads[self._i % len(self._payloads)]
        self._i += 1
        return json.dumps(
            {"scores": scores, "rationale": "Mock rationale, deterministic. All looks correct."}
        )


class TestJudgePrEndToEnd:
    def test_mock_judges_aggregate(self) -> None:
        payloads = [
            dict.fromkeys(DIMENSIONS, 5),
            dict.fromkeys(DIMENSIONS, 3),
            dict.fromkeys(DIMENSIONS, 4),
        ]
        client = _FakeClient(payloads)
        ctx = _ctx(number=42, head_ref="hackathon/test-persona-foo")
        result = asyncio.run(
            judge_pr(
                42,
                n_judges=3,
                model="claude-opus-4-7",
                client=client,
                ctx=ctx,
            )
        )
        assert isinstance(result, JudgeResult)
        assert result.pr_number == 42
        assert result.rubric_version == RUBRIC_VERSION
        for dim in DIMENSIONS:
            assert result.medians[dim] == 4.0
        assert result.total_median == 24.0
        assert "test-persona" in result.consensus

    def test_mock_judge_client_deterministic(self) -> None:
        client = MockJudgeClient(judge_id=0, head_sha="abc123")
        raw1 = asyncio.run(client.judge(system_blocks=[], user="hello"))
        raw2 = asyncio.run(client.judge(system_blocks=[], user="hello"))
        assert raw1 == raw2  # deterministic
        data = json.loads(raw1)
        for dim in DIMENSIONS:
            assert 1 <= data["scores"][dim] <= 5

    def test_n_judges_zero_rejected(self) -> None:
        with pytest.raises(ValueError, match="n_judges"):
            asyncio.run(
                judge_pr(
                    1,
                    n_judges=0,
                    client=_FakeClient([dict.fromkeys(DIMENSIONS, 3)]),
                    ctx=_ctx(),
                )
            )

    def test_one_judge_errors_does_not_sink_run(self) -> None:
        class _MixedClient:
            def __init__(self) -> None:
                self._i = 0

            async def judge(self, *, system_blocks: list[dict[str, Any]], user: str) -> str:
                del system_blocks, user
                self._i += 1
                if self._i == 2:
                    raise RuntimeError("simulated transient failure")
                return json.dumps(
                    {
                        "scores": dict.fromkeys(DIMENSIONS, 4),
                        "rationale": "fine, fine.",
                    }
                )

        result = asyncio.run(
            judge_pr(1, n_judges=3, client=_MixedClient(), ctx=_ctx()),
        )
        # Two healthy judges, one error: medians come from the healthy ones.
        for dim in DIMENSIONS:
            assert result.medians[dim] == 4.0
        assert any(j.error is not None for j in result.judges)
        assert any(j.error is None for j in result.judges)


# --------------------------------------------------------------------------- #
# Provider factory + OpenAI provider (mocked)
# --------------------------------------------------------------------------- #


class TestMakeProvider:
    def test_anthropic_returns_anthropic_provider(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-anthropic-key")
        provider = make_provider("anthropic")
        assert isinstance(provider, AnthropicProvider)

    def test_openai_returns_openai_provider(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPENAI_API_KEY", "test-openai-key")
        provider = make_provider("openai")
        assert isinstance(provider, OpenAIProvider)

    def test_openai_uppercase_case_insensitive(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPENAI_API_KEY", "test-openai-key")
        provider = make_provider("OpenAI")
        assert isinstance(provider, OpenAIProvider)

    def test_unknown_provider_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown judge provider"):
            make_provider("palm")

    def test_openai_missing_key_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        with pytest.raises(RuntimeError, match="OPENAI_API_KEY"):
            make_provider("openai")

    def test_anthropic_missing_key_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY"):
            make_provider("anthropic")

    def test_default_model_for(self) -> None:
        assert default_model_for("anthropic") == DEFAULT_ANTHROPIC_MODEL
        assert default_model_for("openai") == DEFAULT_OPENAI_MODEL
        with pytest.raises(ValueError, match="Unknown judge provider"):
            default_model_for("nope")


class _FakeOpenAIMessage:
    def __init__(self, content: str) -> None:
        self.content = content


class _FakeOpenAIChoice:
    def __init__(self, content: str) -> None:
        self.message = _FakeOpenAIMessage(content)


class _FakeOpenAIResponse:
    def __init__(self, content: str) -> None:
        self.choices = [_FakeOpenAIChoice(content)]


class _FakeOpenAICompletions:
    """Records the create() kwargs so tests can assert on them."""

    def __init__(self, content: str) -> None:
        self._content = content
        self.calls: list[dict[str, Any]] = []

    async def create(self, **kwargs: Any) -> _FakeOpenAIResponse:
        self.calls.append(kwargs)
        return _FakeOpenAIResponse(self._content)


class _FakeOpenAIChat:
    def __init__(self, content: str) -> None:
        self.completions = _FakeOpenAICompletions(content)


class _FakeOpenAIClient:
    def __init__(self, content: str) -> None:
        self.chat = _FakeOpenAIChat(content)


class TestOpenAIProvider:
    def test_openai_provider_judge_uses_chat_completions(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("OPENAI_API_KEY", "test-openai-key")
        provider = OpenAIProvider(model="gpt-5.5")
        fake = _FakeOpenAIClient(
            json.dumps(
                {
                    "scores": dict.fromkeys(DIMENSIONS, 4),
                    "rationale": "ok.",
                }
            )
        )
        # Inject the fake SDK client directly to bypass network init.
        provider._client = fake  # pyright: ignore[reportPrivateUsage]
        raw = asyncio.run(
            provider.judge(
                system_blocks=[{"type": "text", "text": "RUBRIC"}],
                user="user content",
            )
        )
        parsed = json.loads(raw)
        assert parsed["scores"]["correctness"] == 4
        # Confirm the kwargs we care about made it to the SDK.
        assert len(fake.chat.completions.calls) == 1
        call = fake.chat.completions.calls[0]
        assert call["model"] == "gpt-5.5"
        # gpt-5.x models reject explicit temperature kwargs; the provider must
        # omit the kwarg for these models so the default (1) is used.
        assert "temperature" not in call
        assert call["response_format"] == {"type": "json_object"}
        # System message is flattened from blocks; user message is verbatim.
        msgs = call["messages"]
        assert msgs[0]["role"] == "system"
        assert "RUBRIC" in msgs[0]["content"]
        assert msgs[1] == {"role": "user", "content": "user content"}

    def test_openai_provider_passes_temperature_for_non_gpt5_models(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # gpt-4o and earlier accept explicit temperature; we send 0.0 for determinism.
        monkeypatch.setenv("OPENAI_API_KEY", "test-openai-key")
        provider = OpenAIProvider(model="gpt-4o")
        fake = _FakeOpenAIClient(
            json.dumps({"scores": dict.fromkeys(DIMENSIONS, 3), "rationale": "ok."})
        )
        provider._client = fake  # pyright: ignore[reportPrivateUsage]
        asyncio.run(
            provider.judge(
                system_blocks=[{"type": "text", "text": "RUBRIC"}],
                user="user content",
            )
        )
        call = fake.chat.completions.calls[0]
        assert call["model"] == "gpt-4o"
        assert call["temperature"] == 0.0

    def test_openai_provider_flatten_multi_block_system(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("OPENAI_API_KEY", "test-openai-key")
        provider = OpenAIProvider(model="gpt-5.5")
        fake = _FakeOpenAIClient("{}")
        provider._client = fake  # pyright: ignore[reportPrivateUsage]
        asyncio.run(
            provider.judge(
                system_blocks=[
                    {"type": "text", "text": "BLOCK ONE"},
                    {"type": "text", "text": "BLOCK TWO"},
                ],
                user="u",
            )
        )
        system_msg = fake.chat.completions.calls[0]["messages"][0]["content"]
        assert "BLOCK ONE" in system_msg
        assert "BLOCK TWO" in system_msg

    def test_openai_provider_end_to_end_via_judge_pr(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """`judge_pr(..., client=OpenAIProvider(...))` aggregates correctly."""
        monkeypatch.setenv("OPENAI_API_KEY", "test-openai-key")
        provider = OpenAIProvider(model="gpt-5.5")
        fake = _FakeOpenAIClient(
            json.dumps(
                {
                    "scores": dict.fromkeys(DIMENSIONS, 5),
                    "rationale": "Stellar.",
                }
            )
        )
        provider._client = fake  # pyright: ignore[reportPrivateUsage]
        ctx = _ctx(number=99, head_ref="hackathon/openai-llm-foo")
        result = asyncio.run(
            judge_pr(
                99,
                n_judges=2,
                model="gpt-5.5",
                client=provider,
                ctx=ctx,
            )
        )
        # The Anthropic-shape JSON schema is preserved end-to-end.
        assert isinstance(result, JudgeResult)
        assert result.pr_number == 99
        for dim in DIMENSIONS:
            assert result.medians[dim] == 5.0
        assert result.total_median == 30.0
        as_dict = result.to_dict()
        assert as_dict["model"] == "gpt-5.5"
        assert as_dict["rubric_version"] == RUBRIC_VERSION


class TestJudgeTelemetry:
    def test_log_judge_usage_stderr(self, capsys: pytest.CaptureFixture[str]) -> None:
        from types import SimpleNamespace

        response = SimpleNamespace(usage=SimpleNamespace(input_tokens=100, output_tokens=50))
        log_judge_usage(provider="anthropic", model="claude-opus", response=response, judge_id=2)
        err = capsys.readouterr().err
        assert "nest-llm-telemetry" in err
        assert "judge_id=2" in err
        assert "input_tokens=100" in err

    def test_log_judge_usage_disabled(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from types import SimpleNamespace

        monkeypatch.setenv("NEST_LLM_TELEMETRY", "0")
        response = SimpleNamespace(usage=SimpleNamespace(input_tokens=1, output_tokens=1))
        log_judge_usage(provider="openai", model="gpt", response=response)
        assert capsys.readouterr().err == ""


# --------------------------------------------------------------------------- #
# Live marker — only runs with `-m live`
# --------------------------------------------------------------------------- #


@pytest.mark.live
def test_live_anthropic_call() -> None:  # pragma: no cover - requires real API key
    """End-to-end smoke against the real Anthropic API.

    Skipped unless ``pytest -m live`` is passed and ANTHROPIC_API_KEY is set.

    Example::

        ANTHROPIC_API_KEY=... uv run pytest -m live scripts/judge/tests/
    """
    import os

    if not os.environ.get("ANTHROPIC_API_KEY"):
        pytest.skip("ANTHROPIC_API_KEY not set")
    ctx = _ctx(diff="diff --git a/foo b/foo\n+print('hi')\n", body="trivial")
    result = asyncio.run(judge_pr(0, n_judges=1, ctx=ctx))
    for dim in DIMENSIONS:
        assert 1 <= int(result.medians[dim]) <= 5
