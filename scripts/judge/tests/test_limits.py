# SPDX-License-Identifier: Apache-2.0
"""Tests for judge rate limits and token budgets."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from scripts.judge.judge_pr import DIMENSIONS, judge_pr
from scripts.judge.limits import JudgeBudget, JudgeLimitError, reset_judge_budget


def _limits_ctx() -> Any:
    from scripts.judge.judge_pr import PRContext

    return PRContext(
        number=1,
        title="test",
        body="body",
        author="alice",
        head_sha="deadbeef",
        head_ref="hackathon/test",
        diff="",
        diff_truncated=False,
        checks_summary="no check runs reported",
    )


class TestJudgeBudget:
    def test_max_calls_blocks(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("NEST_JUDGE_MAX_CALLS", "1")
        budget = JudgeBudget()
        budget.before_call()
        with pytest.raises(JudgeLimitError, match="call limit"):
            budget.before_call()

    def test_token_budget_blocks(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("NEST_JUDGE_TOKEN_BUDGET", "10")
        budget = JudgeBudget()
        with pytest.raises(JudgeLimitError, match="token budget"):
            budget.record_tokens(6, 5)


class TestJudgePrLimits:
    def setup_method(self) -> None:
        reset_judge_budget()

    def test_max_calls_stops_extra_judges(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("NEST_JUDGE_MAX_CALLS", "1")

        class _OneShot:
            async def judge(self, *, system_blocks: list[dict[str, Any]], user: str) -> str:
                import json

                return json.dumps(
                    {
                        "scores": dict.fromkeys(DIMENSIONS, 4),
                        "rationale": "ok",
                    }
                )

        result = asyncio.run(
            judge_pr(1, n_judges=3, client=_OneShot(), ctx=_limits_ctx()),
        )
        errors = [j.error for j in result.judges if j.error]
        assert len(errors) == 2
        assert all("call limit" in (e or "") for e in errors)
        ok = [j for j in result.judges if j.error is None]
        assert len(ok) == 1
