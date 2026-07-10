# SPDX-License-Identifier: Apache-2.0
"""Rate limits and token budgets for the hackathon judge panel."""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass, field


class JudgeLimitError(RuntimeError):
    """Raised when a judge call would exceed configured limits."""


def _parse_positive_int(name: str) -> int | None:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return None
    value = int(raw)
    if value < 1:
        msg = f"{name} must be >= 1, got {value}"
        raise ValueError(msg)
    return value


def judge_max_calls() -> int | None:
    """Return ``NEST_JUDGE_MAX_CALLS`` when set (total API calls per process)."""
    return _parse_positive_int("NEST_JUDGE_MAX_CALLS")


def judge_token_budget() -> int | None:
    """Return ``NEST_JUDGE_TOKEN_BUDGET`` when set (cumulative input+output tokens)."""
    return _parse_positive_int("NEST_JUDGE_TOKEN_BUDGET")


@dataclass
class JudgeBudget:
    """Tracks judge API usage against optional env limits."""

    calls: int = 0
    tokens_used: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

def before_call(self) -> None:
    max_calls = judge_max_calls()
    token_budget = judge_token_budget()
    with self._lock:
        if token_budget is not None and self.tokens_used >= token_budget:
            raise JudgeLimitError(
                f"judge token budget reached ({self.tokens_used}/{token_budget}); "
                "raise NEST_JUDGE_TOKEN_BUDGET or unset to disable"
            )
        if max_calls is not None and self.calls >= max_calls:
            raise JudgeLimitError(
                f"judge call limit reached ({self.calls}/{max_calls}); "
                "raise NEST_JUDGE_MAX_CALLS or unset to disable"
            )
        self.calls += 1
    def complete_call(
        self,
        *,
        input_tokens: int | None = None,
        output_tokens: int | None = None,
    ) -> None:
        if input_tokens is not None or output_tokens is not None:
            self.record_tokens(input_tokens, output_tokens)

    def record_tokens(self, input_tokens: int | None, output_tokens: int | None) -> None:
        token_budget = judge_token_budget()
        with self._lock:
            self.tokens_used += max(0, input_tokens or 0) + max(0, output_tokens or 0)
            if token_budget is not None and self.tokens_used > token_budget:
                raise JudgeLimitError(
                    f"judge token budget exceeded ({self.tokens_used}/{token_budget}); "
                    "raise NEST_JUDGE_TOKEN_BUDGET or unset to disable"
                )


_GLOBAL_BUDGET = JudgeBudget()


def global_judge_budget() -> JudgeBudget:
    return _GLOBAL_BUDGET


def reset_judge_budget() -> None:
    """Reset counters (for tests)."""
    _GLOBAL_BUDGET.calls = 0
    _GLOBAL_BUDGET.tokens_used = 0
