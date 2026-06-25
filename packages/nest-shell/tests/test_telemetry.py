# SPDX-License-Identifier: Apache-2.0
"""Tests for LLM telemetry logging."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from nest_shell.telemetry import log_anthropic_usage, log_llm_usage, log_openai_usage


class TestTelemetry:
    def test_log_llm_usage_stderr(self, capsys: pytest.CaptureFixture[str]) -> None:
        log_llm_usage(provider="openai", model="gpt-4o-mini", input_tokens=10, output_tokens=5)
        err = capsys.readouterr().err
        assert "nest-llm-telemetry" in err
        assert "input_tokens=10" in err
        assert "output_tokens=5" in err

    def test_disabled_via_env(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("NEST_LLM_TELEMETRY", "0")
        log_llm_usage(provider="openai", model="m", input_tokens=1, output_tokens=1)
        assert capsys.readouterr().err == ""

    def test_log_openai_usage(self, capsys: pytest.CaptureFixture[str]) -> None:
        response = SimpleNamespace(usage=SimpleNamespace(prompt_tokens=3, completion_tokens=7))
        log_openai_usage(model="gpt-4o", response=response, context="test")
        err = capsys.readouterr().err
        assert "input_tokens=3" in err
        assert "output_tokens=7" in err

    def test_log_anthropic_usage(self, capsys: pytest.CaptureFixture[str]) -> None:
        response = SimpleNamespace(usage=SimpleNamespace(input_tokens=11, output_tokens=22))
        log_anthropic_usage(model="claude", response=response, context="test")
        err = capsys.readouterr().err
        assert "input_tokens=11" in err
        assert "output_tokens=22" in err
