# SPDX-License-Identifier: Apache-2.0
"""Optional stderr telemetry for LLM API usage."""

from __future__ import annotations

import os
import sys
from typing import Any


def llm_telemetry_enabled() -> bool:
    """Return False when ``NEST_LLM_TELEMETRY=0``."""
    return os.environ.get("NEST_LLM_TELEMETRY", "1") != "0"


def log_llm_usage(
    *,
    provider: str,
    model: str,
    input_tokens: int | None = None,
    output_tokens: int | None = None,
    context: str = "",
) -> None:
    """Log token usage to stderr for cost/observability debugging."""
    if not llm_telemetry_enabled():
        return
    parts = [f"nest-llm-telemetry provider={provider} model={model}"]
    if input_tokens is not None:
        parts.append(f"input_tokens={input_tokens}")
    if output_tokens is not None:
        parts.append(f"output_tokens={output_tokens}")
    if context:
        parts.append(f"context={context}")
    print(" ".join(parts), file=sys.stderr)


def log_openai_usage(*, model: str, response: Any, context: str = "") -> None:
    usage = getattr(response, "usage", None)
    if usage is None:
        log_llm_usage(provider="openai", model=model, context=context)
        return
    log_llm_usage(
        provider="openai",
        model=model,
        input_tokens=getattr(usage, "prompt_tokens", None),
        output_tokens=getattr(usage, "completion_tokens", None),
        context=context,
    )


def log_anthropic_usage(*, model: str, response: Any, context: str = "") -> None:
    usage = getattr(response, "usage", None)
    if usage is None:
        log_llm_usage(provider="anthropic", model=model, context=context)
        return
    log_llm_usage(
        provider="anthropic",
        model=model,
        input_tokens=getattr(usage, "input_tokens", None),
        output_tokens=getattr(usage, "output_tokens", None),
        context=context,
    )
