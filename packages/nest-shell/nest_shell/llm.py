# SPDX-License-Identifier: Apache-2.0
"""LLM backend abstraction for shell agents.

Example::

    backend = OpenAIBackend(model="gpt-4o-mini")
    response = await backend.complete(messages)
"""

from __future__ import annotations

import warnings
from collections.abc import Awaitable, Callable
from typing import Any, Protocol, cast, runtime_checkable

from nest_shell.telemetry import log_anthropic_usage, log_openai_usage


@runtime_checkable
class LLMBackend(Protocol):
    """Protocol for LLM completion backends.

    Example::

        class MyBackend:
            async def complete(self, messages):
                return "I'll buy that for 50 credits."
    """

    async def complete(self, messages: list[dict[str, str]]) -> str:
        """Send messages to the LLM and return the assistant response text.

        Example::

            response = await backend.complete([{"role": "user", "content": "hello"}])
        """
        ...


class OpenAIBackend:
    """LLM backend using the OpenAI SDK.

    Reads API key from ``OPENAI_API_KEY`` environment variable.

    Example::

        backend = OpenAIBackend(model="gpt-4o-mini", temperature=0.7)
        response = await backend.complete(messages)
    """

    def __init__(
        self,
        model: str = "gpt-4o-mini",
        temperature: float = 0.7,
        max_tokens: int = 256,
        api_key: str | None = None,
    ) -> None:
        self._model = model
        self._temperature = temperature
        self._max_tokens = max_tokens
        self._api_key = api_key  # None = use env var
        self._client: Any | None = None

    def _get_client(self) -> Any:
        if self._client is None:
            import openai  # pyright: ignore[reportMissingModuleSource]

            self._client = cast(
                "Any",
                openai.AsyncOpenAI(api_key=self._api_key),  # pyright: ignore[reportUnknownMemberType]
            )
        return cast("Any", self._client)

    async def complete(self, messages: list[dict[str, str]]) -> str:
        client = self._get_client()
        response: Any = await client.chat.completions.create(
            model=self._model,
            messages=messages,
            temperature=self._temperature,
            max_tokens=self._max_tokens,
        )
        log_openai_usage(model=self._model, response=response, context="shell")
        return str(response.choices[0].message.content or "")


class AnthropicBackend:
    """LLM backend using the Anthropic SDK.

    Reads API key from ``ANTHROPIC_API_KEY`` environment variable.

    Example::

        backend = AnthropicBackend(model="claude-sonnet-4-20250514")
        response = await backend.complete(messages)
    """

    def __init__(
        self,
        model: str = "claude-sonnet-4-20250514",
        temperature: float = 0.7,
        max_tokens: int = 256,
        api_key: str | None = None,
    ) -> None:
        self._model = model
        self._temperature = temperature
        self._max_tokens = max_tokens
        self._api_key = api_key
        self._client: Any | None = None

    def _get_client(self) -> Any:
        if self._client is None:
            import anthropic  # pyright: ignore[reportMissingImports]

            self._client = cast(
                "Any",
                anthropic.AsyncAnthropic(api_key=self._api_key),  # pyright: ignore[reportUnknownVariableType,reportUnknownMemberType]
            )
        return cast("Any", self._client)

    async def complete(self, messages: list[dict[str, str]]) -> str:
        client = self._get_client()
        # Extract system message; Anthropic requires it as a separate parameter.
        system = ""
        chat_messages: list[dict[str, str]] = []
        for m in messages:
            if m["role"] == "system":
                system = m["content"]
            else:
                chat_messages.append(m)
        response: Any = await client.messages.create(
            model=self._model,
            system=system,
            messages=chat_messages,
            temperature=self._temperature,
            max_tokens=self._max_tokens,
        )
        log_anthropic_usage(model=self._model, response=response, context="shell")
        content_blocks = cast("list[Any]", getattr(response, "content", []))
        block = content_blocks[0] if content_blocks else None
        return str(getattr(block, "text", "")) if block else ""


class LiteLLMBackend:
    """LLM backend using litellm for multi-provider support.

    .. deprecated::
        Use :class:`OpenAIBackend` or :class:`AnthropicBackend` instead.

    Example::

        backend = LiteLLMBackend(model="gpt-4o-mini", temperature=0.7)
        response = await backend.complete(messages)
    """

    def __init__(
        self,
        model: str = "gpt-4o-mini",
        temperature: float = 0.7,
        max_tokens: int = 256,
    ) -> None:
        warnings.warn(
            "LiteLLMBackend is deprecated; use OpenAIBackend or AnthropicBackend instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        self._model = model
        self._temperature = temperature
        self._max_tokens = max_tokens

    async def complete(self, messages: list[dict[str, str]]) -> str:
        import litellm  # pyright: ignore[reportMissingImports]

        acompletion = cast(
            "Callable[..., Awaitable[Any]]",
            litellm.acompletion,  # pyright: ignore[reportUnknownMemberType]
        )
        response = await acompletion(
            model=self._model,
            messages=messages,
            temperature=self._temperature,
            max_tokens=self._max_tokens,
        )
        choices = cast("list[Any]", getattr(response, "choices", []))
        if choices:
            msg = getattr(choices[0], "message", None)
            content: str = str(getattr(msg, "content", "") or "") if msg else ""
            return content
        return ""


class MockLLMBackend:
    """Deterministic mock backend for testing without API keys.

    Returns canned responses based on simple keyword matching.

    Example::

        backend = MockLLMBackend()
        response = await backend.complete([{"role": "user", "content": "buy request"}])
    """

    def __init__(self, responses: dict[str, str] | None = None) -> None:
        self._responses = responses or {}
        self._call_count = 0

    @property
    def call_count(self) -> int:
        return self._call_count

    async def complete(self, messages: list[dict[str, str]]) -> str:
        self._call_count += 1
        last_msg = messages[-1]["content"] if messages else ""

        for keyword, response in self._responses.items():
            if keyword in last_msg:
                return response

        if "buy:" in last_msg or "purchase" in last_msg.lower():
            return "ACTION: send\nTO: {sender}\nMESSAGE: sold:product:50"
        if "sold:" in last_msg:
            return "ACTION: send\nTO: {sender}\nMESSAGE: buy:product-next:60"
        if "reject:" in last_msg:
            return "ACTION: send\nTO: {sender}\nMESSAGE: buy:product-retry:70"

        return "ACTION: none"
