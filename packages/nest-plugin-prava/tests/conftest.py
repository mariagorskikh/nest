# SPDX-License-Identifier: Apache-2.0
"""Shared fixtures.

Contract tests run offline against a mocked console. Sandbox tests need a
running Quartermaster console and move real sandbox money, so they skip
unless ``QUARTERMASTER_CONSOLE_URL`` points at a reachable one.

Helpers are exposed as fixtures rather than module-level functions so the
suite collects correctly no matter which directory pytest is rooted at.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any

import httpx
import pytest

if TYPE_CHECKING:
    from collections.abc import Callable

    Handler = Callable[[httpx.Request], httpx.Response]
    MockClientFactory = Callable[[Handler], httpx.AsyncClient]
    JsonResponseFactory = Callable[[int, dict[str, Any]], httpx.Response]

CONSOLE_ENV = "QUARTERMASTER_CONSOLE_URL"


@pytest.fixture
def mock_client() -> MockClientFactory:
    """Build an AsyncClient whose requests are served by a handler.

    Example::

        client = mock_client(lambda req: httpx.Response(200, json={}))
    """

    def factory(handler: Handler) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(handler))

    return factory


@pytest.fixture
def json_response() -> JsonResponseFactory:
    """Shorthand for building a JSON response.

    Example::

        json_response(402, {"error": {"code": "POLICY_REFUSE", "message": "no"}})
    """

    def factory(status: int, payload: dict[str, Any]) -> httpx.Response:
        return httpx.Response(status, json=payload)

    return factory


@pytest.fixture
def console_url() -> str:
    """Console base URL for live sandbox tests."""
    return os.environ.get(CONSOLE_ENV, "http://localhost:3000").rstrip("/")


@pytest.fixture
def live_console(console_url: str) -> str:
    """Skip the test unless a Quartermaster console is actually reachable."""
    try:
        response = httpx.get(f"{console_url}/api/portfolio", timeout=5.0)
        response.raise_for_status()
    except Exception as exc:  # noqa: BLE001 - any failure means "not available"
        pytest.skip(f"no Quartermaster console at {console_url} ({exc})")
    return console_url
