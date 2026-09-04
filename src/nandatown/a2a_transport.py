"""Bounded synchronous JSON transport, not a total-deadline or address policy."""

from __future__ import annotations

import json
import math
from contextlib import contextmanager
from typing import Any, Iterator

import httpx

DEFAULT_MAX_RESPONSE_BYTES = 1_048_576
POLICY_ID = "a2a-bounded-json@0.1"
BUDGET_EXCEEDED = (
    "a2a_response_budget_exceeded: selected local byte budget exceeded for this run"
)


class HTTPStatusError(ValueError):
    def __init__(self, status_code: int):
        self.status_code = status_code
        super().__init__(f"a2a_http_status_{status_code}")


def validate_response_budget(value: int | float) -> int:
    # Profiles currently serialize numeric limits as floats; integral floats
    # are valid, but booleans and coercible strings are not byte counts.
    if (isinstance(value, bool) or not isinstance(value, (int, float))
            or (isinstance(value, float) and not math.isfinite(value))
            or value <= 0 or int(value) != value):
        raise ValueError("a2a_invalid_response_budget")
    return int(value)


@contextmanager
def a2a_client(base_url: str, http: httpx.Client | None,
               timeout_seconds: float) -> Iterator[httpx.Client]:
    if http is not None:
        yield http
    else:
        with httpx.Client(
            base_url=base_url, timeout=timeout_seconds,
            follow_redirects=False, trust_env=False,
            transport=httpx.HTTPTransport(retries=0, trust_env=False),
        ) as client:
            yield client


def read_json(client: httpx.Client, method: str, path: str, *,
              max_response_bytes: int, timeout_seconds: float,
              payload: dict[str, Any] | None = None,
              success_statuses: tuple[int, ...] | range = (200,)
              ) -> dict[str, Any]:
    """Count identity bytes before retention/parsing; always close responses.

    A trusted injected transport may already have materialized its response.
    That seam still gets checked, but its earlier allocations are caller-owned.
    """
    try:
        with client.stream(method, path, json=payload,
                           headers={"Accept-Encoding": "identity"},
                           follow_redirects=False,
                           timeout=timeout_seconds) as response:
            if response.status_code not in success_statuses:
                raise HTTPStatusError(response.status_code)
            encoding = response.headers.get("content-encoding", "identity")
            if encoding.strip().lower() != "identity":
                raise ValueError("a2a_unsupported_encoding")
            length = response.headers.get("content-length")
            if length is not None:
                # Invalid/dishonest lengths never replace actual byte counting.
                try:
                    declared_length = int(length)
                except ValueError:
                    declared_length = None
                if declared_length is not None and declared_length > max_response_bytes:
                    raise ValueError(BUDGET_EXCEEDED)
            chunks = ([response.content] if response.is_stream_consumed
                      else response.iter_raw())
            body = bytearray()
            for chunk in chunks:
                if len(chunk) > max_response_bytes - len(body):
                    raise ValueError(BUDGET_EXCEEDED)
                body.extend(chunk)
            try:
                result = json.loads(body)
            except (ValueError, UnicodeError, RecursionError):
                raise ValueError("a2a_invalid_json") from None
            if not isinstance(result, dict):
                raise ValueError("a2a_json_not_object")
            return result
    except httpx.TimeoutException:
        raise ValueError("a2a_timeout") from None
    except httpx.HTTPError:
        raise ValueError("a2a_transport_error") from None


def effective_policy(max_response_bytes: int, timeout_seconds: float, *,
                     injected: bool, profile_budget: bool) -> dict[str, Any]:
    return {
        "policy_id": POLICY_ID,
        "max_response_bytes": max_response_bytes,
        "budget_basis": "profile" if profile_budget else "implementation_ceiling",
        "accept_encoding": "identity",
        "follow_redirects": False,
        "trust_env": "caller_controlled" if injected else False,
        "transport_retries": "caller_controlled" if injected else 0,
        "client_ownership": "injected" if injected else "owned",
        "phase_timeout_seconds": timeout_seconds,
        "total_deadline_seconds": None,
    }
