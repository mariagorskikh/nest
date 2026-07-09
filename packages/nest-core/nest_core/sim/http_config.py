# SPDX-License-Identifier: Apache-2.0
"""HTTP settings shared by worker transport and plugin RPC clients."""

from __future__ import annotations

import hmac
import os
import random

from nest_core.scenario import ScenarioConfig


def http_retries() -> int:
    raw = os.environ.get("NEST_HTTP_RETRIES", "10").strip()
    try:
        return max(1, int(raw))
    except ValueError:
        return 10


def http_timeout() -> float:
    raw = os.environ.get("NEST_HTTP_TIMEOUT", "30").strip()
    try:
        return max(0.1, float(raw))
    except ValueError:
        return 30.0


def http_max_body_bytes() -> int:
    raw = os.environ.get("NEST_HTTP_MAX_BODY", str(64 * 1024 * 1024)).strip()
    try:
        return max(1024, int(raw))
    except ValueError:
        return 64 * 1024 * 1024


def http_shared_secret() -> str | None:
    """Optional shared secret for worker HTTP bridges and registry RPC."""
    raw = os.environ.get("NEST_HTTP_SHARED_SECRET", "").strip()
    return raw or None


def http_retry_base_delay() -> float:
    raw = os.environ.get("NEST_HTTP_RETRY_BASE_DELAY", "0.05").strip()
    try:
        return max(0.0, float(raw))
    except ValueError:
        return 0.05


def http_retry_jitter() -> float:
    raw = os.environ.get("NEST_HTTP_RETRY_JITTER", "0.05").strip()
    try:
        return max(0.0, float(raw))
    except ValueError:
        return 0.05


def http_retry_rng() -> random.Random:
    raw = os.environ.get("NEST_HTTP_RETRY_SEED", "0").strip()
    try:
        seed = int(raw)
    except ValueError:
        seed = 0
    return random.Random(seed)


def http_auth_header_name() -> str:
    return os.environ.get("NEST_HTTP_AUTH_HEADER", "X-Nest-Auth").strip() or "X-Nest-Auth"


def http_auth_headers() -> dict[str, str]:
    secret = http_shared_secret()
    if secret is None:
        return {}
    return {http_auth_header_name(): secret}


def http_auth_valid(headers: dict[str, str]) -> bool:
    secret = http_shared_secret()
    if secret is None:
        return True
    header = http_auth_header_name().lower()
    provided = headers.get(header) or ""
    return hmac.compare_digest(provided, secret)


def http_bind_is_exposed(bind_host: str) -> bool:
    return bind_host not in ("127.0.0.1", "localhost", "")


def require_http_shared_secret(config: ScenarioConfig) -> None:
    """Fail fast when distributed HTTP would listen on a non-local bind without auth."""
    needs_secret = config.workers > 1 or http_bind_is_exposed(config.worker_bind)
    if not needs_secret:
        return
    if http_shared_secret() is not None:
        return
    msg = (
        "NEST_HTTP_SHARED_SECRET must be set when workers > 1 or worker_bind "
        f"is not localhost (got worker_bind={config.worker_bind!r}, workers={config.workers})"
    )
    raise ValueError(msg)
