# SPDX-License-Identifier: Apache-2.0
"""Shared HTTP retry/backoff helpers for distributed simulation bridges."""

from __future__ import annotations

import asyncio
import random

from nest_core.sim.http_config import http_retry_base_delay, http_retry_jitter


async def http_retry_sleep(attempt: int, rng: random.Random | None = None) -> None:
    """Sleep with linear backoff and optional jitter before an HTTP retry."""
    base = http_retry_base_delay()
    jitter = http_retry_jitter()
    delay = base * (attempt + 1)
    if jitter > 0:
        source = rng or random.Random(0)
        delay += source.uniform(0.0, jitter)
    if delay > 0:
        await asyncio.sleep(delay)
