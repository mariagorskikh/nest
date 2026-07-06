# SPDX-License-Identifier: Apache-2.0
"""Shared fixtures for nest-registry-backends tests.

Both the Cloud SQL and Redis suites follow the same fixture pattern:

* A fresh registry instance is created per test (no shared state).
* Live external services are never required; all tests run offline.
* Cloud SQL tests use an in-process SQLite-compatible shim via
  ``aiosqlite`` and a tiny asyncpg-shaped adapter so that the registry
  code is exercised without a real Postgres instance.  The adapter
  exposes only the subset of the asyncpg pool API that
  ``CloudSqlRegistry`` uses (``acquire()`` context-manager returning a
  connection with ``execute``/``fetch``/``fetchrow`` methods).
* Redis tests use ``fakeredis.aioredis.FakeRedis`` — a fully in-memory
  Redis emulator that supports the same API as ``redis.asyncio``.
"""

from __future__ import annotations

import pytest

# ---------------------------------------------------------------------------
# Marks
# ---------------------------------------------------------------------------

# Tests tagged ``live`` require real external services and are skipped by
# default (matching the workspace ``pytest.ini_options`` marker).
live = pytest.mark.live
