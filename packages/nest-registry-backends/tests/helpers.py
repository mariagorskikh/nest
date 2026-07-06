# SPDX-License-Identifier: Apache-2.0
"""Shared test helpers for nest-registry-backends.

Provides:
* :func:`make_card` — construct ``AgentCard`` instances concisely.
* :class:`AsyncpgShim` — a minimal asyncpg-pool-compatible shim backed by
  ``aiosqlite`` so that :class:`CloudSqlRegistry` can be tested without a
  real PostgreSQL server.  The shim translates the PostgreSQL-flavoured SQL
  in the registry (``$1``-style placeholders, ``JSONB``, ``TEXT[]``,
  ``TIMESTAMPTZ``, ``NOW()``, ``ON CONFLICT ... DO UPDATE``) to SQLite-
  compatible equivalents.  The GIN ``@>`` array-containment operator is
  handled in Python rather than in SQL.
"""

from __future__ import annotations

import json
import re
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Any

from nest_sdk import AgentCard, AgentId

# ---------------------------------------------------------------------------
# AgentCard factory
# ---------------------------------------------------------------------------


def make_card(
    agent_id: str,
    *,
    name: str | None = None,
    caps: list[str] | None = None,
    endpoint: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> AgentCard:
    """Return an :class:`AgentCard` with sensible defaults.

    Example::

        card = make_card("a1", caps=["sell"], metadata={"tier": "gold"})
    """
    return AgentCard(
        agent_id=AgentId(agent_id),
        name=name or agent_id,
        capabilities=caps or [],
        endpoint=endpoint,
        metadata=metadata or {},
    )


# ---------------------------------------------------------------------------
# SQLite-backed asyncpg shim
# ---------------------------------------------------------------------------

_SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS nest_agents (
    agent_id     TEXT PRIMARY KEY,
    card         TEXT NOT NULL,
    capabilities TEXT NOT NULL DEFAULT '',
    expires_at   TEXT
);
CREATE INDEX IF NOT EXISTS nest_agents_expires_idx
    ON nest_agents (expires_at)
    WHERE expires_at IS NOT NULL;
"""


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _pg_to_sqlite_basic(sql: str) -> str:
    """Strip PostgreSQL-specific syntax that SQLite doesn't understand."""
    # Remove all ::type casts (e.g. ::jsonb, ::text[], ::interval)
    sql = re.sub(r"::\w+(\[\])?", "", sql)
    # Replace $N placeholders with ?
    sql = re.sub(r"\$\d+", "?", sql)
    return sql


class _Row:
    """Dict-like row returned by the SQLite shim."""

    def __init__(self, mapping: dict[str, Any]) -> None:
        self._data = mapping

    def __getitem__(self, key: str) -> Any:
        return self._data[key]

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)


class _ShimConn:
    """asyncpg-shaped connection wrapping an ``aiosqlite`` connection."""

    def __init__(self, conn: Any) -> None:
        self._conn = conn

    def _bind(self, args: tuple[Any, ...]) -> tuple[Any, ...]:
        """Convert Python lists (capabilities) to comma-separated strings."""
        out: list[Any] = []
        for a in args:
            if isinstance(a, list):
                out.append(",".join(str(x) for x in a))  # pyright: ignore[reportUnknownArgumentType,reportUnknownVariableType]
            else:
                out.append(a)
        return tuple(out)

    async def execute(self, sql: str, *args: Any) -> None:
        """Execute a DDL or DML statement, translating PG syntax to SQLite."""
        stripped = sql.strip().upper()

        # Translate CREATE TABLE / CREATE INDEX blocks.
        if stripped.startswith("CREATE"):
            sqlite_sql = (
                sql.replace("JSONB", "TEXT")
                .replace("TEXT[]", "TEXT")
                .replace("TIMESTAMPTZ", "TEXT")
                # Remove partial index WHERE clause (not supported in SQLite)
                .replace("WHERE expires_at IS NOT NULL", "")
            )
            # aiosqlite.execute() only accepts a single statement.
            # Split on ";" and run each non-empty, non-GIN statement individually.
            stmts = [s.strip() for s in sqlite_sql.split(";") if s.strip()]
            for stmt in stmts:
                if "USING GIN" in stmt:
                    continue
                try:
                    await self._conn.execute(stmt)
                    await self._conn.commit()
                except Exception:
                    pass
            return

        # Rewrite INSERT ... ON CONFLICT ... DO UPDATE as INSERT OR REPLACE.
        if "ON CONFLICT" in sql and "DO UPDATE" in sql:
            await self._upsert(sql, *args)
            return

        # Replace NOW() with the current timestamp.
        now = _now_iso()
        converted = _pg_to_sqlite_basic(sql).replace("'__NOW__'", f"'{now}'")
        # Also inline NOW() that wasn't pre-replaced.
        converted = converted.replace("NOW()", f"'{now}'")

        await self._conn.execute(converted, self._bind(args))
        await self._conn.commit()

    async def _upsert(self, sql: str, *args: Any) -> None:
        """Rewrite INSERT ... ON CONFLICT ... DO UPDATE as INSERT OR REPLACE."""
        bound = self._bind(args)
        now = _now_iso()

        if len(bound) == 4:
            # With TTL: args are (agent_id, card_json, caps_csv, ttl_secs)
            agent_id, card_json, caps_csv, ttl_secs = bound
            expires_at = (datetime.now(UTC) + timedelta(seconds=float(ttl_secs))).isoformat()
            await self._conn.execute(
                "INSERT OR REPLACE INTO nest_agents (agent_id, card, capabilities, expires_at)"
                " VALUES (?, ?, ?, ?)",
                (agent_id, card_json, caps_csv, expires_at),
            )
        elif len(bound) == 3:
            # Without TTL: args are (agent_id, card_json, caps_csv)
            agent_id, card_json, caps_csv = bound
            await self._conn.execute(
                "INSERT OR REPLACE INTO nest_agents (agent_id, card, capabilities, expires_at)"
                " VALUES (?, ?, ?, NULL)",
                (agent_id, card_json, caps_csv),
            )
        else:
            # Fallback: try to translate generically.
            converted = _pg_to_sqlite_basic(sql).replace("NOW()", f"'{now}'")
            converted = re.sub(
                r"INSERT INTO (\w+) .* ON CONFLICT.*",
                r"INSERT OR REPLACE INTO \1",
                converted,
                flags=re.DOTALL,
            )
            await self._conn.execute(converted, bound)

        await self._conn.commit()

    async def fetch(self, sql: str, *args: Any) -> list[_Row]:
        """Fetch rows, handling the PG @> capability operator in Python."""
        caps_filter: list[str] = []
        clean_sql = sql

        # Detect the @> array-containment operator used by CloudSqlRegistry.
        # Strip the clause from the SQL; apply the filter in Python post-fetch.
        if "@>" in sql:
            # First positional arg is the capability list (a Python list).
            caps_filter = list(args[0]) if args else []
            args = args[1:]
            # Strip `AND capabilities @> $N::text[]` — the cast is still present.
            clean_sql = re.sub(
                r"\s+AND\s+capabilities\s+@>\s+\$\d+(?:::\w+(?:\[\])?)?",
                "",
                sql,
                flags=re.IGNORECASE,
            )

        now = _now_iso()
        converted = (
            _pg_to_sqlite_basic(clean_sql)
            .replace("'__NOW__'", f"'{now}'")
            .replace("NOW()", f"'{now}'")
        )
        cursor = await self._conn.execute(converted, self._bind(args))
        rows = await cursor.fetchall()
        col_names: list[str] = [d[0] for d in cursor.description or []]  # pyright: ignore[reportUnknownVariableType,reportUnknownMemberType]

        result: list[_Row] = []
        for row in rows:
            mapping: dict[str, Any] = dict(zip(col_names, row, strict=False))  # pyright: ignore[reportUnknownArgumentType]
            if caps_filter:
                # The query selects only `card` (JSONB); parse capabilities from it.
                raw_card = mapping.get("card") or "{}"
                try:
                    card_data = json.loads(raw_card)
                    stored_caps: list[str] = card_data.get("capabilities", [])
                except (json.JSONDecodeError, TypeError):
                    stored_caps = []
                if not all(c in stored_caps for c in caps_filter):
                    continue
            result.append(_Row(mapping))
        return result

    async def fetchrow(self, sql: str, *args: Any) -> _Row | None:
        rows = await self.fetch(sql, *args)
        return rows[0] if rows else None


class AsyncpgShim:
    """In-memory asyncpg pool shim backed by SQLite (via ``aiosqlite``).

    Use as a pool argument to :class:`CloudSqlRegistry`; call
    :meth:`close` explicitly when done.

    Example::

        pool = await AsyncpgShim.create()
        reg = CloudSqlRegistry(pool)
        await reg.migrate()
        await pool.close()
    """

    def __init__(self, conn: Any) -> None:
        self._conn = conn

    @classmethod
    async def create(cls) -> AsyncpgShim:
        """Create an in-memory SQLite connection (no file on disk)."""
        import aiosqlite  # type: ignore[import-untyped]

        conn = await aiosqlite.connect(":memory:")
        return cls(conn)

    @asynccontextmanager
    async def acquire(self) -> AsyncGenerator[_ShimConn, None]:
        """Yield a :class:`_ShimConn` for use inside ``CloudSqlRegistry``."""
        yield _ShimConn(self._conn)

    async def close(self) -> None:
        await self._conn.close()
