# SPDX-License-Identifier: Apache-2.0
"""Cloud SQL (PostgreSQL) registry plugin — durable, SQL-backed agent discovery.

This plugin implements the :class:`nest_sdk.Registry` protocol against a
Google Cloud SQL PostgreSQL instance (or any plain ``asyncpg``-compatible
PostgreSQL database).  It replaces the default ``in_memory`` registry with a
schema that persists agent cards across simulation restarts, supports
multi-process simulators that share a single database, and survives process
crashes without losing any registered card.

Design
------
* **Table layout.**  A single ``nest_agents`` table stores the serialised
  ``AgentCard`` as JSONB together with indexed ``capabilities`` and an
  ``expires_at`` timestamp (``NULL`` → immortal; set via ``ttl_seconds``).
* **Lease-based TTL.**  An optional ``ttl_seconds`` argument to the
  constructor causes each ``register`` call to set / refresh ``expires_at``.
  Expired rows are excluded from ``lookup`` results and are pruned lazily on
  the next ``register`` of any agent (``DELETE WHERE expires_at < NOW()``).
* **Subscription.**  The ``subscribe`` generator polls the database on a
  configurable interval and yields newly-registered cards that match the
  query.  This is sufficient for simulation workloads; production deployments
  can swap in a LISTEN/NOTIFY-backed variant.
* **Connection management.**  The class accepts an ``asyncpg`` connection
  pool via the constructor.  A convenience factory
  :func:`connect_cloud_sql` creates a pool via the
  ``google-cloud-sql-connector`` exactly as used in the ``dw-ai-brain`` CFO
  demo.  For plain-PostgreSQL testing (local, CI) the regular
  :func:`connect_postgres` factory skips the Cloud SQL IAM handshake.

Example::

    from nest_registry_backends.cloud_sql import CloudSqlRegistry, connect_postgres

    pool = await connect_postgres("postgresql://user:pw@localhost/testdb")
    registry = CloudSqlRegistry(pool)
    await registry.migrate()
    await registry.register(AgentCard(agent_id=AgentId("a1"), name="Alice"))
    results = await registry.lookup(Query(capabilities=["sell"]))
"""

from __future__ import annotations

import asyncio
import json
import os
from collections.abc import AsyncIterator
from typing import Any

from nest_sdk import AgentCard, AgentId, Query

_SCHEMA_VERSION = 1

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS nest_agents (
    agent_id        TEXT        PRIMARY KEY,
    card            JSONB       NOT NULL,
    capabilities    TEXT[]      NOT NULL DEFAULT '{}',
    expires_at      TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS nest_agents_caps_idx
    ON nest_agents USING GIN (capabilities);
CREATE INDEX IF NOT EXISTS nest_agents_expires_idx
    ON nest_agents (expires_at)
    WHERE expires_at IS NOT NULL;
"""

_DEFAULT_POLL_INTERVAL_S = 1.0
_DEFAULT_TTL_SECONDS: int | None = None


class CloudSqlRegistry:
    """PostgreSQL-backed agent registry compatible with ``nest_sdk.Registry``.

    Parameters
    ----------
    pool:
        An ``asyncpg`` connection pool.  Acquire one via
        :func:`connect_cloud_sql` (GCP) or :func:`connect_postgres` (plain
        PostgreSQL / CI).
    ttl_seconds:
        When set, each ``register`` call sets an ``expires_at`` timestamp
        this many seconds in the future.  ``None`` means cards never expire.
    poll_interval_s:
        Interval in seconds between ``subscribe`` polls.

    Example::

        pool = await connect_postgres("postgresql://localhost/test")
        reg = CloudSqlRegistry(pool)
        await reg.migrate()
    """

    def __init__(
        self,
        pool: Any,
        *,
        ttl_seconds: int | None = _DEFAULT_TTL_SECONDS,
        poll_interval_s: float = _DEFAULT_POLL_INTERVAL_S,
    ) -> None:
        self._pool = pool
        self._ttl = ttl_seconds
        self._poll_interval = poll_interval_s

    # ------------------------------------------------------------------
    # Schema management
    # ------------------------------------------------------------------

    async def migrate(self) -> None:
        """Ensure the ``nest_agents`` table and indexes exist.

        Safe to call multiple times (idempotent DDL).  Call once at
        application startup before any registry operation.

        Example::

            await registry.migrate()
        """
        async with self._pool.acquire() as conn:
            await conn.execute(_CREATE_TABLE)

    # ------------------------------------------------------------------
    # Registry protocol
    # ------------------------------------------------------------------

    async def register(self, card: AgentCard) -> None:
        """Upsert an agent card into the database.

        If the agent already exists the card is overwritten.  When
        ``ttl_seconds`` is set, ``expires_at`` is refreshed.  Expired
        rows for *other* agents are pruned lazily during this call.

        Example::

            await registry.register(AgentCard(agent_id=AgentId("a1"), name="Alice"))
        """
        payload = card.model_dump(mode="json")
        caps = card.capabilities

        async with self._pool.acquire() as conn:
            await conn.execute("DELETE FROM nest_agents WHERE expires_at < NOW()")
            if self._ttl is not None:
                await conn.execute(
                    """
                    INSERT INTO nest_agents (agent_id, card, capabilities, expires_at)
                    VALUES ($1, $2::jsonb, $3::text[], NOW() + ($4 || ' seconds')::interval)
                    ON CONFLICT (agent_id) DO UPDATE
                        SET card         = EXCLUDED.card,
                            capabilities = EXCLUDED.capabilities,
                            expires_at   = EXCLUDED.expires_at
                    """,
                    card.agent_id,
                    json.dumps(payload),
                    caps,
                    str(self._ttl),
                )
            else:
                await conn.execute(
                    """
                    INSERT INTO nest_agents (agent_id, card, capabilities, expires_at)
                    VALUES ($1, $2::jsonb, $3::text[], NULL)
                    ON CONFLICT (agent_id) DO UPDATE
                        SET card         = EXCLUDED.card,
                            capabilities = EXCLUDED.capabilities,
                            expires_at   = NULL
                    """,
                    card.agent_id,
                    json.dumps(payload),
                    caps,
                )

    async def lookup(self, query: Query) -> list[AgentCard]:
        """Return all non-expired agents matching *query*.

        Filtering is performed in SQL when ``capabilities`` are specified
        (GIN index), and falls back to a Python post-filter for
        ``name_pattern`` and ``metadata_filter``.

        Example::

            results = await registry.lookup(Query(capabilities=["sell"]))
        """
        async with self._pool.acquire() as conn:
            if query.capabilities:
                rows = await conn.fetch(
                    """
                    SELECT card FROM nest_agents
                    WHERE (expires_at IS NULL OR expires_at > NOW())
                      AND capabilities @> $1::text[]
                    """,
                    query.capabilities,
                )
            else:
                rows = await conn.fetch(
                    """
                    SELECT card FROM nest_agents
                    WHERE expires_at IS NULL OR expires_at > NOW()
                    """,
                )

        cards = [AgentCard(**json.loads(row["card"])) for row in rows]

        if query.name_pattern:
            cards = [c for c in cards if query.name_pattern in c.name]

        if query.metadata_filter:
            cards = [
                c
                for c in cards
                if all(c.metadata.get(k) == v for k, v in query.metadata_filter.items())
            ]

        return cards

    async def subscribe(self, query: Query) -> AsyncIterator[AgentCard]:
        """Yield new agents matching *query* as they are registered.

        Implemented as a poll loop (interval controlled by
        ``poll_interval_s``).  The generator tracks the set of
        ``agent_id`` values seen so far and yields only *new* arrivals.
        It never terminates; cancel the surrounding task to stop.

        Example::

            async for card in registry.subscribe(Query(capabilities=["sell"])):
                handle(card)
        """
        seen: set[AgentId] = set()
        while True:
            current = await self.lookup(query)
            for card in current:
                if card.agent_id not in seen:
                    seen.add(card.agent_id)
                    yield card
            await asyncio.sleep(self._poll_interval)

    async def deregister(self, agent: AgentId) -> None:
        """Remove an agent from the registry immediately.

        Example::

            await registry.deregister(AgentId("a1"))
        """
        async with self._pool.acquire() as conn:
            await conn.execute(
                "DELETE FROM nest_agents WHERE agent_id = $1",
                agent,
            )

    # ------------------------------------------------------------------
    # Lifecycle helpers
    # ------------------------------------------------------------------

    async def close(self) -> None:
        """Close the underlying connection pool.

        Example::

            await registry.close()
        """
        await self._pool.close()


# ---------------------------------------------------------------------------
# Connection factories
# ---------------------------------------------------------------------------


async def connect_postgres(
    dsn: str,
    *,
    min_size: int = 2,
    max_size: int = 10,
) -> Any:
    """Create an asyncpg pool from a plain PostgreSQL DSN.

    Use this in local development and CI pipelines where the Cloud SQL
    connector is not available.

    Parameters
    ----------
    dsn:
        A ``postgresql://`` connection string.
    min_size / max_size:
        Pool sizing passed directly to :func:`asyncpg.create_pool`.

    Example::

        pool = await connect_postgres("postgresql://user:pw@localhost/testdb")
        registry = CloudSqlRegistry(pool)
        await registry.migrate()
    """
    import asyncpg  # type: ignore[import-untyped]

    return await asyncpg.create_pool(dsn, min_size=min_size, max_size=max_size)  # pyright: ignore[reportUnknownVariableType,reportUnknownMemberType]


async def connect_cloud_sql(
    *,
    instance_connection_name: str | None = None,
    db_user: str | None = None,
    db_name: str | None = None,
    db_password: str | None = None,
    enable_iam_auth: bool = True,
    ip_type: str = "private",
    min_size: int = 2,
    max_size: int = 10,
) -> Any:
    """Create an asyncpg pool via the Google Cloud SQL Python Connector.

    All parameters fall back to environment variables when not specified:

    ==================  ========================
    Parameter           Environment variable
    ==================  ========================
    instance_connection_name  ``INSTANCE_CONNECTION_NAME``
    db_user             ``DB_USER``
    db_name             ``DB_NAME``
    db_password         ``DB_PASSWORD``
    ip_type             ``DB_IP_TYPE`` (``"private"`` or ``"public"``)
    ==================  ========================

    When ``enable_iam_auth`` is ``True`` (the default) the ``db_password``
    is ignored; IAM authentication is used instead.

    Example::

        pool = await connect_cloud_sql(
            instance_connection_name="proj:us-central1:my-instance",
            db_user="nest-sa@project.iam",
            db_name="nest",
        )
    """
    from google.cloud.sql.connector import Connector, IPTypes  # type: ignore[import-untyped]

    conn_name = instance_connection_name or os.environ["INSTANCE_CONNECTION_NAME"]
    user = db_user or os.environ.get("DB_USER", "")
    name = db_name or os.environ.get("DB_NAME", "")
    password = db_password or os.environ.get("DB_PASSWORD", "")

    _ip: Any = (  # pyright: ignore[reportUnknownVariableType]
        IPTypes.PRIVATE if ip_type.lower() == "private" else IPTypes.PUBLIC  # pyright: ignore[reportUnknownMemberType]
    )

    connector: Any = Connector()  # pyright: ignore[reportUnknownVariableType]

    async def _getconn(connection_name: str) -> Any:
        kwargs: dict[str, Any] = {
            "user": user,
            "db": name,
            "enable_iam_auth": enable_iam_auth,
            "ip_type": _ip,
        }
        if not enable_iam_auth:
            kwargs["password"] = password
        return connector.connect(connection_name, "asyncpg", **kwargs)  # pyright: ignore[reportUnknownMemberType,reportUnknownVariableType]

    import asyncpg  # type: ignore[import-untyped]

    pool = await asyncpg.create_pool(  # pyright: ignore[reportUnknownVariableType,reportUnknownMemberType]
        connect=lambda: _getconn(conn_name),
        min_size=min_size,
        max_size=max_size,
    )
    return pool
