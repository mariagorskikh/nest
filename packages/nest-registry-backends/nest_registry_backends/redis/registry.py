# SPDX-License-Identifier: Apache-2.0
"""Redis (Memorystore) registry plugin — low-latency, TTL-native agent discovery.

This plugin implements the :class:`nest_sdk.Registry` protocol against a
Redis or Google Cloud Memorystore for Redis instance.  It is modelled
directly on the agent registry used in the ``dw-ai-brain`` project's
``registry/store.py``, adapted to implement the Nanda Town plugin interface
and to stay free of internal ``dw-ai-brain`` imports.

Design
------
* **Hash per agent.**  Each agent card is stored as a Redis Hash under
  the key ``nest:agent:<agent_id>``.  The hash contains a single ``data``
  field holding the JSON-serialised ``AgentCard``.
* **Capability index.**  For each capability string ``cap``, the agent ID
  is added to the Redis Set ``nest:cap:<cap>``.  Capability-based lookup
  performs an SINTER (set intersection) in Redis — O(N × M) where N is
  the smaller set size and M is the number of capability terms.
* **TTL.**  When ``ttl_seconds`` is set the agent hash and every
  capability set entry are given a matching ``EXPIRE``.
* **Subscription.**  ``subscribe`` polls at a configurable interval and
  yields newly-appearing cards that match the query, identical to the
  Cloud SQL backend.
* **Connection flavours.**
  - :func:`connect_redis` — plain ``redis.asyncio.Redis`` for local dev / CI.
  - :func:`connect_memorystore` — ``RedisCluster`` with GCP IAM token
    auth, matching the ``dw-ai-brain`` ``registry/store.py`` pattern.

Example::

    from nest_registry_backends.redis import RedisRegistry, connect_redis

    client = await connect_redis("redis://localhost:6379")
    registry = RedisRegistry(client)
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

_AGENT_PREFIX = "nest:agent:"
_CAP_PREFIX = "nest:cap:"
_DEFAULT_POLL_INTERVAL_S = 1.0
_DEFAULT_TTL_SECONDS: int | None = None


def _agent_key(agent_id: AgentId) -> str:
    return f"{_AGENT_PREFIX}{agent_id}"


def _cap_key(capability: str) -> str:
    return f"{_CAP_PREFIX}{capability}"


class RedisRegistry:
    """Redis-backed agent registry compatible with ``nest_sdk.Registry``.

    Parameters
    ----------
    client:
        An ``redis.asyncio.Redis`` or ``RedisCluster`` client.  Acquire
        one via :func:`connect_redis` (plain) or
        :func:`connect_memorystore` (GCP Memorystore with IAM).
    ttl_seconds:
        When set, agent keys and capability index sets are given this
        TTL in seconds.  Registering an agent again refreshes the TTL.
        ``None`` means keys never expire.
    poll_interval_s:
        Seconds between ``subscribe`` polls (default 1.0).

    Example::

        client = await connect_redis("redis://localhost:6379")
        reg = RedisRegistry(client)
        await reg.register(AgentCard(agent_id=AgentId("a1"), name="Alice"))
    """

    def __init__(
        self,
        client: Any,
        *,
        ttl_seconds: int | None = _DEFAULT_TTL_SECONDS,
        poll_interval_s: float = _DEFAULT_POLL_INTERVAL_S,
    ) -> None:
        self._r = client
        self._ttl = ttl_seconds
        self._poll_interval = poll_interval_s

    # ------------------------------------------------------------------
    # Registry protocol
    # ------------------------------------------------------------------

    async def register(self, card: AgentCard) -> None:
        """Store an agent card in Redis and update capability indexes.

        Overwrites any existing card for the same ``agent_id``.  When
        ``ttl_seconds`` is set the agent hash and each capability Set
        member receive a refreshed ``EXPIRE``.

        Example::

            await registry.register(AgentCard(agent_id=AgentId("a1"), name="Alice"))
        """
        key = _agent_key(card.agent_id)
        payload = json.dumps(card.model_dump(mode="json"))

        old_raw = await self._r.hget(key, "data")
        old_caps: set[str] = set()
        if old_raw is not None:
            try:
                old_data = json.loads(old_raw)
                old_caps = set(old_data.get("capabilities", []))
            except (json.JSONDecodeError, TypeError):
                pass

        await self._r.hset(key, mapping={"data": payload})
        if self._ttl is not None:
            await self._r.expire(key, self._ttl)

        removed_caps = old_caps - set(card.capabilities)
        cap_ops: list[Any] = []
        for cap in removed_caps:
            cap_ops.append(self._r.srem(_cap_key(cap), card.agent_id))
        for cap in card.capabilities:
            cap_ops.append(self._r.sadd(_cap_key(cap), card.agent_id))
            if self._ttl is not None:
                cap_ops.append(self._r.expire(_cap_key(cap), self._ttl))
        if cap_ops:
            await asyncio.gather(*cap_ops)

    async def lookup(self, query: Query) -> list[AgentCard]:
        """Return agents matching *query* from the Redis index.

        When one or more capabilities are specified, the lookup performs a
        Redis SINTER on the capability Sets.  The result is then
        post-filtered against ``name_pattern`` and ``metadata_filter`` in
        Python (they are uncommon in simulation workloads and not worth a
        secondary index).

        Example::

            results = await registry.lookup(Query(capabilities=["sell"]))
        """
        if query.capabilities:
            cap_keys = [_cap_key(c) for c in query.capabilities]
            if len(cap_keys) == 1:
                agent_ids_raw = await self._r.smembers(cap_keys[0])
            else:
                agent_ids_raw = await self._r.sinter(*cap_keys)
            agent_ids = [
                aid.decode("utf-8") if isinstance(aid, bytes) else aid for aid in agent_ids_raw
            ]
        else:
            agent_ids = await self._scan_all_ids()

        cards: list[AgentCard] = []
        for aid in agent_ids:
            card = await self._fetch_card(AgentId(aid))
            if card is None:
                continue
            if query.name_pattern and query.name_pattern not in card.name:
                continue
            if query.metadata_filter and not all(
                card.metadata.get(k) == v for k, v in query.metadata_filter.items()
            ):
                continue
            cards.append(card)

        return cards

    async def subscribe(self, query: Query) -> AsyncIterator[AgentCard]:
        """Yield newly-registered cards matching *query* as they appear.

        Polls Redis at ``poll_interval_s`` intervals and yields cards
        whose ``agent_id`` has not been seen in previous polls.  Never
        terminates; cancel the enclosing task to stop.

        Example::

            async for card in registry.subscribe(Query(capabilities=["buy"])):
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
        """Remove an agent card and its capability index entries.

        Example::

            await registry.deregister(AgentId("a1"))
        """
        key = _agent_key(agent)
        old_raw = await self._r.hget(key, "data")
        if old_raw is not None:
            try:
                old_data = json.loads(old_raw)
                old_caps: list[str] = old_data.get("capabilities", [])
            except (json.JSONDecodeError, TypeError):
                old_caps = []
            cap_removes = [self._r.srem(_cap_key(c), agent) for c in old_caps]
            if cap_removes:
                await asyncio.gather(*cap_removes)
        await self._r.delete(key)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _fetch_card(self, agent_id: AgentId) -> AgentCard | None:
        """Retrieve and deserialise a single agent card from Redis."""
        raw = await self._r.hget(_agent_key(agent_id), "data")
        if raw is None:
            return None
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return None
        return AgentCard(**data)

    async def _scan_all_ids(self) -> list[str]:
        """SCAN for all ``nest:agent:*`` keys and return the agent IDs."""
        ids: list[str] = []
        cursor = 0
        match = f"{_AGENT_PREFIX}*"
        while True:
            cursor, keys = await self._r.scan(cursor, match=match, count=100)
            for k in keys:
                k_str = k.decode("utf-8") if isinstance(k, bytes) else k
                ids.append(k_str.removeprefix(_AGENT_PREFIX))
            if cursor == 0:
                break
        return ids

    # ------------------------------------------------------------------
    # Lifecycle helpers
    # ------------------------------------------------------------------

    async def close(self) -> None:
        """Close the underlying Redis client.

        Example::

            await registry.close()
        """
        await self._r.aclose()


# ---------------------------------------------------------------------------
# Connection factories
# ---------------------------------------------------------------------------


async def connect_redis(
    url: str = "redis://localhost:6379",
    *,
    decode_responses: bool = False,
) -> Any:
    """Create a plain ``redis.asyncio.Redis`` client.

    Use this in local development and CI pipelines where Memorystore
    IAM auth is not available.

    Parameters
    ----------
    url:
        A ``redis://`` or ``rediss://`` connection string.
    decode_responses:
        When ``True``, all responses are returned as ``str`` instead of
        ``bytes``.  Defaults to ``False`` so that both ``str`` and
        ``bytes`` keys are handled uniformly inside
        :class:`RedisRegistry`.

    Example::

        client = await connect_redis("redis://localhost:6379")
        registry = RedisRegistry(client)
    """
    from redis.asyncio import Redis  # type: ignore[import-untyped]

    return Redis.from_url(url, decode_responses=decode_responses)  # pyright: ignore[reportUnknownVariableType,reportUnknownMemberType]


async def connect_memorystore(
    *,
    host: str | None = None,
    port: int | None = None,
    iam_username: str | None = None,
    ssl: bool = True,
) -> Any:
    """Create a ``RedisCluster`` client for Google Cloud Memorystore with IAM auth.

    This mirrors the ``dw-ai-brain`` ``registry/store.py`` connection
    pattern.  Parameters fall back to environment variables:

    ==================  ==============================
    Parameter           Environment variable
    ==================  ==============================
    host                ``MEMORYSTORE_HOST``
    port                ``MEMORYSTORE_PORT``
    iam_username        ``MEMORYSTORE_IAM_USERNAME``
    ==================  ==============================

    When ``host`` resolves to ``localhost`` or ``127.0.0.1``, IAM auth is
    skipped and a plain cluster connection is made (useful for local
    Redis cluster emulation).

    Example::

        client = await connect_memorystore(host="10.0.0.4", port=6379)
        registry = RedisRegistry(client)
    """
    import google.auth  # type: ignore[import-untyped]
    import google.auth.transport.requests  # type: ignore[import-untyped]
    from redis.asyncio.cluster import RedisCluster  # type: ignore[import-untyped]
    from redis.credentials import CredentialProvider  # type: ignore[import-untyped]

    _host = (host or os.environ.get("MEMORYSTORE_HOST", "localhost")).strip()
    _port = port or int(os.environ.get("MEMORYSTORE_PORT", "6379"))
    _username = (iam_username or os.environ.get("MEMORYSTORE_IAM_USERNAME") or "default").strip()

    def _use_iam() -> bool:
        return _host not in ("localhost", "127.0.0.1")

    if _use_iam():
        _credentials: Any = None

        def _get_token() -> str:
            nonlocal _credentials
            if _credentials is None:
                _credentials, _ = google.auth.default(  # pyright: ignore[reportUnknownMemberType,reportUnknownVariableType]
                    scopes=["https://www.googleapis.com/auth/cloud-platform"]
                )
            req = google.auth.transport.requests.Request()  # pyright: ignore[reportUnknownMemberType,reportUnknownVariableType]
            _credentials.refresh(req)  # pyright: ignore[reportUnknownMemberType]
            raw_token = _credentials.token  # pyright: ignore[reportUnknownMemberType,reportUnknownVariableType]
            token: str = str(raw_token) if raw_token else ""  # pyright: ignore[reportUnknownArgumentType]
            if not token:
                raise RuntimeError("GCP IAM access token for Memorystore is empty after refresh")
            return token

        class _IamProvider(CredentialProvider):
            def get_credentials(self) -> tuple[str, str]:
                return _username, _get_token()

            async def get_credentials_async(self) -> tuple[str, str]:
                token = await asyncio.to_thread(_get_token)
                return _username, token

        pool: Any = RedisCluster(
            host=_host,
            port=_port,
            credential_provider=_IamProvider(),
            ssl=ssl,
            ssl_cert_reqs=None,
            decode_responses=False,
            require_full_coverage=False,
        )
    else:
        pool = RedisCluster(
            host=_host,
            port=_port,
            decode_responses=False,
            require_full_coverage=False,
        )

    await pool.initialize()
    return pool
