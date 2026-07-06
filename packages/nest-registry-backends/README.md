# nest-registry-backends

Persistent registry backends for [Nanda Town](https://github.com/projnanda/nandatown).

The default `in_memory` registry is a single shared dictionary — intentionally
minimal, non-persistent, and single-process.  This package adds two
production-grade alternatives that implement the same `nest_sdk.Registry`
Protocol and are registered as `nest.plugins.registry` entry points so you
can drop them in with a one-line YAML change.

| Plugin name | Backend | Use case |
|-------------|---------|----------|
| `cloud_sql` | PostgreSQL / Google Cloud SQL | Durable, multi-process simulations; SQL queries |
| `redis`     | Redis / Google Cloud Memorystore | Low-latency discovery; TTL-native expiry |

---

## Install

```bash
# Cloud SQL backend only
pip install "nest-registry-backends[cloud_sql]"

# Redis backend only
pip install "nest-registry-backends[redis]"

# Both backends
pip install "nest-registry-backends[all]"
```

---

## Quick start

### Cloud SQL (PostgreSQL)

```python
from nest_registry_backends.cloud_sql import CloudSqlRegistry, connect_postgres

# Local / CI — plain PostgreSQL
pool = await connect_postgres("postgresql://user:pw@localhost/mydb")

# GCP — Cloud SQL with IAM auth (set INSTANCE_CONNECTION_NAME, DB_USER, DB_NAME)
# from nest_registry_backends.cloud_sql import connect_cloud_sql
# pool = await connect_cloud_sql()

registry = CloudSqlRegistry(pool)
await registry.migrate()  # creates the nest_agents table (idempotent)

await registry.register(card)
results = await registry.lookup(Query(capabilities=["sell"]))
await registry.deregister(agent_id)
await registry.close()
```

### Redis / Memorystore

```python
from nest_registry_backends.redis import RedisRegistry, connect_redis

# Local / CI — plain Redis
client = await connect_redis("redis://localhost:6379")

# GCP — Memorystore for Redis with IAM auth (set MEMORYSTORE_HOST, MEMORYSTORE_PORT)
# from nest_registry_backends.redis import connect_memorystore
# client = await connect_memorystore()

registry = RedisRegistry(client, ttl_seconds=3600)

await registry.register(card)
results = await registry.lookup(Query(capabilities=["sell"]))
await registry.deregister(agent_id)
await registry.close()
```

---

## Scenario YAML

After installing the package, point a scenario at either backend:

```yaml
# marketplace.yaml
registry: cloud_sql   # or: redis
```

Run with:

```bash
nest run marketplace.yaml
```

---

## Connection helpers

### `connect_postgres(dsn, *, min_size, max_size)`

Creates an `asyncpg` pool from a plain `postgresql://` DSN.  Suitable for
local development and CI pipelines.

### `connect_cloud_sql(*, instance_connection_name, db_user, db_name, ...)`

Creates an `asyncpg` pool via the [Cloud SQL Python Connector](https://github.com/GoogleCloudPlatform/cloud-sql-python-connector).
All parameters fall back to environment variables:

| Parameter | Env var |
|-----------|---------|
| `instance_connection_name` | `INSTANCE_CONNECTION_NAME` |
| `db_user` | `DB_USER` |
| `db_name` | `DB_NAME` |
| `ip_type` | `DB_IP_TYPE` (`"private"` or `"public"`) |

### `connect_redis(url, *, decode_responses)`

Creates a plain `redis.asyncio.Redis` client from a `redis://` URL.

### `connect_memorystore(*, host, port, iam_username, ssl)`

Creates a `RedisCluster` for Google Cloud Memorystore with IAM token auth
(mirrors the `dw-ai-brain` registry pattern).  Falls back to environment
variables `MEMORYSTORE_HOST`, `MEMORYSTORE_PORT`, `MEMORYSTORE_IAM_USERNAME`.

---

## Design notes

### Cloud SQL registry

- Single `nest_agents` table with a `JSONB` card column, a `TEXT[]`
  capabilities column (GIN-indexed), and an optional `expires_at` timestamp.
- Capability lookups use PostgreSQL's `@>` array-containment operator.
- Expired rows are pruned lazily on each `register` call.
- `subscribe` polls at a configurable interval (default 1 s).

### Redis registry

- Each agent card is stored as a Redis Hash under `nest:agent:<agent_id>`.
- Capabilities are indexed in Redis Sets (`nest:cap:<capability>`), enabling
  fast `SINTER`-based intersection lookups.
- `TTL` is applied to both agent hashes and capability set entries.
- Stale capability entries are cleaned up on re-registration.
- `subscribe` polls at a configurable interval (default 1 s).

---

## Running the tests

```bash
# From the workspace root
uv sync
uv run pytest packages/nest-registry-backends/ -v
```

Tests require `fakeredis` and `aiosqlite` (included in the `dev` extras).
No live database or Redis server is required.

---

## License

Apache-2.0 — see [LICENSE](../../LICENSE).
