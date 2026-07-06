# SPDX-License-Identifier: Apache-2.0
"""Persistent registry backends for Nanda Town.

Two backends are provided:

* :mod:`nest_registry_backends.cloud_sql` — PostgreSQL via asyncpg
  (supports plain PostgreSQL for CI and Google Cloud SQL via the
  ``google-cloud-sql-connector`` for production).
* :mod:`nest_registry_backends.redis` — Redis / Google Cloud Memorystore
  with optional IAM token auth.

Both implement the :class:`nest_sdk.Registry` protocol and are registered
as ``nest.plugins.registry`` entry points.

Example::

    from nest_registry_backends.redis import RedisRegistry, connect_redis

    client = await connect_redis("redis://localhost:6379")
    registry = RedisRegistry(client)
    await registry.register(card)
"""
