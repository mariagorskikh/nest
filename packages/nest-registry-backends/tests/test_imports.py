# SPDX-License-Identifier: Apache-2.0
"""Smoke-test: all public symbols are importable and correctly named."""

from __future__ import annotations


def test_package_importable() -> None:
    import nest_registry_backends  # pyright: ignore[reportUnusedImport]

    _ = nest_registry_backends  # silence unused-import


def test_cloud_sql_exports() -> None:
    from nest_registry_backends.cloud_sql import (
        CloudSqlRegistry,
        connect_cloud_sql,
        connect_postgres,
    )

    assert CloudSqlRegistry is not None
    assert connect_postgres is not None
    assert connect_cloud_sql is not None


def test_redis_exports() -> None:
    from nest_registry_backends.redis import (
        RedisRegistry,
        connect_memorystore,
        connect_redis,
    )

    assert RedisRegistry is not None
    assert connect_redis is not None
    assert connect_memorystore is not None


def test_cloud_sql_registry_has_required_methods() -> None:
    from nest_registry_backends.cloud_sql import CloudSqlRegistry

    assert callable(getattr(CloudSqlRegistry, "register", None))
    assert callable(getattr(CloudSqlRegistry, "lookup", None))
    assert callable(getattr(CloudSqlRegistry, "subscribe", None))
    assert callable(getattr(CloudSqlRegistry, "deregister", None))
    assert callable(getattr(CloudSqlRegistry, "migrate", None))


def test_redis_registry_has_required_methods() -> None:
    from nest_registry_backends.redis import RedisRegistry

    assert callable(getattr(RedisRegistry, "register", None))
    assert callable(getattr(RedisRegistry, "lookup", None))
    assert callable(getattr(RedisRegistry, "subscribe", None))
    assert callable(getattr(RedisRegistry, "deregister", None))
