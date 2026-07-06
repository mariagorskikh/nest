# SPDX-License-Identifier: Apache-2.0
"""Cloud SQL (PostgreSQL) registry backend for Nanda Town."""

from nest_registry_backends.cloud_sql.registry import (
    CloudSqlRegistry as CloudSqlRegistry,
)
from nest_registry_backends.cloud_sql.registry import (
    connect_cloud_sql as connect_cloud_sql,
)
from nest_registry_backends.cloud_sql.registry import (
    connect_postgres as connect_postgres,
)
