# SPDX-License-Identifier: Apache-2.0
"""DataFacts v1 plugin — dataset metadata registry.

Example::

    df = DataFactsV1()
    url = await df.publish(DatasetMetadata(name="weather", owner=AgentId("a1")))
    meta = await df.fetch(url)
"""

from __future__ import annotations

import time
from collections.abc import Callable

from nest_core.types import AccessGrant, AgentId, DataFactsUrl, DatasetMetadata


class DataFactsV1:
    """In-memory DataFacts metadata registry.

    Example::

        df = DataFactsV1()
        url = await df.publish(meta)
    """

    def __init__(
        self,
        clock: Callable[[], float] | None = None,
        freshness_window_seconds: float = 3600.0,
    ) -> None:
        """Create a deterministic-friendly DataFacts registry.

        Example::

            df = DataFactsV1(clock=lambda: 0.0, freshness_window_seconds=60.0)
        """
        if freshness_window_seconds <= 0:
            msg = f"Freshness window must be positive: {freshness_window_seconds}"
            raise ValueError(msg)
        self._clock = clock if clock is not None else time.time
        self._freshness_window_seconds = freshness_window_seconds
        self._datasets: dict[DataFactsUrl, DatasetMetadata] = {}
        self._grants: dict[DataFactsUrl, list[AccessGrant]] = {}
        self._timestamps: dict[DataFactsUrl, float] = {}

    async def publish(self, dataset: DatasetMetadata) -> DataFactsUrl:
        """Publish dataset metadata and return its URL.

        Example::

            url = await df.publish(DatasetMetadata(name="weather", owner=AgentId("a1")))
        """
        url = DataFactsUrl(f"df://{dataset.name}")
        self._datasets[url] = dataset
        self._timestamps[url] = self._clock()
        return url

    async def fetch(self, url: DataFactsUrl) -> DatasetMetadata:
        """Fetch metadata for a dataset URL.

        Example::

            meta = await df.fetch(DataFactsUrl("df://weather"))
        """
        meta = self._datasets.get(url)
        if meta is None:
            msg = f"Dataset not found: {url}"
            raise KeyError(msg)
        return meta

    async def request_access(self, url: DataFactsUrl, requester: AgentId) -> AccessGrant:
        """Request access to a dataset (always grants in v1).

        Example::

            grant = await df.request_access(url, AgentId("a2"))
        """
        if url not in self._datasets:
            msg = f"Dataset not found: {url}"
            raise KeyError(msg)
        grant = AccessGrant(url=url, grantee=requester, tier="read")
        self._grants.setdefault(url, []).append(grant)
        return grant

    async def verify_freshness(self, url: DataFactsUrl) -> bool:
        """Check if a dataset was published within the last hour.

        Example::

            fresh = await df.verify_freshness(url)
        """
        ts = self._timestamps.get(url)
        if ts is None:
            return False
        return (self._clock() - ts) < self._freshness_window_seconds
