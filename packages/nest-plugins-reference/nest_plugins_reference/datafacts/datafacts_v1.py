# SPDX-License-Identifier: Apache-2.0
"""DataFacts v1 plugin — dataset metadata registry.
Example::
    df = DataFactsV1()
    url = await df.publish(DatasetMetadata(name="weather", owner=AgentId("a1")))
    meta = await df.fetch(url)
"""

from __future__ import annotations
from dataclasses import dataclass
from nest_core.types import AccessGrant, AgentId, DataFactsUrl, DatasetMetadata


@dataclass
class SimulationClock:
    """Logical simulation clock for freshness checks (not wall time)."""

    now: float = 0.0

    def advance(self, delta: float = 1.0) -> None:
        self.now += delta


class DataFactsV1:
    """In-memory DataFacts metadata registry.
    Example::
        df = DataFactsV1()
        url = await df.publish(meta)
    """

    def __init__(self, clock: SimulationClock | None = None) -> None:
        self._datasets: dict[DataFactsUrl, DatasetMetadata] = {}
        self._grants: dict[DataFactsUrl, list[AccessGrant]] = {}
        self._timestamps: dict[DataFactsUrl, float] = {}
        self._clock = clock if clock is not None else SimulationClock()

    async def publish(self, dataset: DatasetMetadata) -> DataFactsUrl:
        """Publish dataset metadata and return its URL.
        Example::
            url = await df.publish(DatasetMetadata(name="weather", owner=AgentId("a1")))
        """
        url = DataFactsUrl(f"df://{dataset.name}")
        self._datasets[url] = dataset
        self._timestamps[url] = self._clock.now
        self._clock.advance()
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
        return (self._clock.now - ts) < 3600
