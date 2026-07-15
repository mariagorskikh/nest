# SPDX-License-Identifier: Apache-2.0
"""Gift-card recommendation DataFacts plugin.

Stores purchase-history tables in dataset metadata and provides search-then-rank
recommendations over that table.
"""

from __future__ import annotations

import time
from collections import defaultdict
from typing import Any

from nest_sdk import AccessGrant, AgentId, DataFacts, DataFactsUrl, DatasetMetadata


_TABLE_KEY = "purchase_history_table"


def _text(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


class GiftCardRecommenderFacts(DataFacts):
    """DataFacts plugin with search-based gift-card recommendation.

    Expected dataset metadata format::

        DatasetMetadata(
            name="gift-card-history",
            owner=AgentId("merchant-ops"),
            metadata={
                "purchase_history_table": [
                    {
                        "customer_id": "c-001",
                        "gift_card": "Starbucks",
                        "merchant": "Starbucks",
                        "category": "coffee",
                        "amount": 25,
                        "notes": "birthday coworker",
                    }
                ]
            },
        )
    """

    def __init__(self, *, freshness_ttl_seconds: float = 24 * 3600) -> None:
        self._datasets: dict[DataFactsUrl, DatasetMetadata] = {}
        self._grants: dict[DataFactsUrl, list[AccessGrant]] = {}
        self._timestamps: dict[DataFactsUrl, float] = {}
        self._tables: dict[DataFactsUrl, list[dict[str, Any]]] = {}
        self._freshness_ttl_seconds = freshness_ttl_seconds

    async def publish(self, dataset: DatasetMetadata) -> DataFactsUrl:
        url = DataFactsUrl(f"df://{dataset.name}")
        self._datasets[url] = dataset.model_copy(deep=True)
        self._timestamps[url] = time.time()
        self._tables[url] = self._extract_purchase_table(dataset)
        return url

    async def fetch(self, url: DataFactsUrl) -> DatasetMetadata:
        meta = self._datasets.get(url)
        if meta is None:
            msg = f"Dataset not found: {url}"
            raise KeyError(msg)
        return meta.model_copy(deep=True)

    async def request_access(self, url: DataFactsUrl, requester: AgentId) -> AccessGrant:
        meta = await self.fetch(url)
        if meta.access_tier != "public" and requester != meta.owner:
            msg = f"{requester} is not authorized to read {url} (tier={meta.access_tier!r})"
            raise PermissionError(msg)
        grant = AccessGrant(url=url, grantee=requester, tier="read")
        self._grants.setdefault(url, []).append(grant)
        return grant

    async def verify_freshness(self, url: DataFactsUrl) -> bool:
        ts = self._timestamps.get(url)
        if ts is None:
            return False
        return (time.time() - ts) <= self._freshness_ttl_seconds

    def search_purchase_history(
        self,
        url: DataFactsUrl,
        query: str,
        *,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Return purchase rows matching all tokens in ``query``.

        Search is case-insensitive and spans customer, gift-card, merchant,
        category, and free-form notes columns.
        """
        table = self._tables.get(url)
        if table is None:
            msg = f"Dataset not found: {url}"
            raise KeyError(msg)

        tokens = [t for t in query.lower().split() if t]
        if not tokens:
            return [row.copy() for row in table[:limit]]

        out: list[dict[str, Any]] = []
        for row in table:
            searchable = " ".join(
                [
                    _text(row.get("customer_id")).lower(),
                    _text(row.get("gift_card")).lower(),
                    _text(row.get("merchant")).lower(),
                    _text(row.get("category")).lower(),
                    _text(row.get("notes")).lower(),
                ]
            )
            if all(token in searchable for token in tokens):
                out.append(row.copy())
                if len(out) >= limit:
                    break
        return out

    def recommend_gift_cards(
        self,
        url: DataFactsUrl,
        query: str,
        *,
        top_k: int = 5,
    ) -> list[dict[str, Any]]:
        """Recommend gift cards by ranking cards from searched purchase rows.

        Ranking uses purchase frequency first, then average amount, then
        alphabetical card name for stable deterministic ordering.
        """
        matches = self.search_purchase_history(url, query, limit=10_000)
        aggregates: dict[str, dict[str, Any]] = defaultdict(
            lambda: {"gift_card": "", "purchase_count": 0, "average_amount": 0.0, "_sum": 0.0}
        )

        for row in matches:
            name = _text(row.get("gift_card")).strip()
            if not name:
                continue
            aggregate = aggregates[name]
            aggregate["gift_card"] = name
            aggregate["purchase_count"] += 1
            amount_raw = row.get("amount")
            if isinstance(amount_raw, (int, float)):
                aggregate["_sum"] += float(amount_raw)

        ranked: list[dict[str, Any]] = []
        for aggregate in aggregates.values():
            count = int(aggregate["purchase_count"])
            sum_amount = float(aggregate["_sum"])
            aggregate["average_amount"] = (sum_amount / count) if count > 0 else 0.0
            aggregate.pop("_sum", None)
            ranked.append(aggregate)

        ranked.sort(
            key=lambda item: (
                -int(item["purchase_count"]),
                -float(item["average_amount"]),
                str(item["gift_card"]).lower(),
            )
        )
        return ranked[:top_k]

    def _extract_purchase_table(self, dataset: DatasetMetadata) -> list[dict[str, Any]]:
        raw = dataset.metadata.get(_TABLE_KEY, [])
        if not isinstance(raw, list):
            return []
        rows: list[dict[str, Any]] = []
        for row in raw:
            if isinstance(row, dict):
                rows.append(dict(row))
        return rows