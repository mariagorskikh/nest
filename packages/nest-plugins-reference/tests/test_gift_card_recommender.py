# SPDX-License-Identifier: Apache-2.0
"""Tests for gift-card recommendation DataFacts plugin."""

from __future__ import annotations

import pytest
from nest_core.layers.datafacts import DataFacts
from nest_core.plugins import PluginRegistry
from nest_sdk import AgentId, DatasetMetadata

from nest_plugins_reference.datafacts.gift_card_recommender import GiftCardRecommenderFacts


class TestGiftCardRecommenderFacts:
    def test_isinstance_datafacts(self) -> None:
        assert isinstance(GiftCardRecommenderFacts(), DataFacts)

    @pytest.mark.asyncio
    async def test_publish_fetch_and_search(self) -> None:
        facts = GiftCardRecommenderFacts()
        dataset = DatasetMetadata(
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
                    },
                    {
                        "customer_id": "c-002",
                        "gift_card": "Amazon",
                        "merchant": "Amazon",
                        "category": "shopping",
                        "amount": 50,
                        "notes": "birthday teen",
                    },
                    {
                        "customer_id": "c-003",
                        "gift_card": "Starbucks",
                        "merchant": "Starbucks",
                        "category": "coffee",
                        "amount": 20,
                        "notes": "thank you teacher",
                    },
                ]
            },
        )

        url = await facts.publish(dataset)
        fetched = await facts.fetch(url)
        assert fetched.name == "gift-card-history"

        coffee_rows = facts.search_purchase_history(url, "coffee")
        assert len(coffee_rows) == 2
        assert all(row["gift_card"] == "Starbucks" for row in coffee_rows)

    @pytest.mark.asyncio
    async def test_recommendation_ranks_by_frequency_then_average_amount(self) -> None:
        facts = GiftCardRecommenderFacts()
        url = await facts.publish(
            DatasetMetadata(
                name="gift-card-history",
                owner=AgentId("merchant-ops"),
                metadata={
                    "purchase_history_table": [
                        {
                            "customer_id": "c-001",
                            "gift_card": "Steam",
                            "category": "gaming",
                            "amount": 60,
                            "notes": "teen birthday",
                        },
                        {
                            "customer_id": "c-002",
                            "gift_card": "Steam",
                            "category": "gaming",
                            "amount": 40,
                            "notes": "teen graduation",
                        },
                        {
                            "customer_id": "c-003",
                            "gift_card": "Nintendo",
                            "category": "gaming",
                            "amount": 100,
                            "notes": "teen birthday",
                        },
                    ]
                },
            )
        )

        recs = facts.recommend_gift_cards(url, "gaming teen", top_k=3)
        assert [item["gift_card"] for item in recs] == ["Steam", "Nintendo"]
        assert recs[0]["purchase_count"] == 2
        assert recs[0]["average_amount"] == 50.0

    @pytest.mark.asyncio
    async def test_request_access_enforces_private_tier(self) -> None:
        facts = GiftCardRecommenderFacts()
        url = await facts.publish(
            DatasetMetadata(
                name="gift-card-history-private",
                owner=AgentId("merchant-ops"),
                access_tier="private",
                metadata={"purchase_history_table": []},
            )
        )

        with pytest.raises(PermissionError):
            await facts.request_access(url, AgentId("other-agent"))

        grant = await facts.request_access(url, AgentId("merchant-ops"))
        assert grant.grantee == AgentId("merchant-ops")

    @pytest.mark.asyncio
    async def test_verify_freshness_respects_ttl(self) -> None:
        facts = GiftCardRecommenderFacts(freshness_ttl_seconds=-1.0)
        url = await facts.publish(
            DatasetMetadata(
                name="gift-card-history",
                owner=AgentId("merchant-ops"),
                metadata={"purchase_history_table": []},
            )
        )
        assert await facts.verify_freshness(url) is False


class TestRegistry:
    def test_builtin_resolves(self) -> None:
        cls = PluginRegistry().resolve("datafacts", "gift_card_recommender")
        assert cls is GiftCardRecommenderFacts

    def test_listed_for_datafacts_layer(self) -> None:
        assert ("datafacts", "gift_card_recommender") in PluginRegistry().list_plugins("datafacts")
