# SPDX-License-Identifier: Apache-2.0
"""Tests for the weighted trust plugin (recency-decayed, volume-weighted)."""

from __future__ import annotations

import time

import pytest
from nest_core.types import AgentId, Evidence

from nest_plugins_reference.trust.weighted import WeightedTrust


class TestWeightedTrust:
    """Conformance + behavioural tests for WeightedTrust."""

    @pytest.mark.asyncio
    async def test_default_score_is_neutral(self) -> None:
        """An agent with no history gets a neutral 0.5 score with zero confidence."""
        trust = WeightedTrust()
        score = await trust.score(AgentId("a1"))
        assert score.score == 0.5
        assert score.confidence == 0.0
        assert score.sample_count == 0

    @pytest.mark.asyncio
    async def test_positive_evidence_raises_score(self) -> None:
        """Positive evidence should push the score above neutral."""
        trust = WeightedTrust()
        ev = Evidence(reporter=AgentId("a2"), subject=AgentId("a1"), kind="positive")
        await trust.report(AgentId("a1"), ev)
        await trust.report(AgentId("a1"), ev)

        score = await trust.score(AgentId("a1"))
        assert score.score > 0.5
        assert score.sample_count == 2
        assert score.confidence > 0.0

    @pytest.mark.asyncio
    async def test_negative_evidence_lowers_score(self) -> None:
        """Negative evidence should push the score below neutral."""
        trust = WeightedTrust()
        neg = Evidence(reporter=AgentId("a2"), subject=AgentId("a1"), kind="negative")
        await trust.report(AgentId("a1"), neg)

        score = await trust.score(AgentId("a1"))
        assert score.score < 0.5

    @pytest.mark.asyncio
    async def test_byzantine_worse_than_negative(self) -> None:
        """Byzantine (malicious) evidence should produce a lower score than negative."""
        trust_neg = WeightedTrust()
        trust_byz = WeightedTrust()

        neg = Evidence(reporter=AgentId("a2"), subject=AgentId("a1"), kind="negative")
        byz = Evidence(reporter=AgentId("a2"), subject=AgentId("a1"), kind="byzantine")

        # Use a mix of positive + negative vs positive + byzantine so the
        # difference in severity is visible (single reports both clamp to 0).
        pos = Evidence(reporter=AgentId("a3"), subject=AgentId("a1"), kind="positive")

        await trust_neg.report(AgentId("a1"), pos)
        await trust_neg.report(AgentId("a1"), neg)

        await trust_byz.report(AgentId("a1"), pos)
        await trust_byz.report(AgentId("a1"), byz)

        s_neg = await trust_neg.score(AgentId("a1"))
        s_byz = await trust_byz.score(AgentId("a1"))
        assert s_byz.score < s_neg.score

    @pytest.mark.asyncio
    async def test_mixed_evidence_converges_to_weighted_average(self) -> None:
        """A mix of positive and negative should land between the two extremes."""
        trust = WeightedTrust()
        pos = Evidence(reporter=AgentId("a2"), subject=AgentId("a1"), kind="positive")
        neg = Evidence(reporter=AgentId("a3"), subject=AgentId("a1"), kind="negative")

        for _ in range(3):
            await trust.report(AgentId("a1"), pos)
        for _ in range(1):
            await trust.report(AgentId("a1"), neg)

        score = await trust.score(AgentId("a1"))
        # 3 positives (1.0) + 1 negative (0.0) → weighted avg around 0.75
        assert 0.6 < score.score < 0.9
        assert score.sample_count == 4

    @pytest.mark.asyncio
    async def test_confidence_grows_with_volume(self) -> None:
        """More samples → higher confidence, capped at 1.0."""
        trust = WeightedTrust(max_samples=10)
        ev = Evidence(reporter=AgentId("a2"), subject=AgentId("a1"), kind="positive")

        await trust.report(AgentId("a1"), ev)
        s1 = await trust.score(AgentId("a1"))

        for _ in range(9):
            await trust.report(AgentId("a1"), ev)
        s2 = await trust.score(AgentId("a1"))

        assert s2.confidence > s1.confidence
        assert s2.confidence == pytest.approx(1.0, abs=0.01)

    @pytest.mark.asyncio
    async def test_recency_decay(self) -> None:
        """Old evidence should weigh less than fresh evidence."""
        trust = WeightedTrust(decay_half_life=1.0)  # 1 second half-life

        old_ts = time.time() - 100  # 100 seconds ago → heavily decayed
        fresh_ts = time.time()

        old_neg = Evidence(
            reporter=AgentId("a2"), subject=AgentId("a1"),
            kind="negative", timestamp=old_ts,
        )
        fresh_pos = Evidence(
            reporter=AgentId("a2"), subject=AgentId("a1"),
            kind="positive", timestamp=fresh_ts,
        )

        await trust.report(AgentId("a1"), old_neg)
        await trust.report(AgentId("a1"), fresh_pos)

        score = await trust.score(AgentId("a1"))
        # Fresh positive should dominate → score > 0.5
        assert score.score > 0.5

    @pytest.mark.asyncio
    async def test_score_is_clamped_to_unit_interval(self) -> None:
        """Score must never go below 0 or above 1."""
        trust = WeightedTrust()

        # Flood with byzantine evidence
        byz = Evidence(reporter=AgentId("a2"), subject=AgentId("a1"), kind="byzantine")
        for _ in range(50):
            await trust.report(AgentId("a1"), byz)
        s_low = await trust.score(AgentId("a1"))
        assert s_low.score >= 0.0

        # Flood with positive evidence
        trust2 = WeightedTrust()
        pos = Evidence(reporter=AgentId("a2"), subject=AgentId("a1"), kind="positive")
        for _ in range(50):
            await trust2.report(AgentId("a1"), pos)
        s_high = await trust2.score(AgentId("a1"))
        assert s_high.score <= 1.0

    @pytest.mark.asyncio
    async def test_stake(self) -> None:
        """Staking accumulates amounts per agent."""
        trust = WeightedTrust()
        await trust.stake(AgentId("a1"), 100)
        await trust.stake(AgentId("a1"), 50)
        assert trust._stakes[AgentId("a1")] == 150

    @pytest.mark.asyncio
    async def test_reporter_credibility_tracking(self) -> None:
        """Positive reporters slowly gain credibility over time."""
        trust = WeightedTrust()
        reporter = AgentId("r1")
        subject = AgentId("s1")
        pos = Evidence(reporter=reporter, subject=subject, kind="positive")

        initial_cred = trust._reporter_scores.get(reporter, 0.7)
        for _ in range(10):
            await trust.report(subject, pos)
        final_cred = trust._reporter_scores[reporter]
        assert final_cred > initial_cred
