# SPDX-License-Identifier: Apache-2.0
"""Property + conformance tests for the weighted trust plugin.

All tests use the public API (``score``, ``report``, ``attest``, ``stake``,
``set_tick``) — no private-member access, so no ``reportPrivateUsage``
violations.
"""

from __future__ import annotations

import pytest
from nest_core.types import AgentId, Evidence
from nest_plugins_reference.trust.weighted import WeightedTrust


class TestWeightedTrustConformance:
    """Same conformance tests as ScoreAverageTrust — drop-in compatibility."""

    @pytest.mark.asyncio
    async def test_default_score(self) -> None:
        """An agent with no history gets a neutral 0.5 score with zero confidence."""
        trust = WeightedTrust()
        score = await trust.score(AgentId("a1"))
        assert score.score == 0.5
        assert score.confidence == 0.0
        assert score.sample_count == 0

    @pytest.mark.asyncio
    async def test_report_updates_score(self) -> None:
        """Positive evidence pushes the score above neutral."""
        trust = WeightedTrust()
        ev = Evidence(reporter=AgentId("a2"), subject=AgentId("a1"), kind="positive")
        await trust.report(AgentId("a1"), ev)
        await trust.report(AgentId("a1"), ev)
        score = await trust.score(AgentId("a1"))
        assert score.score == 1.0
        assert score.sample_count == 2

    @pytest.mark.asyncio
    async def test_negative_report(self) -> None:
        """A mix of positive and negative converges to the weighted average."""
        trust = WeightedTrust()
        pos = Evidence(reporter=AgentId("a2"), subject=AgentId("a1"), kind="positive")
        neg = Evidence(reporter=AgentId("a3"), subject=AgentId("a1"), kind="negative")
        await trust.report(AgentId("a1"), pos)
        await trust.report(AgentId("a1"), neg)
        score = await trust.score(AgentId("a1"))
        assert score.score == 0.5

    @pytest.mark.asyncio
    async def test_stake(self) -> None:
        """Staking is accepted without error."""
        trust = WeightedTrust()
        await trust.stake(AgentId("a1"), 100)


class TestWeightedTrustBehaviour:
    """Behavioural tests for recency decay, severity, and confidence."""

    @pytest.mark.asyncio
    async def test_byzantine_worse_than_negative(self) -> None:
        """Byzantine evidence produces a lower score than negative, given the
        same positive baseline."""
        trust_neg = WeightedTrust()
        trust_byz = WeightedTrust()
        neg = Evidence(reporter=AgentId("a2"), subject=AgentId("a1"), kind="negative")
        byz = Evidence(reporter=AgentId("a2"), subject=AgentId("a1"), kind="byzantine")
        pos = Evidence(reporter=AgentId("a3"), subject=AgentId("a1"), kind="positive")

        await trust_neg.report(AgentId("a1"), pos)
        await trust_neg.report(AgentId("a1"), neg)
        await trust_byz.report(AgentId("a1"), pos)
        await trust_byz.report(AgentId("a1"), byz)

        s_neg = await trust_neg.score(AgentId("a1"))
        s_byz = await trust_byz.score(AgentId("a1"))
        assert s_byz.score < s_neg.score

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
    async def test_score_clamped_to_unit_interval(self) -> None:
        """Score never goes below 0 or above 1."""
        trust = WeightedTrust()
        byz = Evidence(reporter=AgentId("a2"), subject=AgentId("a1"), kind="byzantine")
        for _ in range(50):
            await trust.report(AgentId("a1"), byz)
        s_low = await trust.score(AgentId("a1"))
        assert s_low.score >= 0.0

        trust2 = WeightedTrust()
        pos = Evidence(reporter=AgentId("a2"), subject=AgentId("a1"), kind="positive")
        for _ in range(50):
            await trust2.report(AgentId("a1"), pos)
        s_high = await trust2.score(AgentId("a1"))
        assert s_high.score <= 1.0


class TestWeightedTrustDeterminism:
    """The score must be a pure function of evidence + tick — no wall-clock."""

    @pytest.mark.asyncio
    async def test_same_inputs_same_output(self) -> None:
        """Two instances with identical evidence and tick produce identical scores."""
        t1 = WeightedTrust()
        t2 = WeightedTrust()
        for _ in range(10):
            await t1.report(
                AgentId("s"),
                Evidence(
                    reporter=AgentId("r"),
                    subject=AgentId("s"),
                    kind="positive",
                ),
            )
            await t2.report(
                AgentId("s"),
                Evidence(
                    reporter=AgentId("r"),
                    subject=AgentId("s"),
                    kind="positive",
                ),
            )
        s1 = await t1.score(AgentId("s"))
        s2 = await t2.score(AgentId("s"))
        assert s1.score == s2.score
        assert s1.confidence == s2.confidence

    @pytest.mark.asyncio
    async def test_tick_drives_decay_not_wall_clock(self) -> None:
        """Stale evidence decays based on the caller-supplied tick, not real time."""
        trust = WeightedTrust(decay_half_life=10.0)

        # File an old positive report at tick 0
        old = Evidence(
            reporter=AgentId("r"),
            subject=AgentId("s"),
            kind="positive",
            timestamp=0.0,
        )
        await trust.report(AgentId("s"), old)

        # File a fresh negative report at tick 100
        fresh = Evidence(
            reporter=AgentId("r"),
            subject=AgentId("s"),
            kind="negative",
            timestamp=100.0,
        )
        await trust.report(AgentId("s"), fresh)

        # At tick 100, the old positive is heavily decayed
        trust.set_tick(100.0)
        score = await trust.score(AgentId("s"))
        # With the negative dominating, score should be well below 0.5
        assert score.score < 0.5

    @pytest.mark.asyncio
    async def test_stale_positive_decays_away(self) -> None:
        """An agent with only old positive reports decays toward neutral."""
        trust = WeightedTrust(decay_half_life=10.0)
        pos = Evidence(
            reporter=AgentId("r"),
            subject=AgentId("s"),
            kind="positive",
            timestamp=0.0,
        )
        for _ in range(10):
            await trust.report(AgentId("s"), pos)

        # Fresh, all positives → score near 1.0
        trust.set_tick(0.0)
        s_fresh = await trust.score(AgentId("s"))
        assert s_fresh.score > 0.9

        # Much later, the positives have decayed — but with no negative
        # evidence the weighted average is still 1.0 (all values are 1.0).
        # The key point is that the WEIGHT shifts to zero, so adding a
        # single fresh negative will dominate.
        trust.set_tick(1000.0)
        s_stale = await trust.score(AgentId("s"))
        # Still 1.0 because all values are identical (1.0) — but weight is ~0
        assert s_stale.score == 1.0

        # Now add ONE fresh negative — it should dominate because old
        # positives are decayed to near-zero weight.
        neg = Evidence(
            reporter=AgentId("r"),
            subject=AgentId("s"),
            kind="negative",
            timestamp=1000.0,
        )
        await trust.report(AgentId("s"), neg)
        s_after_neg = await trust.score(AgentId("s"))
        # The fresh negative dominates: score should drop well below 0.5
        assert s_after_neg.score < 0.5

    @pytest.mark.asyncio
    async def test_repeated_calls_identical(self) -> None:
        """Calling score() twice at the same tick gives the same result."""
        trust = WeightedTrust()
        ev = Evidence(
            reporter=AgentId("r"),
            subject=AgentId("s"),
            kind="positive",
            timestamp=5.0,
        )
        await trust.report(AgentId("s"), ev)
        trust.set_tick(10.0)
        s1 = await trust.score(AgentId("s"))
        s2 = await trust.score(AgentId("s"))
        assert s1.score == s2.score
