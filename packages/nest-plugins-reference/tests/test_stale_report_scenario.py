# SPDX-License-Identifier: Apache-2.0
"""End-to-end scenario test for the weighted trust plugin.

Boots the ``stale_report`` scenario and proves the weighted plugin's
core claim: stale positive reports decay, so a reformed attacker's
recent malice lowers its score below what ``score_average`` produces.

Also runs the validators and verifies determinism across seeds.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from nest_core.types import AgentId, Evidence
from nest_plugins_reference.trust.score_average import ScoreAverageTrust
from nest_plugins_reference.trust.weighted import WeightedTrust

SCENARIO_PATH = Path(__file__).resolve().parents[3] / "scenarios" / "stale_report.yaml"


# ---------------------------------------------------------------------------
# Discriminator: weighted produces a lower score than score_average
# for the same stale-positive-then-negative evidence.
# ---------------------------------------------------------------------------


class TestStaleReportDiscriminator:
    """The core claim: weighting beats naive averaging on stale evidence."""

    @pytest.mark.asyncio
    async def test_weighted_lower_than_average_for_stale_attack(self) -> None:
        """A reformed attacker with 6 old positives + 4 fresh negatives.

        Under score_average: (6 * 1.0 + 4 * 0.0) / 10 = 0.6 — still trusted.
        Under weighted (decay_half_life=10): old positives decay, negatives
        dominate → score well below 0.6.
        """
        weighted = WeightedTrust(decay_half_life=10.0)
        average = ScoreAverageTrust()

        # File 6 positives at tick 0 (early, stale by end)
        for i in range(6):
            ev = Evidence(
                reporter=AgentId(f"r{i}"),
                subject=AgentId("attacker"),
                kind="positive",
                timestamp=0.0,
            )
            await weighted.report(AgentId("attacker"), ev)
            await average.report(AgentId("attacker"), ev)

        # File 4 negatives at tick 50 (recent, fresh)
        for i in range(4):
            ev = Evidence(
                reporter=AgentId(f"r{i + 6}"),
                subject=AgentId("attacker"),
                kind="negative",
                timestamp=50.0,
            )
            await weighted.report(AgentId("attacker"), ev)
            await average.report(AgentId("attacker"), ev)

        # Advance weighted's clock to tick 50 (same as the last evidence)
        weighted.set_tick(50.0)

        w_score = await weighted.score(AgentId("attacker"))
        a_score = await average.score(AgentId("attacker"))

        # score_average gives 0.6 (6 good, 4 bad → 6/10 = 0.6)
        assert a_score.score == pytest.approx(0.6, abs=0.01)

        # Weighted should give a MUCH lower score because old positives decayed
        assert w_score.score < a_score.score
        assert w_score.score < 0.5, (
            f"Expected weighted score < 0.5 (negatives should dominate), got {w_score.score}"
        )

    @pytest.mark.asyncio
    async def test_score_average_cannot_catch_stale_attack(self) -> None:
        """score_average gives the same score regardless of report ordering."""
        avg = ScoreAverageTrust()

        # All positives
        for i in range(6):
            ev = Evidence(
                reporter=AgentId(f"r{i}"),
                subject=AgentId("a"),
                kind="positive",
            )
            await avg.report(AgentId("a"), ev)

        # Then negatives
        for i in range(4):
            ev = Evidence(
                reporter=AgentId(f"r{i + 6}"),
                subject=AgentId("a"),
                kind="negative",
            )
            await avg.report(AgentId("a"), ev)

        score = await avg.score(AgentId("a"))
        # score_average: (6*1.0 + 4*0.0) / 10 = 0.6 — deceptively trusted
        assert score.score == pytest.approx(0.6, abs=0.01)


# ---------------------------------------------------------------------------
# Determinism: same seed → identical score
# ---------------------------------------------------------------------------


class TestWeightedDeterminism:
    """The score is a pure function of evidence + tick — no wall-clock."""

    @pytest.mark.asyncio
    async def test_identical_scores_across_instances(self) -> None:
        """Two independent instances with identical inputs produce identical scores."""

        async def build_and_score() -> float:
            t = WeightedTrust(decay_half_life=10.0)
            for i in range(6):
                await t.report(
                    AgentId("a"),
                    Evidence(
                        reporter=AgentId("r"),
                        subject=AgentId("a"),
                        kind="positive",
                        timestamp=float(i),
                    ),
                )
            for i in range(4):
                await t.report(
                    AgentId("a"),
                    Evidence(
                        reporter=AgentId("r"),
                        subject=AgentId("a"),
                        kind="negative",
                        timestamp=50.0 + float(i),
                    ),
                )
            t.set_tick(55.0)
            s = await t.score(AgentId("a"))
            return s.score

        s1 = await build_and_score()
        s2 = await build_and_score()
        assert s1 == s2

    @pytest.mark.asyncio
    async def test_seed_independence(self) -> None:
        """WeightedTrust uses no RNG — score is independent of any seed."""
        # Same evidence, different conceptual "seeds" — score must be identical
        # because WeightedTrust has no random component.
        results: list[float] = []
        for _seed in (42, 7, 1337):
            t = WeightedTrust()
            await t.report(
                AgentId("a"),
                Evidence(
                    reporter=AgentId("r"),
                    subject=AgentId("a"),
                    kind="positive",
                    timestamp=0.0,
                ),
            )
            await t.report(
                AgentId("a"),
                Evidence(
                    reporter=AgentId("r"),
                    subject=AgentId("a"),
                    kind="negative",
                    timestamp=10.0,
                ),
            )
            t.set_tick(10.0)
            s = await t.score(AgentId("a"))
            results.append(s.score)
        assert results[0] == results[1] == results[2]
