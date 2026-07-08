# SPDX-License-Identifier: Apache-2.0
# pyright: reportPrivateUsage=false
"""Unit tests for score_average trust plugin."""

from __future__ import annotations

import pytest
from nest_core.types import AgentId, Claim, Evidence


class TestScoreCalculation:
    @pytest.mark.asyncio
    async def test_score_treats_byzantine_as_negative(self) -> None:
        from nest_plugins_reference.trust.score_average import ScoreAverageTrust

        trust = ScoreAverageTrust()
        ev = Evidence(reporter=AgentId("a2"), subject=AgentId("a1"), kind="byzantine")
        await trust.report(AgentId("a1"), ev)

        score = await trust.score(AgentId("a1"))
        assert score.score == 0.0
        assert score.sample_count == 1

    @pytest.mark.asyncio
    async def test_score_returns_running_average(self) -> None:
        from nest_plugins_reference.trust.score_average import ScoreAverageTrust

        trust = ScoreAverageTrust()
        pos = Evidence(reporter=AgentId("a2"), subject=AgentId("a1"), kind="positive")
        neg = Evidence(reporter=AgentId("a3"), subject=AgentId("a1"), kind="negative")
        await trust.report(AgentId("a1"), pos)
        await trust.report(AgentId("a1"), pos)
        await trust.report(AgentId("a1"), neg)

        score = await trust.score(AgentId("a1"))
        assert score.score == 2.0 / 3.0
        assert score.sample_count == 3

    @pytest.mark.asyncio
    async def test_unknown_evidence_defaults_to_neutral(self) -> None:
        from nest_plugins_reference.trust.score_average import ScoreAverageTrust

        trust = ScoreAverageTrust()
        ev = Evidence(reporter=AgentId("a2"), subject=AgentId("a1"), kind="unknown_kind")
        await trust.report(AgentId("a1"), ev)

        score = await trust.score(AgentId("a1"))
        assert score.score == 0.5
        assert score.sample_count == 1


class TestConfidence:
    @pytest.mark.asyncio
    async def test_confidence_increases_with_reports(self) -> None:
        from nest_plugins_reference.trust.score_average import ScoreAverageTrust

        trust = ScoreAverageTrust()
        ev = Evidence(reporter=AgentId("a2"), subject=AgentId("a1"), kind="positive")
        for _ in range(50):
            await trust.report(AgentId("a1"), ev)

        score = await trust.score(AgentId("a1"))
        assert score.confidence == 0.5
        assert score.sample_count == 50

    @pytest.mark.asyncio
    async def test_confidence_caps_at_threshold(self) -> None:
        from nest_plugins_reference.trust.score_average import ScoreAverageTrust

        trust = ScoreAverageTrust()
        ev = Evidence(reporter=AgentId("a2"), subject=AgentId("a1"), kind="positive")
        for _ in range(150):
            await trust.report(AgentId("a1"), ev)

        score = await trust.score(AgentId("a1"))
        assert score.confidence == 1.0
        assert score.sample_count == 150


class TestAttestation:
    @pytest.mark.asyncio
    async def test_attest_returns_placeholder_without_identity(self) -> None:
        from nest_plugins_reference.trust.score_average import ScoreAverageTrust

        trust = ScoreAverageTrust()
        claim = Claim(subject=AgentId("a1"), predicate="test", value="value")
        att = await trust.attest(AgentId("a1"), claim)

        assert att.issuer == AgentId("system")
        assert att.signature.signer == AgentId("system")
        assert att.signature.value == b"attestation"
        assert att.signature.algorithm == "none"


class TestStake:
    @pytest.mark.asyncio
    async def test_stake_accumulates_for_same_agent(self) -> None:
        from nest_plugins_reference.trust.score_average import ScoreAverageTrust

        trust = ScoreAverageTrust()
        await trust.stake(AgentId("a1"), 100)
        await trust.stake(AgentId("a1"), 50)

        assert trust._stakes[AgentId("a1")] == 150

    @pytest.mark.asyncio
    async def test_stakes_are_isolated_between_agents(self) -> None:
        from nest_plugins_reference.trust.score_average import ScoreAverageTrust

        trust = ScoreAverageTrust()
        await trust.stake(AgentId("a1"), 100)
        await trust.stake(AgentId("a2"), 200)

        assert trust._stakes[AgentId("a1")] == 100
        assert trust._stakes[AgentId("a2")] == 200


class TestRegression:
    @pytest.mark.asyncio
    async def test_scores_are_isolated_between_agents(self) -> None:
        from nest_plugins_reference.trust.score_average import ScoreAverageTrust

        trust = ScoreAverageTrust()
        pos = Evidence(reporter=AgentId("a2"), subject=AgentId("a1"), kind="positive")
        neg = Evidence(reporter=AgentId("a3"), subject=AgentId("a2"), kind="negative")
        await trust.report(AgentId("a1"), pos)
        await trust.report(AgentId("a2"), neg)

        score_a1 = await trust.score(AgentId("a1"))
        score_a2 = await trust.score(AgentId("a2"))
        assert score_a1.score == 1.0
        assert score_a2.score == 0.0
