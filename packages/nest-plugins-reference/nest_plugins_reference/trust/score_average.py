# SPDX-License-Identifier: Apache-2.0
"""Score-average trust plugin — running mean of feedback scores.

Example::

    trust = ScoreAverageTrust(identity)
    await trust.report(AgentId("a1"), evidence)
    score = await trust.score(AgentId("a1"))
"""

from __future__ import annotations

from typing import Any

from nest_core.types import (
    AgentId,
    Attestation,
    Claim,
    Evidence,
    ReputationScore,
    Signature,
)


class ScoreAverageTrust:
    """Running-mean reputation based on reported feedback.

    Example::

        trust = ScoreAverageTrust()
        score = await trust.score(AgentId("a1"))
    """

    def __init__(self, identity: Any = None) -> None:
        self._identity = identity
        self._scores: dict[AgentId, list[float]] = {}
        self._stakes: dict[AgentId, int] = {}

    async def score(self, agent: AgentId) -> ReputationScore:
        """Get the running-mean reputation score for an agent.

        Example::

            rep = await trust.score(AgentId("a1"))
        """
        entries = self._scores.get(agent, [])
        if not entries:
            return ReputationScore(agent_id=agent, score=0.5, confidence=0.0, sample_count=0)
        avg = sum(entries) / len(entries)
        confidence = min(1.0, len(entries) / 100.0)
        return ReputationScore(
            agent_id=agent,
            score=avg,
            confidence=confidence,
            sample_count=len(entries),
        )

    async def attest(self, agent: AgentId, claim: Claim) -> Attestation:
        """Create an attestation about an agent.

        Example::

            att = await trust.attest(AgentId("a1"), claim)
        """
        sig = Signature(signer=AgentId("system"), value=b"attestation", algorithm="none")
        if self._identity is not None:
            sig = self._identity.sign(claim.model_dump_json().encode())
        return Attestation(issuer=AgentId("system"), claim=claim, signature=sig)

    async def report(self, agent: AgentId, evidence: Evidence) -> None:
        """Report evidence, updating the agent's score.

        Evidence kind 'positive' adds 1.0, 'negative' adds 0.0, 'byzantine' adds 0.0.
        Self-reports, where the reporter is the agent being scored, are ignored.

        Example::

            await trust.report(AgentId("a1"), Evidence(reporter=..., subject=..., kind="negative"))
        """
        if evidence.reporter == agent:
            return
        score_val = 0.5
        if evidence.kind == "positive":
            score_val = 1.0
        elif evidence.kind in ("negative", "byzantine"):
            score_val = 0.0
        self._scores.setdefault(agent, []).append(score_val)

    async def stake(self, agent: AgentId, amount: int) -> None:
        """Stake reputation on an agent.

        Example::

            await trust.stake(AgentId("a1"), 100)
        """
        self._stakes[agent] = self._stakes.get(agent, 0) + amount
