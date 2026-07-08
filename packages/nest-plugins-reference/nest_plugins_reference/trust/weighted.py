# SPDX-License-Identifier: Apache-2.0
"""Weighted trust plugin — recency-decayed, volume-weighted reputation.

A richer alternative to ScoreAverageTrust that considers:

  * **Recency** — newer evidence counts more than stale evidence via an
    exponential decay factor.
  * **Evidence severity** — ``positive`` adds weight, ``negative`` subtracts
    moderately, ``byzantine`` (fault/malicious) subtracts heavily.
  * **Volume confidence** — more data points → higher confidence score,
    capped at ``max_samples``.
  * **Reporter weighting** — reporters with a good track record are trusted
    more than unknown/new reporters.

The result is a score in ``[0, 1]`` that is more responsive to recent
behaviour and more robust to a few noisy reports than a flat average.

Example::

    trust = WeightedTrust()
    await trust.report(AgentId("a1"), evidence)
    score = await trust.score(AgentId("a1"))  # → ReputationScore
"""

from __future__ import annotations

import math
import time
from typing import Any

from nest_core.types import (
    AgentId,
    Attestation,
    Claim,
    Evidence,
    ReputationScore,
    Signature,
)

# Severity weights for each evidence kind.
_SEVERITY: dict[str, float] = {
    "positive": 1.0,
    "neutral": 0.5,
    "negative": 0.0,
    "byzantine": -0.5,   # worst — explicit malice
}


class _Report:
    """Internal record of a single piece of evidence."""

    __slots__ = ("value", "weight", "ts")

    def __init__(self, value: float, weight: float, ts: float) -> None:
        self.value = value
        self.weight = weight
        self.ts = ts


class WeightedTrust:
    """Recency-decayed, volume-weighted reputation model.

    Parameters
    ----------
    identity:
        Optional identity provider for signing attestations.
    decay_half_life:
        Evidence older than this many seconds has half the weight of
        fresh evidence (exponential decay).  Default 7 days.
    max_samples:
        Number of samples at which confidence reaches 1.0.  Default 50.
    """

    def __init__(
        self,
        identity: Any = None,
        decay_half_life: float = 7 * 24 * 3600,
        max_samples: int = 50,
    ) -> None:
        self._identity = identity
        self._decay_half_life = decay_half_life
        self._max_samples = max_samples
        self._reports: dict[AgentId, list[_Report]] = {}
        self._reporter_scores: dict[AgentId, float] = {}
        self._stakes: dict[AgentId, int] = {}

    # ------------------------------------------------------------------ #
    #  Public API (same interface as ScoreAverageTrust)
    # ------------------------------------------------------------------ #

    async def score(self, agent: AgentId) -> ReputationScore:
        """Compute the weighted reputation score for *agent*.

        Returns a ``ReputationScore`` with:

        * ``score`` in ``[0, 1]`` — 0.5 is neutral.
        * ``confidence`` in ``[0, 1]`` — rises with sample count.
        * ``sample_count`` — number of evidence items on file.
        """
        reports = self._reports.get(agent, [])
        n = len(reports)
        if n == 0:
            return ReputationScore(
                agent_id=agent, score=0.5, confidence=0.0, sample_count=0,
            )

        now = time.time()
        decay_lambda = math.log(2) / self._decay_half_life if self._decay_half_life else 0.0

        weighted_sum = 0.0
        total_weight = 0.0
        for r in reports:
            age = max(0.0, now - r.ts)
            recency = math.exp(-decay_lambda * age)
            w = r.weight * recency
            weighted_sum += r.value * w
            total_weight += w

        raw = weighted_sum / total_weight if total_weight else 0.5
        # Clamp to [0, 1]
        score = max(0.0, min(1.0, raw))
        confidence = min(1.0, n / self._max_samples)

        return ReputationScore(
            agent_id=agent,
            score=score,
            confidence=confidence,
            sample_count=n,
        )

    async def attest(self, agent: AgentId, claim: Claim) -> Attestation:
        """Create a signed attestation about *agent*."""
        sig = Signature(signer=AgentId("system"), value=b"attestation", algorithm="none")
        if self._identity is not None:
            sig = self._identity.sign(claim.model_dump_json().encode())
        return Attestation(issuer=AgentId("system"), claim=claim, signature=sig)

    async def report(self, agent: AgentId, evidence: Evidence) -> None:
        """Record *evidence* about *agent*, updating the weighted score.

        Evidence kinds and their contribution:

        * ``positive`` → value 1.0 (strong good)
        * ``neutral``  → value 0.5 (neither good nor bad)
        * ``negative`` → value 0.0 (poor performance)
        * ``byzantine`` → value -0.5 (active malice — penalised hardest)
        """
        ts = evidence.timestamp if evidence.timestamp is not None else time.time()
        value = _SEVERITY.get(evidence.kind, 0.5)

        # Reporter weight: known-good reporters carry more weight.
        # New reporters default to 0.7 (slightly above neutral).
        reporter_score = self._reporter_scores.get(evidence.reporter, 0.7)
        weight = max(0.1, reporter_score)  # floor so even bad reporters count a little

        self._reports.setdefault(agent, []).append(
            _Report(value=value, weight=weight, ts=ts),
        )

        # Update the reporter's own score: if their report aligns with
        # the subject's average, they become more credible next time.
        # (Simplified: positive reporters slowly gain credibility.)
        if evidence.kind == "positive":
            self._reporter_scores[evidence.reporter] = min(1.0, reporter_score + 0.02)
        elif evidence.kind in ("negative", "byzantine"):
            self._reporter_scores[evidence.reporter] = max(0.1, reporter_score - 0.01)

    async def stake(self, agent: AgentId, amount: int) -> None:
        """Stake reputation on *agent*."""
        self._stakes[agent] = self._stakes.get(agent, 0) + amount
