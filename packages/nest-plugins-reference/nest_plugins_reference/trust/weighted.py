# SPDX-License-Identifier: Apache-2.0
"""Weighted trust plugin — recency-decayed, volume-weighted reputation.

A drop-in alternative to ``ScoreAverageTrust`` that is:

* **Recency-aware** — evidence decays exponentially from its own timestamp,
  not wall-clock time.  The score is a pure function of the evidence list
  and the caller-supplied ``now`` tick, so traces are byte-reproducible.
* **Severity-weighted** — ``positive``, ``neutral``, ``negative``, and
  ``byzantine`` contribute differently, instead of the flat 1.0 / 0.0
  binary used by ``ScoreAverageTrust``.
* **Volume-confident** — ``confidence`` rises with sample count, capped at
  ``max_samples``.

The key discriminator vs. ``ScoreAverageTrust`` is **staleness decay**:
stale positive reports that should no longer carry weight are correctly
discounted, so an agent that *used to be good* but recently turned
malicious sees its score drop, while ``ScoreAverageTrust`` is memoryless
to ordering and treats all reports equally regardless of when they
arrived.

Example::

    trust = WeightedTrust()
    await trust.report(AgentId("a1"), evidence)
    score = await trust.score(AgentId("a1"))
"""

from __future__ import annotations

import math
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
    "byzantine": -0.5,  # worst — explicit malice
}

# Default "now" tick when no clock is available.  Deterministic.
_DEFAULT_NOW: float = 0.0


class _Report:
    """Internal record of a single piece of evidence."""

    __slots__ = ("value", "tick")

    def __init__(self, value: float, tick: float) -> None:
        self.value = value
        self.tick = tick


class WeightedTrust:
    """Recency-decayed, volume-weighted reputation model.

    Parameters
    ----------
    identity:
        Optional identity provider for signing attestations.
    decay_half_life:
        Evidence older than this many ticks has half the weight of fresh
        evidence (exponential decay).  Default 100 ticks (arbitrary
        simulation units, NOT wall-clock seconds).
    max_samples:
        Number of samples at which confidence reaches 1.0.
    """

    def __init__(
        self,
        identity: Any = None,
        decay_half_life: float = 100.0,
        max_samples: int = 50,
    ) -> None:
        self._identity = identity
        self._decay_half_life = decay_half_life
        self._max_samples = max_samples
        self._reports: dict[AgentId, list[_Report]] = {}
        self._stakes: dict[AgentId, int] = {}
        # Caller-supplied "current tick".  Set via :meth:`set_tick` or
        # left at 0.0 — the score is always a pure function of this value
        # and the stored evidence, never of wall-clock time.
        self._now: float = _DEFAULT_NOW

    # ------------------------------------------------------------------ #
    #  Clock — caller-supplied, never wall-clock
    # ------------------------------------------------------------------ #

    def set_tick(self, t: float) -> None:
        """Advance the plugin's internal clock to simulation tick *t*.

        This replaces wall-clock ``time.time()``.  The scenario runner
        or test calls this to advance time deterministically.

        Example::

            trust.set_tick(42.0)
        """
        self._now = t

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
                agent_id=agent,
                score=0.5,
                confidence=0.0,
                sample_count=0,
            )

        now = self._now
        decay_lambda = math.log(2) / self._decay_half_life if self._decay_half_life > 0 else 0.0

        weighted_sum = 0.0
        total_weight = 0.0
        for r in reports:
            age = max(0.0, now - r.tick)
            recency = math.exp(-decay_lambda * age)
            weighted_sum += r.value * recency
            total_weight += recency

        raw = weighted_sum / total_weight if total_weight else 0.5
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

        The evidence timestamp (``evidence.timestamp``) is used as the
        report tick.  If it is ``None``, the plugin's current internal
        tick (``self._now``) is used — both are deterministic.
        """
        tick = evidence.timestamp if evidence.timestamp is not None else self._now
        value = _SEVERITY.get(evidence.kind, 0.5)

        self._reports.setdefault(agent, []).append(
            _Report(value=value, tick=tick),
        )

    async def stake(self, agent: AgentId, amount: int) -> None:
        """Stake reputation on *agent*."""
        self._stakes[agent] = self._stakes.get(agent, 0) + amount
