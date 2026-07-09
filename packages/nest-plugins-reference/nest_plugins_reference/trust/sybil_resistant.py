# SPDX-License-Identifier: Apache-2.0
"""Sybil-resistant trust plugin — EMA-weighted reputation with Sybil detection.

Implements a 2-pass reputation system with three defences against Sybil attacks:
1. **Reporter credibility weighting (2-pass)**: reporters are weighted by their
   own baseline reputation score computed in Pass 1. Low-reputation/cheating
   agents have their reporting power discounted.
2. **Collusion-ring detection**: mutual-boost cliques are detected and penalized.
3. **Burst-rate damping**: rapid-fire reports from the same reporter are damped.
"""

from __future__ import annotations

import math
from collections import defaultdict
from typing import Any

from nest_core.types import (
    AgentId,
    Attestation,
    Claim,
    Evidence,
    ReputationScore,
    Signature,
)


class SybilResistantTrust:
    """EMA-weighted trust with Sybil resistance, collusion detection, and burst damping.

    Example::

        trust = SybilResistantTrust()
        score = await trust.score(AgentId("a1"))
    """

    def __init__(
        self,
        identity: Any = None,
        *,
        ema_alpha: float = 0.3,
        burst_threshold: int = 3,
        burst_decay: float = 0.5,
        collusion_penalty: float = 0.1,
        min_reporters_for_confidence: int = 3,
    ) -> None:
        self._identity = identity
        self._ema_alpha = ema_alpha
        self._burst_threshold = burst_threshold
        self._burst_decay = burst_decay
        self._collusion_penalty = collusion_penalty
        self._min_reporters = min_reporters_for_confidence

        # subject -> list of (raw_score, reporter, sequence_number)
        self._reports: dict[AgentId, list[tuple[float, AgentId, int]]] = defaultdict(list)
        # reporter -> subject -> positive count
        self._positive_reports: dict[AgentId, set[AgentId]] = defaultdict(set)
        # reporter -> subject -> negative count
        self._negative_reports: dict[AgentId, set[AgentId]] = defaultdict(set)
        # subject -> set of distinct reporters
        self._distinct_reporters: dict[AgentId, set[AgentId]] = defaultdict(set)
        # Global monotonic counter for deterministic ordering
        self._seq: int = 0
        # Stakes
        self._stakes: dict[AgentId, int] = {}

    def _raw_score_for_evidence(self, evidence: Evidence) -> float:
        if evidence.kind == "positive":
            return 1.0
        if evidence.kind in ("negative", "byzantine"):
            return -1.0
        return 0.0

    def _detect_collusion_ring(self, subject: AgentId) -> set[AgentId]:
        """Detect reporters that form a mutual-boost collusion ring with subject."""
        reporters = self._distinct_reporters.get(subject, set())
        ring_members: set[AgentId] = set()

        for reporter in reporters:
            # Check if reporter and subject mutually boost each other
            if (
                subject in self._positive_reports[reporter]
                and reporter in self._positive_reports[subject]
                and subject not in self._negative_reports[reporter]
                and reporter not in self._negative_reports[subject]
            ):
                ring_members.add(reporter)

        return ring_members

    def _compute_reporter_opinions(self) -> dict[AgentId, dict[AgentId, float]]:
        """Compute the opinion S_{R, S} of each reporter R about subject S.

        Uses burst-dampened EMA of reports from R about S.
        Returns dict[subject, dict[reporter, opinion_score]].
        """
        opinions: dict[AgentId, dict[AgentId, float]] = defaultdict(dict)
        # reporter -> subject -> count
        reporter_counts: dict[AgentId, dict[AgentId, int]] = defaultdict(lambda: defaultdict(int))

        # We must process all reports in global sequence order to remain deterministic
        all_reports_flat: list[tuple[AgentId, float, AgentId, int]] = []
        for subject, reports in self._reports.items():
            for raw_score, reporter, seq in reports:
                all_reports_flat.append((subject, raw_score, reporter, seq))
        all_reports_flat.sort(key=lambda x: x[3])

        for subject, raw_score, reporter, _ in all_reports_flat:
            reporter_counts[reporter][subject] += 1
            count = reporter_counts[reporter][subject]

            # Calculate burst-dampened alpha
            if count <= self._burst_threshold:
                alpha = self._ema_alpha
            else:
                excess = count - self._burst_threshold
                alpha = self._ema_alpha * (self._burst_decay**excess)

            current = opinions[subject].get(reporter, 0.0)
            opinions[subject][reporter] = alpha * raw_score + (1.0 - alpha) * current

        return opinions

    def _compute_scores_pass1(
        self, opinions: dict[AgentId, dict[AgentId, float]]
    ) -> dict[AgentId, float]:
        """Pass 1: Compute simple unweighted average of opinions for each agent."""
        scores_pass1: dict[AgentId, float] = {}
        for subject in self._reports:
            ops = opinions[subject]
            if not ops:
                scores_pass1[subject] = 0.5
            else:
                avg_op = sum(ops.values()) / len(ops)
                # Map from [-1, 1] to [0, 1]
                scores_pass1[subject] = 0.5 + 0.5 * math.tanh(avg_op)
        return scores_pass1

    def _compute_final_score(self, agent: AgentId) -> tuple[float, float, int]:
        """Compute the final weighted score, confidence, and report count for agent."""
        reports = self._reports.get(agent, [])
        if not reports:
            return 0.5, 0.0, 0

        opinions = self._compute_reporter_opinions()
        scores_pass1 = self._compute_scores_pass1(opinions)

        # Detect collusion ring
        ring_members = self._detect_collusion_ring(agent)

        ops = opinions.get(agent, {})
        if not ops:
            return 0.5, 0.0, 0

        weighted_sum = 0.0
        total_weight = 0.0

        for reporter, opinion_score in ops.items():
            # Pass 2 Weight: reporter's own baseline reputation from Pass 1
            # If reporter has no reports on them, they default to 0.5
            reporter_rep = scores_pass1.get(reporter, 0.5)
            weight = max(0.1, reporter_rep)

            # Apply collusion penalty if reporter is in a mutual-boost ring with subject
            if reporter in ring_members:
                weight *= self._collusion_penalty

            weighted_sum += opinion_score * weight
            total_weight += weight

        avg_opinion = weighted_sum / total_weight if total_weight > 0 else 0.0
        # Map aggregate opinion to [0, 1].
        # We scale by the number of distinct reporters (up to a limit)
        # to allow positive/negative build-up.
        distinct_count = len(self._distinct_reporters.get(agent, set()))
        scaled_opinion = avg_opinion * math.sqrt(distinct_count)
        final_score = 0.5 + 0.5 * math.tanh(scaled_opinion)

        confidence = min(1.0, distinct_count / max(1, self._min_reporters))

        return final_score, confidence, len(reports)

    async def score(self, agent: AgentId) -> ReputationScore:
        """Get the Sybil-resistant reputation score for an agent."""
        score_val, confidence, count = self._compute_final_score(agent)
        return ReputationScore(
            agent_id=agent,
            score=score_val,
            confidence=confidence,
            sample_count=count,
        )

    async def attest(self, agent: AgentId, claim: Claim) -> Attestation:
        sig = Signature(signer=AgentId("system"), value=b"attestation", algorithm="none")
        if self._identity is not None:
            sig = self._identity.sign(claim.model_dump_json().encode())
        return Attestation(issuer=AgentId("system"), claim=claim, signature=sig)

    async def report(self, agent: AgentId, evidence: Evidence) -> None:
        raw = self._raw_score_for_evidence(evidence)
        reporter = evidence.reporter

        self._seq += 1
        self._reports[agent].append((raw, reporter, self._seq))
        self._distinct_reporters[agent].add(reporter)

        if evidence.kind == "positive":
            self._positive_reports[reporter].add(agent)
        elif evidence.kind in ("negative", "byzantine"):
            self._negative_reports[reporter].add(agent)

    async def stake(self, agent: AgentId, amount: int) -> None:
        self._stakes[agent] = self._stakes.get(agent, 0) + amount
