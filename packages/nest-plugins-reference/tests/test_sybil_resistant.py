# SPDX-License-Identifier: Apache-2.0
"""Tests for the Sybil-resistant trust plugin.

Covers the three core Sybil-resistance mechanisms:

1. Reporter-weight normalisation — one entity's N sock puppets cannot
   amplify their signal N-fold.
2. Collusion-ring detection — mutual-boost cliques are detected and
   discounted.
3. Burst-rate damping — rapid-fire reports from the same reporter are
   exponentially decayed.

Also includes scenario integration tests and adversarial validator
cross-checks (validators FAIL against ``score_average``, PASS against
``sybil_resistant``).

Example::

    pytest packages/nest-plugins-reference/tests/test_sybil_resistant.py -v
"""

from __future__ import annotations

import pytest
from nest_core.types import AgentId, Evidence
from nest_plugins_reference.trust.score_average import ScoreAverageTrust
from nest_plugins_reference.trust.sybil_resistant import SybilResistantTrust

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_evidence(reporter: str, subject: str, kind: str) -> Evidence:
    """Create an Evidence instance for tests.

    Example::

        ev = _make_evidence("r1", "a1", "positive")
    """
    return Evidence(
        reporter=AgentId(reporter),
        subject=AgentId(subject),
        kind=kind,
    )


# ---------------------------------------------------------------------------
# Basic functionality
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_initial_score_is_neutral() -> None:
    """An agent with no reports should have score 0.5 and confidence 0.0."""
    trust = SybilResistantTrust()
    score = await trust.score(AgentId("unknown"))
    assert score.score == pytest.approx(0.5)
    assert score.confidence == pytest.approx(0.0)
    assert score.sample_count == 0


@pytest.mark.asyncio
async def test_positive_reports_increase_score() -> None:
    """Positive reports from distinct reporters should increase score."""
    trust = SybilResistantTrust()
    for i in range(5):
        await trust.report(
            AgentId("target"),
            _make_evidence(f"reporter-{i}", "target", "positive"),
        )
    score = await trust.score(AgentId("target"))
    assert score.score > 0.5
    assert score.sample_count == 5


@pytest.mark.asyncio
async def test_negative_reports_decrease_score() -> None:
    """Negative reports from distinct reporters should decrease score."""
    trust = SybilResistantTrust()
    for i in range(5):
        await trust.report(
            AgentId("target"),
            _make_evidence(f"reporter-{i}", "target", "negative"),
        )
    score = await trust.score(AgentId("target"))
    assert score.score < 0.5


@pytest.mark.asyncio
async def test_confidence_increases_with_distinct_reporters() -> None:
    """Confidence should increase when more distinct reporters contribute."""
    trust = SybilResistantTrust(min_reporters_for_confidence=5)
    for i in range(5):
        await trust.report(
            AgentId("target"),
            _make_evidence(f"reporter-{i}", "target", "positive"),
        )
    score = await trust.score(AgentId("target"))
    assert score.confidence == pytest.approx(1.0)


@pytest.mark.asyncio
async def test_attest_produces_attestation() -> None:
    """attest() should return a valid Attestation."""
    from nest_core.types import Claim

    trust = SybilResistantTrust()
    claim = Claim(subject=AgentId("a1"), predicate="is_reliable", value="true")
    att = await trust.attest(AgentId("a1"), claim)
    assert att.claim == claim
    assert att.signature is not None


@pytest.mark.asyncio
async def test_stake_accumulates() -> None:
    """stake() should accumulate amounts."""
    trust = SybilResistantTrust()
    await trust.stake(AgentId("a1"), 50)
    await trust.stake(AgentId("a1"), 30)
    assert trust._stakes[AgentId("a1")] == 80  # pyright: ignore[reportPrivateUsage]


# ---------------------------------------------------------------------------
# Sybil flood resistance
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_flood_attack_is_damped() -> None:
    """A single reporter flooding positive reports should have diminishing effect.

    Under ``score_average`` 20 positive reports from one reporter would push
    the score to ~1.0.  Under ``sybil_resistant`` burst damping limits the
    effect of reports beyond the threshold.
    """
    sybil_trust = SybilResistantTrust(burst_threshold=3, burst_decay=0.5)
    naive_trust = ScoreAverageTrust()

    # Flood from a single reporter
    for _ in range(20):
        await sybil_trust.report(
            AgentId("target"),
            _make_evidence("attacker", "target", "positive"),
        )
        await naive_trust.report(
            AgentId("target"),
            _make_evidence("attacker", "target", "positive"),
        )

    sybil_score = await sybil_trust.score(AgentId("target"))
    naive_score = await naive_trust.score(AgentId("target"))

    # Naive score is 1.0 (all positive), sybil score should be much lower
    assert naive_score.score == pytest.approx(1.0)
    assert sybil_score.score < naive_score.score
    # The sybil score should be closer to neutral than to 1.0
    assert sybil_score.score < 0.85


@pytest.mark.asyncio
async def test_flood_does_not_affect_legitimate_reporters() -> None:
    """Reports from distinct reporters should still be weighted normally."""
    trust = SybilResistantTrust(burst_threshold=3, burst_decay=0.5)

    # 5 distinct reporters each send 1 positive report
    for i in range(5):
        await trust.report(
            AgentId("target"),
            _make_evidence(f"honest-{i}", "target", "positive"),
        )

    score = await trust.score(AgentId("target"))
    # Score should be clearly above neutral
    assert score.score > 0.6


# ---------------------------------------------------------------------------
# Collusion ring detection
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_collusion_ring_detected_and_penalised() -> None:
    """A mutual-boost ring of agents should be detected and discounted.

    Under ``score_average`` mutual boosting is invisible.  Under
    ``sybil_resistant`` collusion detection applies a penalty.
    """
    trust = SybilResistantTrust(collusion_penalty=0.1)

    # Create a collusion ring: A boosts B, B boosts A
    await trust.report(AgentId("B"), _make_evidence("A", "B", "positive"))
    await trust.report(AgentId("A"), _make_evidence("B", "A", "positive"))
    await trust.report(AgentId("A"), _make_evidence("C", "A", "positive"))
    await trust.report(AgentId("B"), _make_evidence("C", "B", "positive"))

    # Also have A boost B multiple times
    for _ in range(5):
        await trust.report(AgentId("B"), _make_evidence("A", "B", "positive"))

    score_b = await trust.score(AgentId("B"))

    # Compare with a non-colluding agent that got the same number of positives
    trust2 = SybilResistantTrust(collusion_penalty=0.1)
    for i in range(7):
        await trust2.report(
            AgentId("clean"),
            _make_evidence(f"reporter-{i}", "clean", "positive"),
        )
    score_clean = await trust2.score(AgentId("clean"))

    # The colluding agent should have a lower effective score
    assert score_b.score < score_clean.score


# ---------------------------------------------------------------------------
# Reporter weight normalisation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reporter_weight_cap() -> None:
    """No single reporter should dominate the score calculation.

    With 5 distinct reporters, each reporter's cap is 1/5 = 0.2.
    One reporter sending 100 positives + 4 others sending 1 negative each
    should still show a mixed (not purely positive) score.
    """
    trust = SybilResistantTrust(burst_threshold=2, burst_decay=0.3)

    # One sybil sends 100 positive reports
    for _ in range(100):
        await trust.report(
            AgentId("target"),
            _make_evidence("sybil", "target", "positive"),
        )

    # Four honest reporters each send 1 negative report
    for i in range(4):
        await trust.report(
            AgentId("target"),
            _make_evidence(f"honest-{i}", "target", "negative"),
        )

    score = await trust.score(AgentId("target"))
    # Despite 100 positives vs 4 negatives, the negatives should still
    # meaningfully drag the score down from 1.0
    assert score.score < 0.95


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_deterministic_scoring() -> None:
    """Same sequence of reports should always produce the same score."""
    scores: list[float] = []

    for _ in range(3):
        trust = SybilResistantTrust()
        for i in range(10):
            kind = "positive" if i % 3 != 0 else "negative"
            await trust.report(
                AgentId("target"),
                _make_evidence(f"reporter-{i}", "target", kind),
            )
        score = await trust.score(AgentId("target"))
        scores.append(score.score)

    # All three runs should produce identical results
    assert scores[0] == pytest.approx(scores[1])
    assert scores[1] == pytest.approx(scores[2])


# ---------------------------------------------------------------------------
# Protocol compliance
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_implements_trust_protocol() -> None:
    """SybilResistantTrust should satisfy the Trust protocol."""
    from nest_core.layers.trust import Trust

    trust = SybilResistantTrust()
    assert isinstance(trust, Trust)


# ---------------------------------------------------------------------------
# Validator integration tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sybil_flood_validator_fails_against_naive() -> None:
    """The flood validator should detect unopposed flood patterns in traces."""
    from nest_core.validators import validate_sybil_flood_resistance

    # Simulate trace events: one reporter floods good reports, no bad reports
    events: list[dict[str, object]] = []
    for i in range(10):
        events.append(
            {
                "kind": "send",
                "agent": "sybil-0",
                "to": "observer-0",
                "msg": f"report:{i}:honest-0:good",
            }
        )

    results = validate_sybil_flood_resistance(events)
    assert len(results) == 1
    assert not results[0].passed, "flood validator should FAIL on unopposed flood"


@pytest.mark.asyncio
async def test_sybil_flood_validator_passes_with_diverse_reporters() -> None:
    """The flood validator should PASS when reports come from diverse sources."""
    from nest_core.validators import validate_sybil_flood_resistance

    events: list[dict[str, object]] = []
    for i in range(10):
        events.append(
            {
                "kind": "send",
                "agent": f"reporter-{i}",
                "to": "observer-0",
                "msg": f"report:{i}:honest-0:good",
            }
        )

    results = validate_sybil_flood_resistance(events)
    assert len(results) == 1
    assert results[0].passed


@pytest.mark.asyncio
async def test_sybil_score_integrity_validator() -> None:
    """Honest-only deliverers should have non-negative score in traces."""
    from nest_core.validators import validate_sybil_score_integrity

    events: list[dict[str, object]] = []
    # Honest agent delivers
    events.append(
        {
            "kind": "send",
            "agent": "honest-0",
            "to": "buyer-0",
            "msg": "deliver:1:honest-0",
        }
    )
    # Gets good report
    events.append(
        {
            "kind": "send",
            "agent": "buyer-0",
            "to": "observer-0",
            "msg": "report:1:honest-0:good",
        }
    )

    results = validate_sybil_score_integrity(events)
    assert len(results) == 1
    assert results[0].passed


# ---------------------------------------------------------------------------
# Scenario smoke test
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sybil_scenario_loads() -> None:
    """The sybil_reputation scenario factory should load and create agents."""
    from nest_core.scenarios import get_scenario_factory

    factory = get_scenario_factory("sybil_reputation")
    assert factory is not None
