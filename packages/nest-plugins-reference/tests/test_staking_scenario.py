# SPDX-License-Identifier: Apache-2.0
"""Scenario test for the standalone staking primitive."""

from __future__ import annotations

import pytest
from nest_plugins_reference.trust.staking import AgentStakeTracker


def test_staking_scenario() -> None:
    tracker = AgentStakeTracker()

    # Agent A posts 100 stake to signal credibility.
    tracker.post_stake("agent-a", 100)
    assert tracker.get_stake("agent-a") == 100

    # Agent B slashes Agent A for 30 after observing misbehavior.
    tracker.slash_stake("agent-a", 30)
    assert tracker.get_stake("agent-a") == 70


def test_unstaked_agent_has_zero_balance() -> None:
    tracker = AgentStakeTracker()
    assert tracker.get_stake("never-staked") == 0


def test_negative_amounts_are_rejected() -> None:
    tracker = AgentStakeTracker()

    with pytest.raises(ValueError, match="non-negative"):
        tracker.post_stake("agent-a", -1)
    with pytest.raises(ValueError, match="non-negative"):
        tracker.slash_stake("agent-a", -1)
