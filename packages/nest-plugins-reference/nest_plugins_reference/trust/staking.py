# SPDX-License-Identifier: Apache-2.0
"""Standalone staking primitive for credibility signaling.

Tracks per-agent credibility stakes in plain dicts, without touching the
base ``Trust`` protocol. Agents post stake to signal trustworthiness; other
agents slash it to penalize misbehavior.

Example::

    tracker = AgentStakeTracker()
    tracker.post_stake("agent-a", 100)
    tracker.slash_stake("agent-a", 30)
    assert tracker.get_stake("agent-a") == 70
"""

from __future__ import annotations


class AgentStakeTracker:
    """Tracks credibility stakes per agent.

    Example::

        tracker = AgentStakeTracker()
        tracker.post_stake("agent-a", 100)
    """

    def __init__(self) -> None:
        self._stakes: dict[str, int] = {}

    def post_stake(self, agent_id: str, amount: int) -> int:
        """Add ``amount`` to an agent's stake and return the new balance.

        Example::

            balance = tracker.post_stake("agent-a", 100)
        """
        if amount < 0:
            raise ValueError("amount must be non-negative")
        self._stakes[agent_id] = self._stakes.get(agent_id, 0) + amount
        return self._stakes[agent_id]

    def get_stake(self, agent_id: str) -> int:
        """Return an agent's current stake balance, 0 if never staked.

        Example::

            balance = tracker.get_stake("agent-a")
        """
        return self._stakes.get(agent_id, 0)

    def slash_stake(self, agent_id: str, amount: int) -> int:
        """Remove ``amount`` from an agent's stake and return the new balance.

        Example::

            balance = tracker.slash_stake("agent-a", 30)
        """
        if amount < 0:
            raise ValueError("amount must be non-negative")
        self._stakes[agent_id] = max(self._stakes.get(agent_id, 0) - amount, 0)
        return self._stakes[agent_id]
