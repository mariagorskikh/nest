# SPDX-License-Identifier: Apache-2.0
"""Pluggable scarcity anchors for :class:`~...trust.bonded_trust.BondedTrust`.

`bonded_trust` gates a trust root on a bond, but is deliberately agnostic about
*what makes the bond scarce*. Any :class:`~...trust.bonded_trust.StakeLedger`
will do — the Sybil-resistance argument only needs the anchor to be finite and
non-forgeable. This module ships two, to show the anchor is genuinely swappable:

* :class:`CreditBackedLedger` — scarcity = the **payments layer's** finite credit
  balances. Reserving a bond debits real credits.
* :class:`ProofOfWorkLedger` — scarcity = **computational work**. A bond unit
  must be backed by a proof-of-work solution, so minting K identities costs K×
  the work. No payments layer, no trusted mint — just CPU. (A consensus-gated
  allocator fits the same interface: quorum grants budget instead of hashes.)

Both are deterministic, so Tier-1 traces stay byte-reproducible.
"""

from __future__ import annotations

import hashlib

from nest_core.types import AgentId


class CreditBackedLedger:
    """Scarcity anchored in a finite, shared credit ledger (the payments layer).

    Construct with the payments plugin's ``balances`` dict; reserving a bond
    debits it, so total bond across every agent is bounded by the credit supply.

    Example::

        ledger = CreditBackedLedger({AgentId("a1"): 100})
        assert ledger.reserve(AgentId("a1"), 150) == 100  # clamped to balance
    """

    def __init__(self, balances: dict[AgentId, int]) -> None:
        self._balances = balances

    def balance(self, agent: AgentId) -> int:
        """Remaining spendable balance for *agent*.

        Example::

            bal = ledger.balance(AgentId("a1"))
        """
        return self._balances.get(agent, 0)

    def reserve(self, agent: AgentId, amount: int) -> int:
        """Reserve up to ``amount`` of *agent*'s balance, debiting what is taken.

        Example::

            taken = ledger.reserve(AgentId("a1"), 100)
        """
        available = self._balances.get(agent, 0)
        take = min(available, max(0, amount))
        self._balances[agent] = available - take
        return take


class ProofOfWorkLedger:
    """Scarcity anchored in computational work — no credits, no trusted mint.

    Each unit of bond must be backed by a proof-of-work: a nonce whose
    ``sha256(agent:counter:nonce)`` has ``difficulty_bits`` leading zero bits.
    :meth:`mine` finds them deterministically (scanning nonces in order), so a
    swarm minting many identities pays the work for each — the anchor is CPU,
    not a balance a Sybil can conjure.

    Example::

        pow_ledger = ProofOfWorkLedger(difficulty_bits=8)
        assert pow_ledger.mine(AgentId("a1"), 2) == 2   # earns 2 units of bond
        assert pow_ledger.reserve(AgentId("a1"), 2) == 2
    """

    def __init__(self, difficulty_bits: int = 12) -> None:
        if not 1 <= difficulty_bits <= 32:
            msg = f"difficulty_bits must be in 1..32; got {difficulty_bits}"
            raise ValueError(msg)
        self._difficulty = difficulty_bits
        self._budget: dict[AgentId, int] = {}
        # Counters already redeemed per agent — the anti-replay set. A given
        # (agent, counter) may be proven at most once, so a solution can't be
        # resubmitted to inflate budget.
        self._redeemed: dict[AgentId, set[int]] = {}
        # High-water counter per agent so successive mine() calls earn *fresh*
        # work rather than re-finding the same nonces.
        self._next_counter: dict[AgentId, int] = {}

    def _solved(self, agent: AgentId, counter: int, nonce: int) -> bool:
        digest = hashlib.sha256(f"{agent}:{counter}:{nonce}".encode()).digest()
        return int.from_bytes(digest[:4], "big") >> (32 - self._difficulty) == 0

    def solve(self, agent: AgentId, counter: int) -> int:
        """Find a valid nonce for ``(agent, counter)`` by scanning in order.

        This is the work: the caller (or :meth:`mine`) pays CPU to find it, and
        the search is deterministic so traces stay reproducible.

        Example::

            nonce = pow_ledger.solve(AgentId("a1"), 0)
        """
        nonce = 0
        while not self._solved(agent, counter, nonce):
            nonce += 1
        return nonce

    def prove(self, agent: AgentId, counter: int, nonce: int) -> bool:
        """Verify one proof-of-work solution and, if valid and unseen, grant a unit.

        A ``(agent, counter)`` pair can be redeemed only once; resubmitting a
        solution (replay) returns ``False`` and grants nothing.

        Example::

            ok = pow_ledger.prove(AgentId("a1"), 0, 4211)
        """
        redeemed = self._redeemed.setdefault(agent, set())
        if counter in redeemed:
            return False  # replay — already redeemed
        if self._solved(agent, counter, nonce):
            redeemed.add(counter)
            self._budget[agent] = self._budget.get(agent, 0) + 1
            return True
        return False

    def mine(self, agent: AgentId, count: int) -> int:
        """Deterministically mine ``count`` *fresh* proofs for *agent*; returns units earned.

        Each call advances the agent's counter high-water, so mining always costs
        new work and never re-redeems an earlier solution.

        Example::

            earned = pow_ledger.mine(AgentId("a1"), 3)
        """
        earned = 0
        start = self._next_counter.get(agent, 0)
        for counter in range(start, start + count):
            if self.prove(agent, counter, self.solve(agent, counter)):
                earned += 1
        self._next_counter[agent] = start + count
        return earned

    def reserve(self, agent: AgentId, amount: int) -> int:
        """Reserve up to ``amount`` of *agent*'s mined budget, debiting what is taken.

        Example::

            taken = pow_ledger.reserve(AgentId("a1"), 2)
        """
        available = self._budget.get(agent, 0)
        take = min(available, max(0, amount))
        self._budget[agent] = available - take
        return take
