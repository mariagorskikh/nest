# SPDX-License-Identifier: Apache-2.0
"""Capability-conformance registry gate — a signature is not a verified skill.

``AgentCard.capabilities`` (``nest_core.types``) is a bare, self-asserted
``list[str]``. Every existing defense in this repo — signed cards
(``ed25519_rotating``, ``byzantine_gossip``), scored reputation
(``agent_receipts``, ``score_average``) — proves who published a claim or how
an agent behaves *overall*. None of them checks a claim against the specific
behavior it names: an agent can register ``capabilities=["sell"]`` with a
perfectly valid signature and keep being discovered forever even if it never
completes a single sale. That gap is the one A2A v1.0's signed Agent Cards
and NANDA's Verified AgentFacts layer both name and neither closes: signing
proves the publisher, not the capability.

This plugin closes it at the discovery boundary. It wraps an inner registry
and tracks fulfillment/defection evidence **per ``(agent_id, capability)``
pair**, not per agent:

* **Bootstrap allowance.** A pair with no evidence yet is never excluded —
  discovery cannot punish a claim nobody has tested.
* **Per-capability exclusion.** Once a pair accumulates
  ``defection_threshold`` defections, ``lookup`` stops returning that agent
  for queries naming that capability. A defection on ``"sell"`` does not
  affect the same agent's ``"deliver"`` capability — the gate is on the
  claim, not the identity.
* **Re-admission, not blacklisting.** A single ``report_fulfillment`` call
  resets that pair's defection count to zero. This is a known trade-off, not
  an oversight: an attacker who fulfills once per ``defection_threshold - 1``
  defections evades exclusion indefinitely. Closing that requires a
  windowed or decaying counter, out of scope for this gate.

``report_fulfillment``/``report_defection`` are not part of the ``Registry``
Protocol — callers (agents, scenario factories, tests) call them directly on
the concrete instance, the same way ``GossipRegistry`` exposes
``gossip_round`` beyond the interface it implements.

Registered as ``("registry", "verified_capabilities")`` in
``nest_core.plugins``.

Example::

    reg = VerifiedCapabilitiesRegistry()
    await reg.register(AgentCard(agent_id=AgentId("a1"), name="a1", capabilities=["sell"]))
    reg.report_defection(AgentId("a1"), "sell")
    results = await reg.lookup(Query(capabilities=["sell"]))  # [] once excluded
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from nest_core.types import AgentCard, AgentId, Query

from nest_plugins_reference.registry.in_memory import InMemoryRegistry

DEFAULT_DEFECTION_THRESHOLD = 1
"""Defections on a single ``(agent, capability)`` pair before it is excluded.

The reference scenario runs at zero message drop, so there is no transient
noise a legitimate defection could be confused with — one observed silence
past a buyer's timeout is already a real signal, not jitter. Set higher for
a lossy transport, mirroring how ``gossip.py`` ties its convergence bound to
its configured drop rate.
"""


class VerifiedCapabilitiesRegistry:
    """Registry wrapper that gates capability discovery on fulfillment evidence.

    Example::

        reg = VerifiedCapabilitiesRegistry(defection_threshold=1)
        await reg.register(card)
    """

    def __init__(
        self,
        inner: Any = None,
        *,
        defection_threshold: int = DEFAULT_DEFECTION_THRESHOLD,
    ) -> None:
        self._inner = inner if inner is not None else InMemoryRegistry()
        self._threshold = defection_threshold
        self._defections: dict[tuple[AgentId, str], int] = {}

    def _is_excluded(self, agent_id: AgentId, capability: str) -> bool:
        return self._defections.get((agent_id, capability), 0) >= self._threshold

    def _passes_gate(self, card: AgentCard, query: Query) -> bool:
        return not any(self._is_excluded(card.agent_id, cap) for cap in query.capabilities)

    async def register(self, card: AgentCard) -> None:
        """Register an agent card with the inner registry.

        Example::

            await reg.register(card)
        """
        await self._inner.register(card)

    async def lookup(self, query: Query) -> list[AgentCard]:
        """Look up agents matching *query*, excluding gated capability claims.

        A card is dropped iff, for at least one capability named in
        ``query.capabilities``, that ``(agent_id, capability)`` pair has
        reached ``defection_threshold``. Capabilities not named in the query
        never affect inclusion.

        Example::

            results = await reg.lookup(Query(capabilities=["sell"]))
        """
        candidates = await self._inner.lookup(query)
        return [card for card in candidates if self._passes_gate(card, query)]

    async def subscribe(self, query: Query) -> AsyncIterator[AgentCard]:
        """Subscribe to new registrations matching *query*, applying the same gate.

        The gate is evaluated at yield time, so a card excluded when it
        registers but re-admitted later is still delivered once fulfillment
        evidence clears it on a subsequent registration.

        Example::

            async for card in reg.subscribe(query):
                print(card.name)
        """
        async for card in self._inner.subscribe(query):
            if self._passes_gate(card, query):
                yield card

    async def deregister(self, agent: AgentId) -> None:
        """Remove an agent from the inner registry.

        Example::

            await reg.deregister(AgentId("a1"))
        """
        await self._inner.deregister(agent)

    def report_fulfillment(self, agent_id: AgentId, capability: str) -> None:
        """Record that *agent_id* fulfilled an observed *capability* interaction.

        Resets that pair's defection count to zero, re-admitting it to
        ``lookup`` results for that capability if it had been excluded.

        Example::

            reg.report_fulfillment(AgentId("a1"), "sell")
        """
        self._defections[(agent_id, capability)] = 0

    def report_defection(self, agent_id: AgentId, capability: str) -> None:
        """Record that *agent_id* defected on an observed *capability* interaction.

        Increments that pair's defection count; once it reaches
        ``defection_threshold``, the agent stops appearing in ``lookup``
        results for queries naming that capability.

        Example::

            reg.report_defection(AgentId("a1"), "sell")
        """
        key = (agent_id, capability)
        self._defections[key] = self._defections.get(key, 0) + 1
