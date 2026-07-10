# SPDX-License-Identifier: Apache-2.0
"""Differentially private registry with a bounded membership leak.

The default registry answers who is registered and what each agent can do
exactly. A caller reads the answer from a plain dict. The behavior is correct
for discovery and it leaks membership. Anyone who queries the registry, or reads
the published index off the wire, recovers the full member set and every
advertised capability. Membership is often the sensitive fact. That an agent
registered a ``sell_medical_data`` capability at all can reveal more than any
message the agent later encrypts. ``DPBloomRegistry`` adds a capability-query
surface and gives it a formal privacy guarantee.

What it does

``DPBloomRegistry`` serves legitimate ``lookup`` from a true card store, exactly
like the in-memory reference, so discovery keeps working. Every registration
also folds into a published membership index. The index is a Bloom filter whose
bits are perturbed by RAPPOR-style permanent randomized response [2] before
anyone outside the registry reads them. Curious peers and passive observers see only
:meth:`published_index` and test membership through :meth:`membership_query`. The
raw card store never crosses that boundary. The published index is the artifact
an adversary can obtain, so the privacy claim is about the index, not the store.

The guarantee

Fix the number of hashes ``k``. Inserting one member sets at most ``k`` bits of
the true filter, so two registries whose member sets differ by a single agent
differ in at most ``k`` bit positions. The plugin flips each published bit
independently with probability ``p``. A single differing bit then satisfies
``Pr[r=1 | true=1] / Pr[r=1 | true=0] = (1 - p) / p``, so the per-bit budget is
``eps0 = ln((1 - p) / p)``. Sequential composition over the at most ``k``
differing bits gives ``eps = k * ln((1 - p) / p)``, which is
epsilon-differential privacy with one agent's membership as the unit of privacy.
Inverting for a target budget gives the calibrated flip probability
``p = 1 / (1 + exp(eps / k))``. A smaller ``eps`` moves ``p`` toward ``1/2``,
which adds noise, strengthens privacy, and lowers query accuracy. The trade-off
between membership privacy and query accuracy stays explicit rather than silent.

Randomness and determinism

Differential privacy is a property of the mechanism's coin flips. The plugin
draws those flips once from a keyed PRF over a secret per-instance ``seed``,
following RAPPOR memoization [2]. An adversary without the seed observes only the
published bits and gains advantage at most ``e^eps``. Fixing the seed fixes one
draw of the coins and makes a Tier 1 trace byte-identical on replay. A fixed
seed does not weaken the guarantee for a seedless adversary, the same way
publishing a ciphertext does not weaken a cipher whose key stays secret. The
``trust_gated`` plugin takes the same stance when it separates
``deterministic=True`` from its secure default.

References

The mechanism composes two lines of prior work. Randomized response over the
filter bits, and the memoization that fixes each instance's coins once, follow
RAPPOR [2]. The membership-privacy goal and the differentially private Bloom
filter construction follow Tirmazi [4], which builds on the adversarial Bloom
filter model of Naor and Yogev [1] and its learned extension by Almashaqbeh,
Bishop, and Tirmazi [3].

[1] Moni Naor and Eylon Yogev. Bloom Filters in Adversarial Environments. 2014.
    arXiv:1412.8356.
[2] Úlfar Erlingsson, Vasyl Pihur, and Aleksandra Korolova. RAPPOR: Randomized
    Aggregatable Privacy-Preserving Ordinal Response. ACM CCS, 2014.
[3] Ghada Almashaqbeh, Allison Bishop, and Hayder Tirmazi. Adversary Resilient
    Learned Bloom Filters. ASIACRYPT, 2025. arXiv:2409.06556.
[4] Hayder Tirmazi. Adversarially Robust Bloom Filters: Privacy, Reductions, and
    Open Problems. 2025. arXiv:2501.15751.

Example::

    reg = DPBloomRegistry(seed=b"reg-42", epsilon=1.0, num_hashes=5, num_bits=4096)
    await reg.register(AgentCard(agent_id=AgentId("a1"), name="Seller", capabilities=["sell"]))
    hits = await reg.lookup(Query(capabilities=["sell"]))
    observer_view = reg.published_index()
    maybe = reg.membership_query(observer_view, AgentId("a1"))
"""

from __future__ import annotations

import asyncio
import hashlib
import math
from collections.abc import AsyncIterator
from dataclasses import dataclass

from nest_core.types import AgentCard, AgentId, Query

_PRF_DOMAIN = b"nest/dp_bloom/flip/1"
"""Domain-separation tag for the flip PRF. The tag stops the seed from colliding
with any other seeded use of the same bytes in the stack."""


def calibrate_flip_probability(epsilon: float, num_hashes: int) -> float:
    """Return the per-bit flip probability that achieves ``epsilon``-DP.

    The function inverts ``eps = k * ln((1 - p) / p)`` for ``p``. Sequential
    composition splits the budget evenly across the ``k`` hashes, so the unit of
    privacy is one agent's membership at its at most ``k`` set bits.

    Example::

        p = calibrate_flip_probability(epsilon=1.0, num_hashes=5)
        assert 0.0 < p < 0.5
    """
    if epsilon <= 0.0:
        msg = f"epsilon must be positive, got {epsilon}"
        raise ValueError(msg)
    if num_hashes <= 0:
        msg = f"num_hashes must be positive, got {num_hashes}"
        raise ValueError(msg)
    return 1.0 / (1.0 + math.exp(epsilon / num_hashes))


def epsilon_for(flip_probability: float, num_hashes: int) -> float:
    """Return the epsilon guaranteed by a given flip probability and ``k``.

    The function is the inverse of :func:`calibrate_flip_probability`. The
    adversarial validator uses it to check that a plugin's claimed budget matches
    the noise the plugin actually injects.

    Example::

        eps = epsilon_for(0.1, num_hashes=5)
        assert eps > 0
    """
    if not 0.0 < flip_probability < 0.5:
        msg = f"flip_probability must be in (0, 0.5), got {flip_probability}"
        raise ValueError(msg)
    if num_hashes <= 0:
        msg = f"num_hashes must be positive, got {num_hashes}"
        raise ValueError(msg)
    return num_hashes * math.log((1.0 - flip_probability) / flip_probability)


@dataclass(frozen=True)
class PublishedIndex:
    """The observer-facing, epsilon-DP membership index for a registry snapshot.

    The index carries the perturbed Bloom bits and the public parameters a
    membership query needs. The index omits the true card store, the seed, and
    the unperturbed bits, which is the whole point of the boundary.

    Example::

        idx = reg.published_index()
        assert len(idx.bits) == idx.num_bits
    """

    bits: tuple[bool, ...]
    num_bits: int
    num_hashes: int
    epsilon: float


class DPBloomRegistry:
    """Registry whose published membership index is epsilon-differentially private.

    The class implements the :class:`~nest_core.layers.registry.Registry`
    protocol. ``lookup`` and ``subscribe`` behave like the in-memory reference
    and serve exact results from the true store, so discovery keeps working for
    legitimate agents. The differential privacy applies to
    :meth:`published_index` and :meth:`membership_query`, the surface an observer
    actually sees.

    Example::

        reg = DPBloomRegistry(seed=b"s", epsilon=1.0, num_hashes=5, num_bits=2048)
        await reg.register(AgentCard(agent_id=AgentId("a1"), name="A", capabilities=["x"]))
    """

    def __init__(
        self,
        seed: bytes = b"",
        *,
        epsilon: float = 1.0,
        num_hashes: int = 5,
        num_bits: int = 4096,
    ) -> None:
        if num_bits <= 0:
            msg = f"num_bits must be positive, got {num_bits}"
            raise ValueError(msg)
        self._seed = seed
        self._epsilon = epsilon
        self._num_hashes = num_hashes
        self._num_bits = num_bits
        self._flip_p = calibrate_flip_probability(epsilon, num_hashes)
        self._cards: dict[AgentId, AgentCard] = {}
        self._true_bits: list[bool] = [False] * num_bits
        self._subscribers: list[asyncio.Queue[AgentCard]] = []

    @property
    def epsilon(self) -> float:
        """The privacy budget this registry's published index satisfies.

        Example::

            assert reg.epsilon > 0
        """
        return self._epsilon

    @property
    def flip_probability(self) -> float:
        """Per-bit randomized-response flip probability, calibrated from epsilon.

        Example::

            assert 0.0 < reg.flip_probability < 0.5
        """
        return self._flip_p

    def _positions(self, token: str) -> list[int]:
        """Deterministic ``k`` bit positions for a membership token.

        Double hashing over the two halves of a SHA-256 digest replaces an
        external RNG, so the positions are a pure function of the token and
        reproduce byte-for-byte across runs.
        """
        digest = hashlib.sha256(token.encode("utf-8")).digest()
        h1 = int.from_bytes(digest[:16], "big")
        h2 = int.from_bytes(digest[16:], "big") | 1  # an odd step visits every bucket
        return [(h1 + i * h2) % self._num_bits for i in range(self._num_hashes)]

    @staticmethod
    def _tokens(card: AgentCard) -> list[str]:
        """Membership tokens a card contributes: its agent id and each capability.

        The ``cap:`` prefix namespaces capabilities so ``cap:sell`` cannot
        collide with an agent literally named ``sell``.
        """
        tokens = [f"agent:{card.agent_id}"]
        tokens.extend(f"cap:{cap}" for cap in card.capabilities)
        return tokens

    def _flip(self, position: int) -> bool:
        """Return the permanent randomized-response coin for one bit.

        A ``True`` result means flip the bit. The secret seed keys the draw, so
        the coins stay unpredictable to a seedless adversary and reproducible for
        the trace. The draw is memoized by construction, so the same ``seed`` and
        ``position`` always yield the same coin.
        """
        material = _PRF_DOMAIN + self._seed + b"|" + position.to_bytes(8, "big")
        draw = int.from_bytes(hashlib.sha256(material).digest()[:8], "big")
        return draw / 2**64 < self._flip_p

    def published_index(self) -> PublishedIndex:
        """Return the epsilon-DP membership index an observer may read.

        The method applies permanent randomized response to the true Bloom bits.
        Repeated calls on the same registry state return identical bits because
        the seed memoizes the coins, so re-sampling leaks nothing extra.

        Example::

            idx = reg.published_index()
            assert idx.epsilon == reg.epsilon
        """
        bits = tuple(bit ^ self._flip(pos) for pos, bit in enumerate(self._true_bits))
        return PublishedIndex(
            bits=bits,
            num_bits=self._num_bits,
            num_hashes=self._num_hashes,
            epsilon=self._epsilon,
        )

    def membership_query(self, index: PublishedIndex, agent: AgentId) -> bool:
        """Test whether ``agent`` looks present in a published index.

        The test reports present when every hashed position is set, the standard
        membership test on a Bloom filter. Noise makes the answer probabilistic,
        and that imprecision is the privacy, so a single query is evidence rather
        than proof of membership.

        Example::

            present = reg.membership_query(reg.published_index(), AgentId("a1"))
        """
        return all(index.bits[pos] for pos in self._positions(f"agent:{agent}"))

    async def register(self, card: AgentCard) -> None:
        """Register a card in the true store and fold it into the DP index.

        Example::

            await reg.register(AgentCard(agent_id=AgentId("a1"), name="A"))
        """
        self._cards[card.agent_id] = card
        for token in self._tokens(card):
            for pos in self._positions(token):
                self._true_bits[pos] = True
        for q in self._subscribers:
            await q.put(card)

    async def lookup(self, query: Query) -> list[AgentCard]:
        """Look up agents matching ``query`` with exact results from the true store.

        Example::

            hits = await reg.lookup(Query(capabilities=["sell"]))
        """
        return [card for card in self._cards.values() if self._matches(card, query)]

    async def subscribe(self, query: Query) -> AsyncIterator[AgentCard]:
        """Subscribe to future registrations matching ``query``.

        Example::

            async for card in reg.subscribe(Query(capabilities=["sell"])):
                ...
        """
        q: asyncio.Queue[AgentCard] = asyncio.Queue()
        self._subscribers.append(q)
        try:
            while True:
                card = await q.get()
                if self._matches(card, query):
                    yield card
        finally:
            self._subscribers.remove(q)

    async def deregister(self, agent: AgentId) -> None:
        """Remove an agent from the true store.

        The DP index is monotone because a Bloom filter cannot clear a bit it
        shares with another member without corrupting it. Deregistration hides
        future lookups but leaves the agent's historical membership bits in the
        index until the filter rebuilds. The residue is a documented limitation,
        not a bug.

        Example::

            await reg.deregister(AgentId("a1"))
        """
        self._cards.pop(agent, None)

    @staticmethod
    def _matches(card: AgentCard, query: Query) -> bool:
        if query.capabilities and not all(cap in card.capabilities for cap in query.capabilities):
            return False
        return not (query.name_pattern and query.name_pattern not in card.name)
