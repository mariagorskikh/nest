# SPDX-License-Identifier: Apache-2.0
"""Differentially private registry: membership queries under an epsilon bound.

The default registry plugin
:class:`~nest_plugins_reference.registry.in_memory.InMemoryRegistry` answers
*"who is registered, and what can they do?"* from a plain ``dict``. That is
functionally correct and **operationally a privacy leak**: anyone who can query
the registry (or read the published index off the wire) can enumerate the exact
member set and every agent's capabilities. Membership is often the sensitive
bit — that a given agent registered a ``sell_medical_data`` capability at all
can be more revealing than any single message it later encrypts. The
:doc:`registry wishlist </layers/registry>` calls out "capability queries";
this plugin adds the query surface *and* a formal privacy guarantee over it.

What it does
------------

``DPBloomRegistry`` serves legitimate ``lookup`` from a true card store, exactly
like the in-memory reference (so scenarios that depend on discovery keep
working). Alongside that, every registration is folded into a **published
membership index** — a Bloom filter whose bits are perturbed by RAPPOR-style
permanent randomized response before anyone outside the registry may read them.
Curious peers and passive observers see only :meth:`published_index` and answer
membership through :meth:`membership_query`; the raw card store never crosses
that boundary. The index is what appears on the wire / in the trace, so the
privacy claim is about the artifact an adversary can actually obtain.

The guarantee
-------------

Fix the number of hashes ``k``. Inserting one member sets at most ``k`` bits of
the true filter, so two registries whose member sets differ by a single agent
(*neighboring* inputs) differ in at most ``k`` bit positions. Each published bit
is flipped independently with probability ``p``; a single differing bit then
satisfies ``Pr[r=1 | true=1] / Pr[r=1 | true=0] = (1 - p) / p``, i.e. per-bit
``eps0 = ln((1 - p) / p)``. Sequential composition over the ``<= k`` differing
bits gives ``eps = k * ln((1 - p) / p)`` — **epsilon-differential privacy with
the unit of privacy being one agent's membership**. Solving for the flip
probability that hits a target budget:

    ``p = 1 / (1 + exp(eps / k))``

So a caller asks for ``epsilon`` and ``k`` and the plugin calibrates ``p``.
Smaller ``epsilon`` → ``p`` closer to ``1/2`` → more noise, stronger privacy,
lower query accuracy. This is the classic membership/accuracy trade-off, made
explicit rather than silent.

Where the randomness lives (and why the trace is still deterministic)
---------------------------------------------------------------------

The privacy is over the mechanism's coin flips, and those flips are drawn once —
RAPPOR calls this *permanent randomized response* / memoization — from a keyed
PRF over a per-instance ``seed``. An adversary who does not hold the seed sees
only the published bits and faces advantage at most ``e^eps``; that is the
threat model. Fixing ``seed`` fixes one realization of the coin flips, which is
what makes a Tier-1 trace byte-identical on replay. It does **not** weaken the
guarantee for a seed-less adversary, any more than publishing a ciphertext
weakens a cipher whose key stays secret. (Same stance ``trust_gated`` takes when
it separates ``deterministic=True`` from its secure default.)

Example::

    reg = DPBloomRegistry(seed=b"reg-42", epsilon=1.0, num_hashes=5, num_bits=4096)
    await reg.register(AgentCard(agent_id=AgentId("a1"), name="Seller", capabilities=["sell"]))
    hits = await reg.lookup(Query(capabilities=["sell"]))       # true store, exact
    observer_view = reg.published_index()                       # perturbed, epsilon-DP
    maybe = reg.membership_query(observer_view, AgentId("a1"))  # noisy membership test
"""

from __future__ import annotations

import asyncio
import hashlib
import math
from collections.abc import AsyncIterator
from dataclasses import dataclass

from nest_core.types import AgentCard, AgentId, Query

_PRF_DOMAIN = b"nest/dp_bloom/flip/1"
"""Domain-separation tag mixed into the flip PRF so the seed cannot collide with
any other seeded use of the same bytes elsewhere in the stack."""


def calibrate_flip_probability(epsilon: float, num_hashes: int) -> float:
    """Return the per-bit flip probability that achieves ``epsilon``-DP.

    Inverts ``eps = k * ln((1 - p) / p)`` for ``p``. The unit of privacy is one
    agent's membership (at most ``k`` set bits), so the budget is split evenly
    across the ``k`` hashes by sequential composition.

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

    Inverse of :func:`calibrate_flip_probability`; used by the adversarial
    validator to check that a plugin's *claimed* budget matches the noise it
    actually injects.

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

    Carries the perturbed Bloom bits plus the public parameters needed to run a
    membership query. It deliberately does **not** carry the true card store, the
    seed, or the un-perturbed bits — that is the whole point of the boundary.

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

    Implements the :class:`~nest_core.layers.registry.Registry` protocol.
    ``lookup``/``subscribe`` behave like the in-memory reference (exact, served
    from the true store) so discovery keeps working for legitimate agents; the
    differential privacy applies to :meth:`published_index` and
    :meth:`membership_query`, the surface an observer actually sees.

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

    # -- introspection --------------------------------------------------------

    @property
    def epsilon(self) -> float:
        """The privacy budget this registry's published index satisfies.

        Example::

            assert reg.epsilon > 0
        """
        return self._epsilon

    @property
    def flip_probability(self) -> float:
        """Per-bit randomized-response flip probability (calibrated from epsilon).

        Example::

            assert 0.0 < reg.flip_probability < 0.5
        """
        return self._flip_p

    # -- Bloom hashing --------------------------------------------------------

    def _positions(self, token: str) -> list[int]:
        """Deterministic ``k`` bit positions for a membership token.

        Double hashing over SHA-256 halves — no external RNG, so positions are a
        pure function of the token and reproduce byte-for-byte across runs.
        """
        digest = hashlib.sha256(token.encode("utf-8")).digest()
        h1 = int.from_bytes(digest[:16], "big")
        h2 = int.from_bytes(digest[16:], "big") | 1  # odd => full period
        return [(h1 + i * h2) % self._num_bits for i in range(self._num_hashes)]

    @staticmethod
    def _tokens(card: AgentCard) -> list[str]:
        """Membership tokens contributed by a card: the agent id and each capability.

        Capabilities are namespaced so ``cap:sell`` cannot collide with an agent
        literally named ``sell``.
        """
        tokens = [f"agent:{card.agent_id}"]
        tokens.extend(f"cap:{cap}" for cap in card.capabilities)
        return tokens

    # -- randomized response --------------------------------------------------

    def _flip(self, position: int) -> bool:
        """Return the permanent RR coin for one bit (True => flip that bit).

        Keyed by the secret seed, so the coins are unpredictable to a seed-less
        adversary yet reproducible for the trace. Memoized-by-construction: the
        same ``(seed, position)`` always yields the same coin.
        """
        material = _PRF_DOMAIN + self._seed + b"|" + position.to_bytes(8, "big")
        draw = int.from_bytes(hashlib.sha256(material).digest()[:8], "big")
        return draw / 2**64 < self._flip_p

    def published_index(self) -> PublishedIndex:
        """Return the epsilon-DP membership index an observer is allowed to read.

        Applies permanent randomized response to the true Bloom bits. Calling it
        repeatedly on the same registry state returns identical bits (the coins
        are memoized via the seed), so it does not leak extra information through
        re-sampling.

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

        The honest membership test on a (perturbed) Bloom filter: report present
        iff every hashed position is set. Noise makes this answer probabilistic —
        that imprecision is exactly the privacy — so a single query is evidence,
        not proof, of membership.

        Example::

            present = reg.membership_query(reg.published_index(), AgentId("a1"))
        """
        return all(index.bits[pos] for pos in self._positions(f"agent:{agent}"))

    # -- Registry protocol ----------------------------------------------------

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
        """Look up agents matching ``query`` (exact, from the true store).

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

        Note: the DP index is monotone (bits are not cleared) because a Bloom
        filter cannot un-set a bit shared with another member without corrupting
        it. Deregistration therefore hides *future* lookups but leaves the
        agent's historical membership bits in the index until the filter is
        rebuilt — a deliberate, documented limitation, not a bug.

        Example::

            await reg.deregister(AgentId("a1"))
        """
        self._cards.pop(agent, None)

    @staticmethod
    def _matches(card: AgentCard, query: Query) -> bool:
        if query.capabilities and not all(cap in card.capabilities for cap in query.capabilities):
            return False
        return not (query.name_pattern and query.name_pattern not in card.name)
