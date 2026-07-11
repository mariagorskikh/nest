# SPDX-License-Identifier: Apache-2.0
"""Determinism regression tests for negotiation session identifiers.

These tests fail against the previous ``uuid.uuid4`` implementation of
``AlternatingOffers.open`` (which minted a fresh id every run) and pass once
session ids are derived deterministically from ``(initiator, partner, seq)``.
They pin ADR-004 (seeded-determinism) for the negotiation layer: the same
logical sequence of opened negotiations must produce byte-identical ids across
independent runs, so a seeded trace can be diffed and replayed. Sibling of
``test_coordination_determinism`` for the coordination layer.
"""

from __future__ import annotations

import hashlib

from hypothesis import given
from hypothesis import strategies as st
from nest_core.types import AgentId, Money, Terms
from nest_plugins_reference.negotiation._ids import derive_session_id
from nest_plugins_reference.negotiation.alternating_offers import AlternatingOffers


def _terms() -> Terms:
    return Terms(price=Money(amount=100))


async def _open_ids(neg: AlternatingOffers, partner: AgentId, n: int) -> list[str]:
    """Return the session ids from opening ``n`` successive negotiations."""
    return [(await neg.open(partner, _terms())).id for _ in range(n)]


class TestReplayDeterminism:
    """The same logical run must produce byte-identical session ids."""

    async def test_open_replays_identically(self) -> None:
        run1 = await _open_ids(AlternatingOffers(AgentId("a1")), AgentId("a2"), 5)
        run2 = await _open_ids(AlternatingOffers(AgentId("a1")), AgentId("a2"), 5)
        assert run1 == run2


class TestUniqueness:
    """Distinct sessions must still get distinct ids (no regression in function)."""

    async def test_successive_sessions_are_distinct(self) -> None:
        ids = await _open_ids(AlternatingOffers(AgentId("a1")), AgentId("a2"), 50)
        assert len(set(ids)) == len(ids)

    async def test_distinct_partners_are_distinct(self) -> None:
        neg = AlternatingOffers(AgentId("a1"))
        a = (await neg.open(AgentId("a2"), _terms())).id
        b = (await neg.open(AgentId("a3"), _terms())).id
        assert a != b

    async def test_distinct_initiators_are_distinct(self) -> None:
        a = (await AlternatingOffers(AgentId("x")).open(AgentId("p"), _terms())).id
        b = (await AlternatingOffers(AgentId("y")).open(AgentId("p"), _terms())).id
        assert a != b


class TestDeriveSessionId:
    """Unit properties of the id derivation itself."""

    def test_is_pure(self) -> None:
        assert derive_session_id(AgentId("a1"), AgentId("a2"), 1) == derive_session_id(
            AgentId("a1"), AgentId("a2"), 1
        )

    def test_uses_no_ambient_state(self) -> None:
        # Recomputing after unrelated work (which would perturb any RNG or
        # clock-based scheme) yields the identical id.
        first = derive_session_id(AgentId("a1"), AgentId("a2"), 7)
        _ = [hashlib.sha256(str(i).encode()).hexdigest() for i in range(1000)]
        assert derive_session_id(AgentId("a1"), AgentId("a2"), 7) == first

    def test_encoding_is_injective(self) -> None:
        # Length-prefixing prevents boundary-ambiguity collisions that plain
        # concatenation would allow.
        assert derive_session_id(AgentId("ab"), AgentId("c"), 0) != derive_session_id(
            AgentId("a"), AgentId("bc"), 0
        )

    @given(
        initiator=st.text(min_size=1, max_size=16),
        partner=st.text(min_size=1, max_size=16),
        seq=st.integers(min_value=0, max_value=1_000_000),
    )
    def test_deterministic_over_arbitrary_inputs(self, initiator: str, partner: str, seq: int) -> None:
        assert derive_session_id(AgentId(initiator), AgentId(partner), seq) == derive_session_id(
            AgentId(initiator), AgentId(partner), seq
        )
