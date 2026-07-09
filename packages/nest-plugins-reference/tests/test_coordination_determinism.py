# SPDX-License-Identifier: Apache-2.0
"""Determinism regression tests for coordination round identifiers.

These tests fail against the previous ``uuid.uuid4`` implementation of
``ContractNet.propose`` / ``HotStuff.propose`` (which minted a fresh id every
run) and pass once round ids are derived deterministically from
``(agent, task, seq)``. They pin ADR-004 (seeded-determinism) for the
coordination layer: the same logical proposal sequence must produce
byte-identical ids across independent runs, so a seeded trace can be diffed
and replayed.
"""

from __future__ import annotations

import hashlib

from hypothesis import given
from hypothesis import strategies as st
from nest_core.types import AgentId, Task
from nest_plugins_reference.coordination._ids import derive_round_id
from nest_plugins_reference.coordination.contract_net import ContractNet
from nest_plugins_reference.coordination.hotstuff import HotStuff


def _task(i: int = 1) -> Task:
    return Task(id=f"t{i}", description="work")


async def _propose_ids(coord: ContractNet | HotStuff, n: int) -> list[str]:
    """Return the round ids from proposing ``n`` successive tasks."""
    return [(await coord.propose(_task(i))).id for i in range(n)]


class TestReplayDeterminism:
    """The same logical run must produce byte-identical round ids."""

    async def test_contract_net_replays_identically(self) -> None:
        run1 = await _propose_ids(ContractNet(AgentId("manager")), 5)
        run2 = await _propose_ids(ContractNet(AgentId("manager")), 5)
        assert run1 == run2

    async def test_hotstuff_replays_identically(self) -> None:
        run1 = await _propose_ids(HotStuff(AgentId("r0")), 5)
        run2 = await _propose_ids(HotStuff(AgentId("r0")), 5)
        assert run1 == run2


class TestUniqueness:
    """Distinct rounds must still get distinct ids (no regression in function)."""

    async def test_successive_rounds_are_distinct(self) -> None:
        ids = await _propose_ids(ContractNet(AgentId("manager")), 50)
        assert len(set(ids)) == len(ids)

    async def test_distinct_proposers_are_distinct(self) -> None:
        a = (await ContractNet(AgentId("a")).propose(_task())).id
        b = (await ContractNet(AgentId("b")).propose(_task())).id
        assert a != b

    async def test_contract_net_and_hotstuff_share_the_scheme(self) -> None:
        # Same (agent, task, seq) yields the same id regardless of plugin,
        # because both derive it from the shared helper.
        cn = (await ContractNet(AgentId("x")).propose(_task(1))).id
        hs = (await HotStuff(AgentId("x")).propose(_task(1))).id
        assert cn == hs == derive_round_id(AgentId("x"), "t1", 1)


class TestDeriveRoundId:
    """Unit properties of the id derivation itself."""

    def test_is_pure(self) -> None:
        assert derive_round_id(AgentId("r0"), "t1", 1) == derive_round_id(AgentId("r0"), "t1", 1)

    def test_uses_no_ambient_state(self) -> None:
        # Recomputing after unrelated work (which would perturb any RNG or
        # clock-based scheme) yields the identical id.
        first = derive_round_id(AgentId("r0"), "t1", 7)
        _ = [hashlib.sha256(str(i).encode()).hexdigest() for i in range(1000)]
        assert derive_round_id(AgentId("r0"), "t1", 7) == first

    def test_encoding_is_injective(self) -> None:
        # Length-prefixing prevents boundary-ambiguity collisions that plain
        # concatenation would allow.
        assert derive_round_id(AgentId("ab"), "c", 0) != derive_round_id(AgentId("a"), "bc", 0)

    @given(
        agent=st.text(min_size=1, max_size=16),
        task=st.text(min_size=1, max_size=16),
        seq=st.integers(min_value=0, max_value=1_000_000),
    )
    def test_deterministic_over_arbitrary_inputs(self, agent: str, task: str, seq: int) -> None:
        assert derive_round_id(AgentId(agent), task, seq) == derive_round_id(
            AgentId(agent), task, seq
        )
