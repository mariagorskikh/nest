# SPDX-License-Identifier: Apache-2.0
"""Tests for the ``dp_bloom`` differentially private registry and its validator.

The suite covers four properties. The epsilon and flip-probability calibration
is a correct inverse pair. Legitimate ``lookup`` stays exact, since differential
privacy applies to the published index and not to in-registry discovery. The
published index is byte-deterministic under a fixed seed and seed-sensitive
across seeds. The adversarial membership-inference validator passes ``dp_bloom``
and fails the exact ``in_memory`` reference, which is the charter's mandatory
fail-then-pass gate.
"""

from __future__ import annotations

import asyncio

import pytest
from nest_core.types import AgentCard, AgentId, Query
from nest_plugins_reference.registry.dp_bloom import (
    DPBloomRegistry,
    calibrate_flip_probability,
    epsilon_for,
)
from nest_plugins_reference.registry.in_memory import InMemoryRegistry
from nest_plugins_reference.validators.dp_bloom_validators import (
    check_membership_inference_bounded,
)

_EPS = 3.0
_K = 3
_BITS = 512
_BACKGROUND = [
    AgentCard(agent_id=AgentId(f"bg-{i}"), name=f"BG{i}", capabilities=["sell"]) for i in range(8)
]
_TARGET = AgentCard(agent_id=AgentId("target"), name="Target", capabilities=["sell"])


def test_calibration_is_an_inverse_pair() -> None:
    p = calibrate_flip_probability(_EPS, _K)
    assert 0.0 < p < 0.5
    assert epsilon_for(p, _K) == pytest.approx(_EPS)


def test_smaller_epsilon_means_more_noise() -> None:
    # A tighter privacy budget must push the flip probability toward 1/2.
    assert calibrate_flip_probability(1.0, _K) > calibrate_flip_probability(3.0, _K)


@pytest.mark.parametrize("bad", [0.0, -1.0])
def test_non_positive_epsilon_rejected(bad: float) -> None:
    with pytest.raises(ValueError, match="epsilon must be positive"):
        calibrate_flip_probability(bad, _K)


def test_lookup_is_exact_despite_privacy() -> None:
    reg = DPBloomRegistry(seed=b"s", epsilon=_EPS, num_hashes=_K, num_bits=_BITS)

    async def run() -> list[AgentCard]:
        for card in _BACKGROUND:
            await reg.register(card)
        await reg.register(AgentCard(agent_id=AgentId("buyer"), name="Buyer", capabilities=["buy"]))
        return await reg.lookup(Query(capabilities=["sell"]))

    hits = asyncio.run(run())
    assert {c.agent_id for c in hits} == {c.agent_id for c in _BACKGROUND}


def _build_index_bits(seed: bytes) -> tuple[bool, ...]:
    reg = DPBloomRegistry(seed=seed, epsilon=_EPS, num_hashes=_K, num_bits=_BITS)

    async def run() -> tuple[bool, ...]:
        for card in _BACKGROUND:
            await reg.register(card)
        return reg.published_index().bits

    return asyncio.run(run())


def test_published_index_is_deterministic_under_fixed_seed() -> None:
    assert _build_index_bits(b"seed-42") == _build_index_bits(b"seed-42")


def test_published_index_depends_on_seed() -> None:
    # Different secret seeds draw different randomized-response coins.
    assert _build_index_bits(b"seed-42") != _build_index_bits(b"seed-7")


def _dp_bloom_oracle(seed: int, include_target: bool) -> bool:
    reg = DPBloomRegistry(seed=str(seed).encode(), epsilon=_EPS, num_hashes=_K, num_bits=_BITS)

    async def run() -> bool:
        for card in _BACKGROUND:
            await reg.register(card)
        if include_target:
            await reg.register(_TARGET)
        return reg.membership_query(reg.published_index(), _TARGET.agent_id)

    return asyncio.run(run())


def _in_memory_oracle(_seed: int, include_target: bool) -> bool:
    reg = InMemoryRegistry()

    async def run() -> bool:
        for card in _BACKGROUND:
            await reg.register(card)
        if include_target:
            await reg.register(_TARGET)
        cards = await reg.lookup(Query())
        return any(card.agent_id == _TARGET.agent_id for card in cards)

    return asyncio.run(run())


def test_validator_passes_dp_bloom() -> None:
    report = check_membership_inference_bounded(_dp_bloom_oracle, _EPS)
    assert report.passed, report.detail
    assert report.evidence["empirical_epsilon"] <= report.evidence["threshold"]  # type: ignore[operator]


def test_validator_fails_exact_registry() -> None:
    report = check_membership_inference_bounded(_in_memory_oracle, _EPS)
    assert not report.passed, report.detail
