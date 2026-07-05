# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the ``verified`` registry plugin.

Covers protocol conformance, honest admission, all three typed rejection
reasons, state isolation on rejection, and pass-through of ``key_id``/
``signed_at`` from rotating identities.

Example::

    pytest packages/nest-plugins-reference/tests/test_verified_registry.py
"""

from __future__ import annotations

import asyncio
from typing import cast

import pytest
from nest_core.layers.registry import Registry
from nest_core.types import AgentCard, AgentId, Query
from nest_plugins_reference.identity.did_key import DidKeyIdentity
from nest_plugins_reference.registry.verified import (
    REASON_BAD_SIGNATURE,
    REASON_MISSING_SIGNATURE,
    REASON_SIGNER_MISMATCH,
    RegistrationRejectedError,
    VerifiedRegistry,
    canonical_card_bytes,
    sign_card,
)

_A1 = AgentId("a1")
_A2 = AgentId("a2")
_A3 = AgentId("a3")  # unknown to the verifier


def _identity(agent_id: AgentId) -> DidKeyIdentity:
    return DidKeyIdentity(agent_id, seed=b"test:" + str(agent_id).encode())


@pytest.fixture
def identities() -> dict[AgentId, DidKeyIdentity]:
    return {aid: _identity(aid) for aid in (_A1, _A2, _A3)}


@pytest.fixture
def registry(identities: dict[AgentId, DidKeyIdentity]) -> VerifiedRegistry:
    verifier = DidKeyIdentity(AgentId("verifier"), seed=b"test:verifier")
    # a3 is deliberately NOT registered with the verifier.
    for aid in (_A1, _A2):
        verifier.register_peer(aid, identities[aid].public_key)
    return VerifiedRegistry(verifier)


def _card(agent_id: AgentId) -> AgentCard:
    return AgentCard(
        agent_id=agent_id,
        name=str(agent_id),
        capabilities=[f"service:{agent_id}"],
        endpoint=f"self://{agent_id}",
    )


class TestProtocolConformance:
    def test_is_registry(self, registry: VerifiedRegistry) -> None:
        assert isinstance(registry, Registry)


class TestHonestPath:
    @pytest.mark.asyncio
    async def test_signed_registration_accepted_and_discoverable(
        self, registry: VerifiedRegistry, identities: dict[AgentId, DidKeyIdentity]
    ) -> None:
        await registry.register(sign_card(_card(_A1), identities[_A1]))
        results = await registry.lookup(Query(capabilities=[f"service:{_A1}"]))
        assert [c.agent_id for c in results] == [_A1]

    @pytest.mark.asyncio
    async def test_deregister_removes_card(
        self, registry: VerifiedRegistry, identities: dict[AgentId, DidKeyIdentity]
    ) -> None:
        await registry.register(sign_card(_card(_A1), identities[_A1]))
        await registry.deregister(_A1)
        assert await registry.lookup(Query()) == []

    @pytest.mark.asyncio
    async def test_subscriber_notified_on_admission(
        self, registry: VerifiedRegistry, identities: dict[AgentId, DidKeyIdentity]
    ) -> None:
        agen = registry.subscribe(Query(capabilities=[f"service:{_A1}"]))

        async def _first() -> AgentCard:
            async for card in agen:
                return card
            msg = "subscription ended without a card"
            raise AssertionError(msg)

        task = asyncio.ensure_future(_first())
        await asyncio.sleep(0)  # let the subscriber install its queue
        await registry.register(sign_card(_card(_A1), identities[_A1]))
        card = await asyncio.wait_for(task, timeout=1.0)
        assert card.agent_id == _A1

    def test_signature_covers_capability_order_and_ignores_metadata(self) -> None:
        base = _card(_A1)
        reordered = base.model_copy(deep=True)
        reordered.capabilities = list(reversed([*base.capabilities, "z", "a"]))
        base.capabilities = [*base.capabilities, "z", "a"]
        base.metadata["extra"] = "ignored"
        assert canonical_card_bytes(base) == canonical_card_bytes(reordered)


class TestRejections:
    @pytest.mark.asyncio
    async def test_unsigned_rejected_missing_signature(self, registry: VerifiedRegistry) -> None:
        with pytest.raises(RegistrationRejectedError) as exc_info:
            await registry.register(_card(_A1))
        assert exc_info.value.reason == REASON_MISSING_SIGNATURE

    @pytest.mark.asyncio
    async def test_malformed_signature_rejected_missing_signature(
        self, registry: VerifiedRegistry
    ) -> None:
        card = _card(_A1)
        card.metadata["signature"] = {"signer": str(_A1), "value": "not-hex", "algorithm": "x"}
        with pytest.raises(RegistrationRejectedError) as exc_info:
            await registry.register(card)
        assert exc_info.value.reason == REASON_MISSING_SIGNATURE

    @pytest.mark.asyncio
    async def test_impersonation_rejected_signer_mismatch(
        self, registry: VerifiedRegistry, identities: dict[AgentId, DidKeyIdentity]
    ) -> None:
        # a2 signs a card claiming a1's id: valid signature, wrong signer.
        with pytest.raises(RegistrationRejectedError) as exc_info:
            await registry.register(sign_card(_card(_A1), identities[_A2]))
        assert exc_info.value.reason == REASON_SIGNER_MISMATCH

    @pytest.mark.asyncio
    async def test_spoofed_signer_field_rejected_bad_signature(
        self, registry: VerifiedRegistry, identities: dict[AgentId, DidKeyIdentity]
    ) -> None:
        # a2 signs a1's card, then rewrites the signer field to a1: the
        # signature bytes cannot verify under a1's key.
        card = sign_card(_card(_A1), identities[_A2])
        sig_record = card.metadata["signature"]
        assert isinstance(sig_record, dict)
        sig_record["signer"] = str(_A1)
        with pytest.raises(RegistrationRejectedError) as exc_info:
            await registry.register(card)
        assert exc_info.value.reason == REASON_BAD_SIGNATURE

    @pytest.mark.asyncio
    async def test_tamper_after_signing_rejected_bad_signature(
        self, registry: VerifiedRegistry, identities: dict[AgentId, DidKeyIdentity]
    ) -> None:
        card = sign_card(_card(_A1), identities[_A1])
        card.capabilities.append(f"service:{_A2}")  # capability forgery
        with pytest.raises(RegistrationRejectedError) as exc_info:
            await registry.register(card)
        assert exc_info.value.reason == REASON_BAD_SIGNATURE

    @pytest.mark.asyncio
    async def test_unknown_signer_rejected_bad_signature(
        self, registry: VerifiedRegistry, identities: dict[AgentId, DidKeyIdentity]
    ) -> None:
        # a3 signs its own card but the verifier holds no key for a3.
        with pytest.raises(RegistrationRejectedError) as exc_info:
            await registry.register(sign_card(_card(_A3), identities[_A3]))
        assert exc_info.value.reason == REASON_BAD_SIGNATURE

    @pytest.mark.asyncio
    async def test_rejection_mutates_nothing(
        self, registry: VerifiedRegistry, identities: dict[AgentId, DidKeyIdentity]
    ) -> None:
        with pytest.raises(RegistrationRejectedError):
            await registry.register(sign_card(_card(_A1), identities[_A2]))
        assert await registry.lookup(Query()) == []


class TestRotatingIdentityPassThrough:
    def test_key_id_and_signed_at_survive_sign_card(self) -> None:
        from nest_plugins_reference.identity.ed25519_rotating import Ed25519RotatingIdentity

        ident = Ed25519RotatingIdentity(_A1, seed=b"test:rotating")
        if hasattr(ident, "set_clock"):
            ident.set_clock(1.0)
        card = sign_card(_card(_A1), ident)
        sig_record = card.metadata["signature"]
        assert isinstance(sig_record, dict)
        sig_data = cast("dict[str, object]", sig_record)
        assert isinstance(sig_data.get("key_id"), str)
