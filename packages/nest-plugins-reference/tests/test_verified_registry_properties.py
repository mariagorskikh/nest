# SPDX-License-Identifier: Apache-2.0
"""Hypothesis property tests for the ``verified`` registry plugin.

Two invariants, each over 100 generated examples:

* **Completeness** — any well-formed card, signed by its own identity, is
  admitted and discoverable.
* **Soundness** — any signed card mutated in any signature-covered field
  after signing is rejected with ``bad_signature``, and never stored.

Example::

    pytest packages/nest-plugins-reference/tests/test_verified_registry_properties.py
"""

from __future__ import annotations

import asyncio

from hypothesis import given, settings
from hypothesis import strategies as st
from nest_core.types import AgentCard, AgentId, Query
from nest_plugins_reference.identity.did_key import DidKeyIdentity
from nest_plugins_reference.registry.verified import (
    REASON_BAD_SIGNATURE,
    REASON_SIGNER_MISMATCH,
    RegistrationRejectedError,
    VerifiedRegistry,
    sign_card,
)

_agent_id_st = st.from_regex(r"[a-z]{1,8}-[0-9]{1,3}", fullmatch=True).map(AgentId)
_name_st = st.text(
    alphabet=st.characters(min_codepoint=32, max_codepoint=126, exclude_characters='"\\'),
    min_size=0,
    max_size=20,
)
_capabilities_st = st.lists(
    st.from_regex(r"[a-z_]{1,12}", fullmatch=True), min_size=0, max_size=5, unique=True
)
_endpoint_st = st.none() | st.from_regex(r"self://[a-z0-9]{1,10}", fullmatch=True)

_cards_st = st.builds(
    AgentCard,
    agent_id=_agent_id_st,
    name=_name_st,
    capabilities=_capabilities_st,
    endpoint=_endpoint_st,
)

_MUTATIONS = ("append_capability", "rename", "swap_endpoint", "swap_agent_id")


def _fresh_registry(card: AgentCard) -> tuple[VerifiedRegistry, DidKeyIdentity]:
    """Build a registry whose verifier knows exactly this card's owner.

    Example::

        registry, identity = _fresh_registry(card)
    """
    identity = DidKeyIdentity(card.agent_id, seed=b"prop:" + str(card.agent_id).encode())
    verifier = DidKeyIdentity(AgentId("prop-verifier"), seed=b"prop:verifier")
    verifier.register_peer(card.agent_id, identity.public_key)
    return VerifiedRegistry(verifier), identity


class TestCompleteness:
    @settings(max_examples=100, deadline=None)
    @given(card=_cards_st)
    def test_own_signed_card_always_admitted(self, card: AgentCard) -> None:
        registry, identity = _fresh_registry(card)

        async def run() -> list[AgentCard]:
            await registry.register(sign_card(card, identity))
            return await registry.lookup(Query(capabilities=list(card.capabilities)))

        results = asyncio.run(run())
        assert any(c.agent_id == card.agent_id for c in results)


class TestSoundness:
    @settings(max_examples=100, deadline=None)
    @given(card=_cards_st, mutation=st.sampled_from(_MUTATIONS))
    def test_any_post_signing_mutation_rejected(self, card: AgentCard, mutation: str) -> None:
        registry, identity = _fresh_registry(card)
        signed = sign_card(card, identity)

        if mutation == "append_capability":
            signed.capabilities.append("forged_capability")
        elif mutation == "rename":
            signed.name = signed.name + "-mut"
        elif mutation == "swap_endpoint":
            signed.endpoint = "sybil://attacker"
        else:  # swap_agent_id: claim someone else entirely
            victim = AgentId(str(card.agent_id) + "x")
            signed.agent_id = victim

        async def run() -> str:
            try:
                await registry.register(signed)
            except RegistrationRejectedError as exc:
                assert await registry.lookup(Query()) == []
                return exc.reason
            return "accepted"

        reason = asyncio.run(run())
        # swap_agent_id changes the claimed id away from the signer, which the
        # signer check catches first; every other mutation breaks the signature.
        expected = REASON_SIGNER_MISMATCH if mutation == "swap_agent_id" else REASON_BAD_SIGNATURE
        assert reason == expected
