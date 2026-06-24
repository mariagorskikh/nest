# SPDX-License-Identifier: Apache-2.0
"""Tests for the sealedbox privacy plugin (real authenticated encryption)."""

import pytest
from nest_core.plugins import PluginRegistry
from nest_core.types import AgentId, Proof, Statement, Witness
from nest_plugins_reference.privacy.sealedbox import (
    MalformedEnvelopeError,
    NotInAudienceError,
    SealedBoxPrivacy,
    TamperError,
)


async def test_encrypt_decrypt_round_trip() -> None:
    src = SealedBoxPrivacy(AgentId("src"), seed=7)
    dest = SealedBoxPrivacy(AgentId("dest"), seed=7)
    blob = await src.encrypt(b"the eagle lands at dawn", [AgentId("dest")])
    assert blob != b"the eagle lands at dawn"  # actually encrypted, not passthrough
    assert await dest.decrypt(blob) == b"the eagle lands at dawn"


async def test_multi_recipient_and_outsider() -> None:
    src = SealedBoxPrivacy(AgentId("src"), seed=7)
    blob = await src.encrypt(b"hello team", [AgentId("a"), AgentId("b")])
    for name in ("a", "b"):
        member = SealedBoxPrivacy(AgentId(name), seed=7)
        assert await member.decrypt(blob) == b"hello team"
    outsider = SealedBoxPrivacy(AgentId("eve"), seed=7)
    with pytest.raises(NotInAudienceError):
        await outsider.decrypt(blob)


async def test_tampered_ciphertext_raises() -> None:
    src = SealedBoxPrivacy(AgentId("src"), seed=7)
    dest = SealedBoxPrivacy(AgentId("dest"), seed=7)
    blob = bytearray(await src.encrypt(b"secret", [AgentId("dest")]))
    blob[-1] ^= 0x01  # corrupt the AEAD tag/ciphertext
    with pytest.raises(TamperError):
        await dest.decrypt(bytes(blob))


async def test_malformed_envelope_raises() -> None:
    dest = SealedBoxPrivacy(AgentId("dest"), seed=7)
    with pytest.raises(MalformedEnvelopeError):
        await dest.decrypt(b"not an envelope")


async def test_prove_and_verify_are_honest_stubs() -> None:
    priv = SealedBoxPrivacy(AgentId("src"), seed=7)
    with pytest.raises(NotImplementedError):
        await priv.prove(Statement(predicate="x"), Witness())
    proof = Proof(statement=Statement(predicate="x"), data=b"", scheme="sealedbox")
    with pytest.raises(NotImplementedError):
        await priv.verify_proof(Statement(predicate="x"), proof)


async def test_deterministic_mode_is_replayable() -> None:
    a = SealedBoxPrivacy(AgentId("src"), seed=7)
    b = SealedBoxPrivacy(AgentId("src"), seed=7)
    blob_a = await a.encrypt(b"same", [AgentId("dest")])
    blob_b = await b.encrypt(b"same", [AgentId("dest")])
    assert blob_a == blob_b  # same seed + sender + counter => identical bytes (replayable)


async def test_random_mode_is_secret_but_round_trips() -> None:
    src = SealedBoxPrivacy(AgentId("src"), deterministic=False)
    dest = SealedBoxPrivacy(AgentId("dest"), deterministic=False)
    src.register_peer(AgentId("dest"), dest.public_key_raw)
    blob1 = await src.encrypt(b"hush", [AgentId("dest")])
    blob2 = await src.encrypt(b"hush", [AgentId("dest")])
    assert blob1 != blob2  # randomized: not seed-derivable, not reproducible
    assert await dest.decrypt(blob1) == b"hush"


def test_registered_in_plugin_registry() -> None:
    reg = PluginRegistry()
    assert reg.resolve("privacy", "sealedbox") is SealedBoxPrivacy
    assert ("privacy", "sealedbox") in reg.list_plugins("privacy")
