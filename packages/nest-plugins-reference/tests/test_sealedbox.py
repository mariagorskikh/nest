# SPDX-License-Identifier: Apache-2.0
"""Tests for the ``sealedbox`` privacy plugin.

Covers the full Problem 09 surface (hybrid encryption, selective disclosure,
broadcast revocation, the four required adversarial attacks) plus the plugin's
headline property — nonce-misuse-resistant deterministic derivation — including a
live demonstration that the reuse validator FAILS against the ``noop`` passthrough
and against the merged ``hybrid_x25519`` deterministic mode, and PASSES against
``sealedbox``.
"""

from __future__ import annotations

import base64
import json

import pytest
from nest_core.plugins import PluginRegistry
from nest_core.types import AgentId, Statement, Witness
from nest_plugins_reference.privacy.hybrid_x25519 import HybridX25519Privacy
from nest_plugins_reference.privacy.noop import NoopPrivacy
from nest_plugins_reference.privacy.sealedbox import (
    MalformedEnvelopeError,
    NotInAudienceError,
    ReplayError,
    SealedBoxPrivacy,
    TamperError,
    commit_credential,
    content_ciphertext,
)
from nest_plugins_reference.validators.sealedbox_validators import (
    check_deterministic_reuse_safe,
    check_eavesdropper_blocked,
    check_field_injection_rejected,
    check_no_two_time_pad,
    check_replay_rejected,
    check_stale_revocation_blocked,
    corrupt_proof,
)

# Distinct, equal-length plaintexts for two-time-pad detection.
_PT_A = b"attack-at-dawn!!"
_PT_B = b"retreat-at-dusk!"


# --------------------------------------------------------------------------- #
# Hybrid encryption round-trips
# --------------------------------------------------------------------------- #
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


async def test_plaintext_never_on_the_wire() -> None:
    src = SealedBoxPrivacy(AgentId("src"), seed=7)
    blob = await src.encrypt(b"top-secret-bid-1700", [AgentId("dest")])
    assert b"top-secret-bid-1700" not in blob


async def test_tampered_ciphertext_raises() -> None:
    src = SealedBoxPrivacy(AgentId("src"), seed=7)
    dest = SealedBoxPrivacy(AgentId("dest"), seed=7)
    blob = bytearray(await src.encrypt(b"secret", [AgentId("dest")]))
    blob[-1] ^= 0x01  # corrupt the AEAD tag/ciphertext
    with pytest.raises(TamperError):
        await dest.decrypt(bytes(blob))


async def test_tampered_header_breaks_authentication() -> None:
    """The header (sender/epoch/counter) is bound as AAD, so editing it fails."""
    sender = "src"
    src = SealedBoxPrivacy(AgentId(sender), seed=7)
    dest = SealedBoxPrivacy(AgentId("dest"), seed=7)
    blob = bytearray(await src.encrypt(b"secret", [AgentId("dest")]))
    # Layout: magic(4) ver(1) sender_len(2) sender(len) epoch(4) counter(8) ...
    epoch_off = 5 + 2 + len(sender)
    blob[epoch_off] ^= 0x01  # flip a byte of the bound epoch -> AAD mismatch
    with pytest.raises(TamperError):
        await dest.decrypt(bytes(blob))


async def test_malformed_envelope_raises() -> None:
    dest = SealedBoxPrivacy(AgentId("dest"), seed=7)
    with pytest.raises(MalformedEnvelopeError):
        await dest.decrypt(b"not an envelope")


async def test_replay_rejected() -> None:
    src = SealedBoxPrivacy(AgentId("src"), seed=7)
    dest = SealedBoxPrivacy(AgentId("dest"), seed=7)
    env = await src.encrypt(b"once", [AgentId("dest")])
    assert await dest.decrypt(env) == b"once"
    with pytest.raises(ReplayError):
        await dest.decrypt(env)


# --------------------------------------------------------------------------- #
# Determinism AND nonce-misuse resistance (the headline property)
# --------------------------------------------------------------------------- #
async def test_deterministic_mode_is_replayable() -> None:
    a = SealedBoxPrivacy(AgentId("src"), seed=7)
    b = SealedBoxPrivacy(AgentId("src"), seed=7)
    blob_a = await a.encrypt(b"same", [AgentId("dest")])
    blob_b = await b.encrypt(b"same", [AgentId("dest")])
    assert blob_a == blob_b  # same seed+sender+counter+plaintext+audience => identical bytes


async def test_counter_reuse_is_not_a_two_time_pad() -> None:
    """Two reconstructed senders (counter reset) encrypting DIFFERENT plaintexts
    must not share a keystream — the property counter-only schemes lack."""
    a = SealedBoxPrivacy(AgentId("src"), seed=7)
    b = SealedBoxPrivacy(AgentId("src"), seed=7)
    env_a = await a.encrypt(_PT_A, [AgentId("dest")])  # counter 0
    env_b = await b.encrypt(_PT_B, [AgentId("dest")])  # counter 0 again (fresh instance)
    report = check_no_two_time_pad(
        content_ciphertext(env_a), _PT_A, content_ciphertext(env_b), _PT_B
    )
    assert report.passed, report.detail


async def test_reuse_validator_passes_against_sealedbox() -> None:
    report = await check_deterministic_reuse_safe(
        lambda: SealedBoxPrivacy(AgentId("src"), seed=7),
        audience=[AgentId("dest")],
        plaintext_a=_PT_A,
        plaintext_b=_PT_B,
    )
    assert report.passed, report.detail


async def test_reuse_validator_fails_against_noop() -> None:
    """noop leaks the plaintext directly, so the ciphertext XOR is the plaintext XOR."""
    report = await check_deterministic_reuse_safe(
        NoopPrivacy,
        audience=[AgentId("dest")],
        plaintext_a=_PT_A,
        plaintext_b=_PT_B,
        extract=lambda env: env,  # noop envelope IS the plaintext
    )
    assert not report.passed
    assert "two-time pad" in report.detail


async def test_reuse_validator_fails_against_hybrid_deterministic() -> None:
    """The novel differentiator, proven live: the merged hybrid plugin's
    deterministic mode reuses (key, nonce) when reconstructed, and the validator
    catches it. sealedbox is the fix."""
    recipient_pub = HybridX25519Privacy(AgentId("r"), seed=b"r", deterministic=True).public_key

    def make_hybrid_sender() -> HybridX25519Privacy:
        s = HybridX25519Privacy(AgentId("sender"), seed=b"s", deterministic=True)
        s.register_peer(AgentId("r"), recipient_pub)
        return s

    def extract_hybrid_ct(env: bytes) -> bytes:
        obj = json.loads(env)
        return base64.b64decode(obj["ct"])  # ct||tag; first len(pt) bytes = keystream^pt

    report = await check_deterministic_reuse_safe(
        make_hybrid_sender,
        audience=[AgentId("r")],
        plaintext_a=_PT_A,
        plaintext_b=_PT_B,
        extract=extract_hybrid_ct,
    )
    assert not report.passed
    assert "two-time pad" in report.detail


async def test_random_mode_is_secret_but_round_trips() -> None:
    src = SealedBoxPrivacy(AgentId("src"), deterministic=False)
    dest = SealedBoxPrivacy(AgentId("dest"), deterministic=False)
    src.register_peer(AgentId("dest"), dest.public_key_raw)
    blob1 = await src.encrypt(b"hush", [AgentId("dest")])
    blob2 = await src.encrypt(b"hush", [AgentId("dest")])
    assert blob1 != blob2  # randomized: not seed-derivable, not reproducible
    assert await dest.decrypt(blob1) == b"hush"


# --------------------------------------------------------------------------- #
# Selective disclosure (salted Merkle commitment)
# --------------------------------------------------------------------------- #
def _credential() -> tuple[Statement, Witness]:
    fields = {"name": "Ada", "age": "37", "country": "GB", "clearance": "secret"}
    root, salts = commit_credential(fields, salt_seed=b"issuer-seed")
    statement = Statement(
        predicate="credential",
        public_inputs={"root": root, "reveal": json.dumps(["age", "country"])},
    )
    witness = Witness(private_inputs={**fields, "__salts__": json.dumps(salts, sort_keys=True)})
    return statement, witness


async def test_selective_disclosure_reveals_only_requested_fields() -> None:
    priv = SealedBoxPrivacy(AgentId("holder"), seed=7)
    statement, witness = _credential()
    proof = await priv.prove(statement, witness)
    assert await priv.verify_proof(statement, proof)
    body = json.loads(proof.data)
    assert set(body["disclosed"]) == {"age", "country"}
    # An undisclosed field's value must not leak anywhere in the proof bytes.
    assert b"secret" not in proof.data
    assert b"Ada" not in proof.data


async def test_field_injection_fails_verification() -> None:
    priv = SealedBoxPrivacy(AgentId("holder"), seed=7)
    statement, witness = _credential()
    proof = await priv.prove(statement, witness)
    tampered = corrupt_proof(proof)
    assert not await priv.verify_proof(statement, tampered)


async def test_wrong_root_fails_verification() -> None:
    priv = SealedBoxPrivacy(AgentId("holder"), seed=7)
    statement, witness = _credential()
    proof = await priv.prove(statement, witness)
    forged = Statement(
        predicate="credential",
        public_inputs={"root": "00" * 32, "reveal": json.dumps(["age", "country"])},
    )
    assert not await priv.verify_proof(forged, proof)


async def test_inconsistent_witness_raises() -> None:
    priv = SealedBoxPrivacy(AgentId("holder"), seed=7)
    statement, _ = _credential()
    bad_witness = Witness(private_inputs={"age": "37", "__salts__": "{}"})
    with pytest.raises(ValueError, match="salt"):
        await priv.prove(statement, bad_witness)


# --------------------------------------------------------------------------- #
# Broadcast revocation
# --------------------------------------------------------------------------- #
async def test_revocation_blocks_future_but_not_past() -> None:
    sender = SealedBoxPrivacy(AgentId("sender"), seed=7)
    pre = await sender.encrypt(b"pre-revocation", [AgentId("carol"), AgentId("dave")])
    new_epoch = sender.revoke(AgentId("carol"))
    assert new_epoch == 1
    post = await sender.encrypt(b"post-revocation", [AgentId("carol"), AgentId("dave")])

    carol = SealedBoxPrivacy(AgentId("carol"), seed=7)
    assert await carol.decrypt(pre) == b"pre-revocation"  # past message still readable
    with pytest.raises(NotInAudienceError):
        await carol.decrypt(post)  # excluded from the post-revocation wrap set

    dave = SealedBoxPrivacy(AgentId("dave"), seed=7)
    assert await dave.decrypt(post) == b"post-revocation"  # non-revoked member unaffected


async def test_rerevoke_is_idempotent() -> None:
    sender = SealedBoxPrivacy(AgentId("sender"), seed=7)
    first = sender.revoke(AgentId("carol"))
    second = sender.revoke(AgentId("carol"))
    assert first == second == 1  # re-revoking does not advance the epoch again


# --------------------------------------------------------------------------- #
# Reconstruction is safe end-to-end: distinct messages at a reused counter are
# not mistaken for replays of each other (the replay guard keys on the envelope).
# --------------------------------------------------------------------------- #
async def test_reconstructed_sender_distinct_messages_are_not_false_replays() -> None:
    dest = SealedBoxPrivacy(AgentId("dest"), seed=7)
    env_a = await SealedBoxPrivacy(AgentId("src"), seed=7).encrypt(_PT_A, [AgentId("dest")])
    env_b = await SealedBoxPrivacy(AgentId("src"), seed=7).encrypt(_PT_B, [AgentId("dest")])
    assert env_a != env_b  # same (sender, epoch, counter) but distinct plaintext -> distinct bytes
    assert await dest.decrypt(env_a) == _PT_A
    assert await dest.decrypt(env_b) == _PT_B  # NOT rejected as a replay


async def test_reveal_field_name_containing_comma() -> None:
    priv = SealedBoxPrivacy(AgentId("holder"), seed=7)
    fields = {"a,b": "x", "c": "y"}
    root, salts = commit_credential(fields, salt_seed=b"s")
    statement = Statement(
        predicate="cred", public_inputs={"root": root, "reveal": json.dumps(["a,b"])}
    )
    witness = Witness(private_inputs={**fields, "__salts__": json.dumps(salts, sort_keys=True)})
    proof = await priv.prove(statement, witness)
    assert await priv.verify_proof(statement, proof)
    assert set(json.loads(proof.data)["disclosed"]) == {"a,b"}


# --------------------------------------------------------------------------- #
# The Problem-09 adversarial validators pass against sealedbox
# --------------------------------------------------------------------------- #
async def test_validators_pass_against_sealedbox() -> None:
    src = SealedBoxPrivacy(AgentId("src"), seed=7)
    secret = b"sealed-bid-1700"
    env = await src.encrypt(secret, [AgentId("dest")])

    eavesdropper = SealedBoxPrivacy(AgentId("eve"), seed=7)
    r1 = await check_eavesdropper_blocked(eavesdropper, env, secret=secret)
    assert r1.passed, r1.detail

    r2 = await check_replay_rejected(SealedBoxPrivacy(AgentId("dest"), seed=7), env)
    assert r2.passed, r2.detail

    holder = SealedBoxPrivacy(AgentId("holder"), seed=7)
    statement, witness = _credential()
    good = await holder.prove(statement, witness)
    r3 = await check_field_injection_rejected(holder, statement, good, corrupt_proof(good))
    assert r3.passed, r3.detail

    sender = SealedBoxPrivacy(AgentId("sender"), seed=7)
    pre = await sender.encrypt(b"pre", [AgentId("carol"), AgentId("dave")])
    sender.revoke(AgentId("carol"))
    post = await sender.encrypt(b"post", [AgentId("carol"), AgentId("dave")])
    r4 = await check_stale_revocation_blocked(SealedBoxPrivacy(AgentId("carol"), seed=7), pre, post)
    assert r4.passed, r4.detail


async def test_eavesdropper_validator_fails_against_noop() -> None:
    noop = NoopPrivacy()
    secret = b"sealed-bid-1700"
    env = await noop.encrypt(secret, [AgentId("dest")])
    report = await check_eavesdropper_blocked(noop, env, secret=secret)
    assert not report.passed


# --------------------------------------------------------------------------- #
# Registry discovery (built-in map + entry point)
# --------------------------------------------------------------------------- #
def test_registered_in_plugin_registry() -> None:
    reg = PluginRegistry()
    assert reg.resolve("privacy", "sealedbox") is SealedBoxPrivacy
    assert ("privacy", "sealedbox") in reg.list_plugins("privacy")
