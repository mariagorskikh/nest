# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the ``ed25519_prerotation`` identity plugin.

Each adversarial case maps to a production incident: post-rotation forgery is
a replay with a stolen retired key (old backup, ex-employee); backdating is an
antedated contract or tampered audit timestamp; the rotation hijack is a live
key exfiltration (leaked CI secret) followed by an identity-takeover attempt;
recovery-after-hijack is the incident-response path — rotating to the
pre-committed cold key that never touched the compromised host.

Example::

    pytest packages/nest-plugins-reference/tests/chainaim/test_ed25519_prerotation.py
"""

from __future__ import annotations

import asyncio

import pytest
from nest_core.types import AgentId
from nest_plugins_reference.identity.chainaim.ed25519_prerotation import (
    ALGORITHM,
    Ed25519PreRotatingIdentity,
    KeyId,
)


def _ident(name: str = "a1", seed: bytes = b"seed") -> Ed25519PreRotatingIdentity:
    return Ed25519PreRotatingIdentity(AgentId(name), seed=seed)


def _peer_pair() -> tuple[Ed25519PreRotatingIdentity, Ed25519PreRotatingIdentity]:
    """An agent plus a peer that registered the agent's inception commitment."""
    agent = _ident("a1", b"agent-root")
    peer = _ident("p1", b"peer-root")
    peer.register_peer_inception(AgentId("a1"), agent.public_key, agent.current_commitment)
    return agent, peer


class TestSignVerify:
    def test_sign_verify_roundtrip(self) -> None:
        ident = _ident()
        sig = ident.sign(b"hello")
        assert sig.algorithm == ALGORITHM
        assert sig.key_id is not None
        assert ident.verify(b"hello", sig, AgentId("a1"))

    def test_verify_rejects_wrong_payload(self) -> None:
        ident = _ident()
        assert not ident.verify(b"tampered", ident.sign(b"hello"), AgentId("a1"))

    def test_verify_rejects_wrong_signer(self) -> None:
        ident = _ident()
        assert not ident.verify(b"hello", ident.sign(b"hello"), AgentId("someone-else"))

    def test_public_key_is_raw_32_bytes(self) -> None:
        assert len(_ident().public_key) == 32

    def test_register_peer_rejects_private_key(self) -> None:
        ident = _ident()
        with pytest.raises(ValueError, match="public keys only"):
            ident.register_peer(AgentId("a2"), b"\x00" * 32, private_key=b"nope")


class TestPreRotationCommitments:
    def test_inception_publishes_commitment(self) -> None:
        ident = _ident()
        commitment = ident.current_commitment
        alg, _, digest_hex = commitment.partition(":")
        assert alg == "sha256"
        assert len(bytes.fromhex(digest_hex)) == 32

    def test_rotate_key_returns_keyid_spec_exact(self) -> None:
        ident = _ident()
        ident.set_clock(5.0)
        kid = ident.rotate_key(b"root2")
        # Spec: rotate_key(new_seed) -> KeyId. The return is the id itself,
        # not a record wrapper; the published record lives on latest_rotation.
        assert isinstance(kid, str)
        assert kid == ident.current_key_id

    def test_revealed_key_matches_prior_commitment(self) -> None:
        import hashlib

        ident = _ident()
        before = ident.current_commitment
        ident.set_clock(5.0)
        ident.rotate_key(b"root2")
        rec = ident.latest_rotation
        assert rec is not None
        assert before == "sha256:" + hashlib.sha256(rec.new_public_key).hexdigest()

    def test_new_seed_cannot_choose_revealed_key(self) -> None:
        # Two identical agents rotate with DIFFERENT new seeds: the revealed
        # key is identical (it was committed at inception); only the *next*
        # commitment differs. This is the commit-then-reveal discipline.
        a = _ident("a1", b"same-root")
        b = _ident("a1", b"same-root")
        a.set_clock(5.0)
        b.set_clock(5.0)
        assert a.rotate_key(b"seed-A") == b.rotate_key(b"seed-B")
        ra, rb = a.latest_rotation, b.latest_rotation
        assert ra is not None and rb is not None
        assert ra.new_next_digest != rb.new_next_digest

    def test_latest_rotation_none_before_first_rotation(self) -> None:
        assert _ident().latest_rotation is None

    def test_unknown_digest_alg_rejected(self) -> None:
        with pytest.raises(ValueError, match="digest algorithm"):
            Ed25519PreRotatingIdentity(AgentId("a1"), digest_alg="not-a-hash")

    def test_shake_like_alg_rejected(self) -> None:
        # shake_128 needs an output length: no plain hexdigest -> unusable
        # as a commitment algorithm here, and rejected up front.
        with pytest.raises(ValueError, match="digest algorithm"):
            Ed25519PreRotatingIdentity(AgentId("a1"), digest_alg="shake_128")

    def test_alternate_digest_alg_end_to_end(self) -> None:
        agent = Ed25519PreRotatingIdentity(AgentId("a1"), seed=b"s", digest_alg="sha512")
        peer = _ident("p1")
        peer.register_peer_inception(AgentId("a1"), agent.public_key, agent.current_commitment)
        assert agent.current_commitment.startswith("sha512:")
        agent.set_clock(3.0)
        peer.set_clock(3.0)
        agent.rotate_key(b"r2")
        rec = agent.latest_rotation
        assert rec is not None
        assert peer.apply_rotation(rec)

    def test_malformed_peer_commitment_rejected_at_registration(self) -> None:
        peer = _ident("p1")
        for bad in ("", "sha256", "sha256:", ":abcd", "sha256:zz", "nope-999:abcd"):
            with pytest.raises(ValueError, match="commitment"):
                peer.register_peer_inception(AgentId("a1"), b"\x01" * 32, bad)


class TestWindowAttacks:
    def test_old_signature_verifies_as_of_old_window(self) -> None:
        ident = _ident()
        ident.set_clock(1.0)
        old_sig = ident.sign(b"made-at-1")
        ident.set_clock(5.0)
        ident.rotate_key(b"new")
        assert ident.verify(b"made-at-1", old_sig, AgentId("a1"), as_of=1.0)

    def test_post_rotation_forgery_rejected(self) -> None:
        ident = _ident()
        stale = ident.current_key_id
        ident.set_clock(5.0)
        ident.rotate_key(b"new")
        ident.set_clock(9.0)
        forged = ident.sign_with(b"forged-late", stale)
        assert not ident.verify(b"forged-late", forged, AgentId("a1"), as_of=9.0)

    def test_backdating_rejected(self) -> None:
        ident = _ident()
        ident.set_clock(5.0)
        ident.rotate_key(b"new")
        backdated = ident.sign(b"claims-to-be-old")
        assert not ident.verify(b"claims-to-be-old", backdated, AgentId("a1"), as_of=2.0)


class TestRotationHijack:
    """The attack #3 suite: attacker HOLDS the current key. Reactive rotation
    accepts these; pre-rotation must reject every one of them."""

    def test_forged_rotation_fails_continuity(self) -> None:
        agent, peer = _peer_pair()
        agent.set_clock(5.0)
        peer.set_clock(5.0)
        attempt = agent.forge_rotation(b"attacker-seed")
        assert not peer.verify_continuity(AgentId("a1"), attempt)

    def test_forged_rotation_does_not_mutate_peer_state(self) -> None:
        agent, peer = _peer_pair()
        attempt = agent.forge_rotation(b"attacker-seed")
        assert not peer.apply_rotation(attempt)
        # Hijacked key never becomes valid: honest signatures still verify,
        # and a signature under the forged key does not resolve at the peer.
        sig = agent.sign(b"still-honest")
        assert peer.verify(b"still-honest", sig, AgentId("a1"))

    def test_forge_does_not_mutate_attacker_side_either(self) -> None:
        agent, _ = _peer_pair()
        kid_before = agent.current_key_id
        commitment_before = agent.current_commitment
        agent.forge_rotation(b"attacker-seed")
        assert agent.current_key_id == kid_before
        assert agent.current_commitment == commitment_before
        assert agent.latest_rotation is None

    def test_recovery_after_hijack(self) -> None:
        # Incident response: the hijack fails, the victim rotates to the
        # genuinely pre-committed cold key, peers adopt it, and post-recovery
        # signatures verify.
        agent, peer = _peer_pair()
        agent.set_clock(5.0)
        peer.set_clock(5.0)
        assert not peer.apply_rotation(agent.forge_rotation(b"attacker-seed"))
        agent.rotate_key(b"recovery-root")
        rec = agent.latest_rotation
        assert rec is not None
        assert peer.apply_rotation(rec)
        agent.set_clock(7.0)
        peer.set_clock(7.0)
        sig = agent.sign(b"post-recovery")
        assert peer.verify(b"post-recovery", sig, AgentId("a1"), as_of=7.0)

    def test_honest_rotation_accepted_by_peer(self) -> None:
        agent, peer = _peer_pair()
        agent.set_clock(5.0)
        peer.set_clock(5.0)
        agent.rotate_key(b"root2")
        rec = agent.latest_rotation
        assert rec is not None
        assert peer.verify_continuity(AgentId("a1"), rec)
        assert peer.apply_rotation(rec)
        agent.set_clock(6.0)
        sig = agent.sign(b"after-rotation")
        assert peer.verify(b"after-rotation", sig, AgentId("a1"), as_of=6.0)

    def test_strict_path_no_commitment_no_rotation(self) -> None:
        # Single strict path (no permissive mode): a peer registered without
        # inception data can verify signatures but never adopt a rotation.
        agent = _ident("a1", b"agent-root")
        legacy_peer = _ident("p1", b"peer-root")
        legacy_peer.register_peer(AgentId("a1"), agent.public_key)
        assert legacy_peer.verify(b"m", agent.sign(b"m"), AgentId("a1"))
        agent.set_clock(5.0)
        agent.rotate_key(b"root2")
        rec = agent.latest_rotation
        assert rec is not None
        assert not legacy_peer.verify_continuity(AgentId("a1"), rec)
        assert not legacy_peer.apply_rotation(rec)

    def test_retired_key_cannot_authorise_successor(self) -> None:
        # Retired-key injection (kept from the reactive design): a rotation
        # whose old_key_id is not the chain tip is rejected even with a valid
        # signature and even if the commitment would match.
        agent, peer = _peer_pair()
        agent.set_clock(5.0)
        peer.set_clock(5.0)
        agent.rotate_key(b"root2")
        first = agent.latest_rotation
        assert first is not None
        assert peer.apply_rotation(first)
        # Replay the SAME already-applied rotation at the peer: old key is now
        # retired and the successor already present -> idempotent verify is
        # True, but a *different* rotation off the retired key must fail.
        assert peer.verify_continuity(AgentId("a1"), first)
        agent.set_clock(8.0)
        peer.set_clock(8.0)
        agent.rotate_key(b"root3")
        second = agent.latest_rotation
        assert second is not None
        assert peer.apply_rotation(second)
        # Now 'first' rotation's old key is two steps stale; verifying it as a
        # fresh event must fail (its successor exists -> idempotence path),
        # but a forged branch from that stale key must be rejected.
        stale_branch = agent.forge_rotation(b"branch-seed")
        assert not peer.verify_continuity(AgentId("a1"), stale_branch)


class TestResolveAndDeterminism:
    def test_private_key_never_serialised(self) -> None:
        ident = _ident()
        ident.set_clock(2.0)
        ident.rotate_key(b"r2")
        record = asyncio.run(ident.resolve(AgentId("a1")))
        for key in record.metadata["keys"]:
            assert set(key) == {
                "key_id",
                "public_key",
                "issued_at",
                "rotated_out",
                "next_key_digest",
            }
            assert "private" not in str(key).lower()

    def test_resolve_exports_commitments(self) -> None:
        ident = _ident()
        record = asyncio.run(ident.resolve(AgentId("a1")))
        assert record.metadata["keys"][0]["next_key_digest"] == ident.current_commitment

    def test_same_seed_same_keys_commitments_signatures(self) -> None:
        a = _ident("a1", b"root")
        b = _ident("a1", b"root")
        assert a.current_key_id == b.current_key_id
        assert a.current_commitment == b.current_commitment
        assert a.sign(b"payload").value == b.sign(b"payload").value
        a.set_clock(4.0)
        b.set_clock(4.0)
        assert a.rotate_key(b"r2") == b.rotate_key(b"r2")
        ra, rb = a.latest_rotation, b.latest_rotation
        assert ra is not None and rb is not None
        assert ra.continuity_signature == rb.continuity_signature
        assert ra.new_next_digest == rb.new_next_digest

    def test_sign_with_unknown_key_raises(self) -> None:
        ident = _ident()
        with pytest.raises(ValueError, match="no private key"):
            ident.sign_with(b"x", KeyId("deadbeef"))
