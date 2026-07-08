# SPDX-License-Identifier: Apache-2.0
"""Hypothesis property-based tests for the ``ed25519_prerotation`` plugin.

Invariants checked over generated payloads, seeds, ticks, and rotation counts:

1. Sign/verify round-trip inside the signing key's validity window.
2. As-of correctness: accept iff the observed tick is in ``[issued_at, rotated_out)``.
3. Post-rotation forgery is always rejected at any tick ``>= rotated_out``.
4. Backdating (a new-key signature anchored before its ``issued_at``) is rejected.
5. **Commitment-chain integrity over N rotations**: every revealed key's digest
   equals the commitment published at the previous establishment event, for
   arbitrary rotation counts and per-rotation seeds — the long-lived-agent
   guarantee.
6. **A forged rotation never matches the commitment** (attacker-chosen key vs
   sha256 preimage resistance), for any attacker seed — and is therefore
   rejected by a peer, while the honest rotation at the same tick is accepted.
7. Determinism: same seed and clock schedule -> identical key ids, commitment
   strings, rotation evidence, and signature bytes (forensic reproducibility).
8. Unknown digest algorithms are rejected at construction, for arbitrary
   not-a-real-hash names.

The plugin clock advances forward-only, so tests draw bounds and apply ticks
in strictly ascending order; ticks are integer-valued (cast to ``float``) to
keep half-open boundary equality exact and CI non-flaky.

Example::

    pytest packages/nest-plugins-reference/tests/chainaim/test_ed25519_prerotation_properties.py
"""

from __future__ import annotations

import hashlib

from hypothesis import given, settings
from hypothesis import strategies as st
from nest_core.types import AgentId
from nest_plugins_reference.identity.ed25519_prerotation import (
    Ed25519PreRotatingIdentity,
)

# Bounded strategies: small payloads/seeds keep crypto cheap; integer ticks
# (cast to float) keep half-open-window boundary equality exact.
_payloads = st.binary(min_size=0, max_size=256)
_seeds = st.binary(min_size=0, max_size=64)
_ticks = st.integers(min_value=0, max_value=10_000).map(float)
_small_ticks = st.integers(min_value=1, max_value=100)


def _ident(name: str = "a1", seed: bytes = b"seed") -> Ed25519PreRotatingIdentity:
    return Ed25519PreRotatingIdentity(AgentId(name), seed=seed)


class TestRoundTripAndWindows:
    @settings(max_examples=50, deadline=None)
    @given(payload=_payloads, seed=_seeds, as_of=_ticks)
    def test_signature_verifies_within_window(
        self, payload: bytes, seed: bytes, as_of: float
    ) -> None:
        """With no rotation the sole key's window is ``[0, +inf)``: any as-of
        tick >= 0 accepts."""
        ident = _ident(seed=seed)
        sig = ident.sign(payload)
        assert ident.verify(payload, sig, AgentId("a1"), as_of=as_of)

    @settings(max_examples=50, deadline=None)
    @given(payload=_payloads, seed=_seeds, rotate_tick=_small_ticks, probe=_ticks)
    def test_as_of_window_correctness(
        self, payload: bytes, seed: bytes, rotate_tick: int, probe: float
    ) -> None:
        """A signature by key #0 verifies iff the as-of tick lies inside
        ``[0, rotated_out)`` — equality at the boundary rejects."""
        ident = _ident(seed=seed)
        sig = ident.sign(payload)
        ident.set_clock(float(rotate_tick))
        ident.rotate_key(b"next-root")
        expected = 0.0 <= probe < float(rotate_tick)
        assert ident.verify(payload, sig, AgentId("a1"), as_of=probe) is expected

    @settings(max_examples=50, deadline=None)
    @given(payload=_payloads, seed=_seeds, rotate_tick=_small_ticks, delta=_ticks)
    def test_post_rotation_forgery_always_rejected(
        self, payload: bytes, seed: bytes, rotate_tick: int, delta: float
    ) -> None:
        ident = _ident(seed=seed)
        stale = ident.current_key_id
        ident.set_clock(float(rotate_tick))
        ident.rotate_key(b"next-root")
        forged = ident.sign_with(payload, stale)
        assert not ident.verify(payload, forged, AgentId("a1"), as_of=float(rotate_tick) + delta)

    @settings(max_examples=50, deadline=None)
    @given(payload=_payloads, seed=_seeds, rotate_tick=_small_ticks)
    def test_backdating_always_rejected(
        self, payload: bytes, seed: bytes, rotate_tick: int
    ) -> None:
        ident = _ident(seed=seed)
        ident.set_clock(float(rotate_tick))
        ident.rotate_key(b"next-root")
        backdated = ident.sign(payload)
        # Any anchor strictly before the new key's issue tick must reject.
        assert not ident.verify(payload, backdated, AgentId("a1"), as_of=float(rotate_tick) - 1.0)


class TestCommitmentChain:
    @settings(max_examples=25, deadline=None)
    @given(
        seed=_seeds,
        rotation_seeds=st.lists(st.binary(min_size=0, max_size=16), min_size=1, max_size=8),
    )
    def test_n_rotation_commitment_chain_integrity(
        self, seed: bytes, rotation_seeds: list[bytes]
    ) -> None:
        """Every revealed key hashes to the previously published commitment,
        for any rotation count and any per-rotation seeds."""
        ident = _ident(seed=seed)
        commitments = [ident.current_commitment]
        tick = 0.0
        for rot_seed in rotation_seeds:
            tick += 1.0
            ident.set_clock(tick)
            ident.rotate_key(rot_seed)
            rec = ident.latest_rotation
            assert rec is not None
            prior = commitments[-1]
            assert prior == "sha256:" + hashlib.sha256(rec.new_public_key).hexdigest()
            commitments.append(rec.new_next_digest)

    @settings(max_examples=25, deadline=None)
    @given(seed=_seeds, attacker_seed=_seeds, rotate_tick=_small_ticks)
    def test_forged_rotation_never_matches_commitment(
        self, seed: bytes, attacker_seed: bytes, rotate_tick: int
    ) -> None:
        """For any attacker seed, the forged successor's digest differs from
        the committed one, a peer rejects the forgery, and the honest rotation
        at the same tick is still accepted (recovery)."""
        agent = _ident("a1", seed=seed)
        peer = _ident("p1", seed=b"peer")
        peer.register_peer_inception(AgentId("a1"), agent.public_key, agent.current_commitment)
        agent.set_clock(float(rotate_tick))
        peer.set_clock(float(rotate_tick))

        attempt = agent.forge_rotation(attacker_seed)
        committed = agent.current_commitment
        forged_digest = "sha256:" + hashlib.sha256(attempt.new_public_key).hexdigest()
        assert forged_digest != committed
        assert not peer.verify_continuity(AgentId("a1"), attempt)
        assert not peer.apply_rotation(attempt)

        agent.rotate_key(b"recovery-root")
        rec = agent.latest_rotation
        assert rec is not None
        assert peer.apply_rotation(rec)


class TestDeterminism:
    @settings(max_examples=25, deadline=None)
    @given(
        seed=_seeds,
        payload=_payloads,
        rotation_seeds=st.lists(st.binary(min_size=0, max_size=16), min_size=0, max_size=4),
    )
    def test_same_seed_identical_kel_commitments_signatures(
        self, seed: bytes, payload: bytes, rotation_seeds: list[bytes]
    ) -> None:
        """Two agents with the same seed and clock schedule produce identical
        key event logs: key ids, commitments, rotation evidence, signatures."""
        a = _ident("a1", seed=seed)
        b = _ident("a1", seed=seed)
        tick = 0.0
        for rot_seed in rotation_seeds:
            tick += 1.0
            a.set_clock(tick)
            b.set_clock(tick)
            assert a.rotate_key(rot_seed) == b.rotate_key(rot_seed)
            ra, rb = a.latest_rotation, b.latest_rotation
            assert ra is not None and rb is not None
            assert ra.continuity_signature == rb.continuity_signature
            assert ra.new_next_digest == rb.new_next_digest
        assert a.current_key_id == b.current_key_id
        assert a.current_commitment == b.current_commitment
        assert a.sign(payload).value == b.sign(payload).value

    @settings(max_examples=25, deadline=None)
    @given(alg=st.text(min_size=1, max_size=20))
    def test_unknown_digest_alg_rejected(self, alg: str) -> None:
        """Any name hashlib cannot produce a plain hexdigest for is rejected
        at construction (real algorithms construct fine and are skipped)."""
        try:
            hashlib.new(alg, b"probe").hexdigest()
            usable = True
        except (ValueError, TypeError):
            usable = False
        if usable:
            Ed25519PreRotatingIdentity(AgentId("a1"), digest_alg=alg)
        else:
            try:
                Ed25519PreRotatingIdentity(AgentId("a1"), digest_alg=alg)
                raise AssertionError("expected ValueError for unusable digest_alg")
            except ValueError:
                pass
