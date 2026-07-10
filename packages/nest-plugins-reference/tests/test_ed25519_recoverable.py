# SPDX-License-Identifier: Apache-2.0
# pyright: reportPrivateUsage=false
"""Unit tests for the ``ed25519_recoverable`` identity plugin.

Covers real Ed25519 sign/verify, time-locked rotation, K-of-N social recovery,
the nine adversarial attacks the plugin defeats, determinism, and monotonic
clock enforcement.

Example::

    pytest packages/nest-plugins-reference/tests/test_ed25519_recoverable.py
"""

from __future__ import annotations

import asyncio

import pytest
from nest_core.types import AgentId
from nest_plugins_reference.identity.ed25519_recoverable import (
    ALGORITHM,
    DEFAULT_TIME_LOCK,
    Ed25519RecoverableIdentity,
    KeyId,
    RecoveryEvent,
    _key_id_for,
    _public_bytes,
)


def _ident(
    name: str = "a1",
    seed: bytes = b"seed",
    *,
    attesters: list[str] | None = None,
    quorum_k: int = 2,
    time_lock: float = DEFAULT_TIME_LOCK,
) -> Ed25519RecoverableIdentity:
    attester_ids = [AgentId(a) for a in attesters] if attesters else []
    return Ed25519RecoverableIdentity(
        AgentId(name),
        seed=seed,
        recovery_attesters=attester_ids,
        recovery_quorum_k=quorum_k,
        time_lock=time_lock,
    )


def _attester(name: str, seed: bytes | None = None) -> Ed25519RecoverableIdentity:
    return Ed25519RecoverableIdentity(AgentId(name), seed=seed or name.encode())


# ── Basic sign/verify ────────────────────────────────────────────────


class TestSignVerify:
    def test_sign_verify_roundtrip(self) -> None:
        ident = _ident()
        sig = ident.sign(b"hello")
        assert sig.algorithm == ALGORITHM
        assert sig.key_id is not None
        assert ident.verify(b"hello", sig, AgentId("a1"))

    def test_verify_rejects_wrong_payload(self) -> None:
        ident = _ident()
        sig = ident.sign(b"hello")
        assert not ident.verify(b"tampered", sig, AgentId("a1"))

    def test_verify_rejects_wrong_signer(self) -> None:
        ident = _ident()
        sig = ident.sign(b"hello")
        assert not ident.verify(b"hello", sig, AgentId("someone-else"))

    def test_public_key_is_raw_32_bytes(self) -> None:
        assert len(_ident().public_key) == 32

    def test_private_key_never_serialised(self) -> None:
        ident = _ident()
        record = asyncio.run(ident.resolve(AgentId("a1")))
        for key in record.metadata["keys"]:
            assert "private" not in str(key).lower()


# ── Time-locked rotation ─────────────────────────────────────────────


class TestTimeLock:
    def test_instant_rotation_rejected(self) -> None:
        ident = _ident()
        ident.advance(5.0)
        with pytest.raises(ValueError, match="activates_at"):
            ident.rotate(b"new", activates_at=5.0)

    def test_rotation_below_time_lock_rejected(self) -> None:
        ident = _ident()
        ident.advance(5.0)
        with pytest.raises(ValueError, match="activates_at"):
            ident.rotate(b"new", activates_at=7.0)

    def test_rotation_at_time_lock_accepted(self) -> None:
        ident = _ident()
        ident.advance(5.0)
        pending = ident.rotate(b"new", activates_at=8.0)
        assert pending.activates_at == 8.0

    def test_rotation_activates_after_advance(self) -> None:
        ident = _ident()
        old_key = ident.current_key_id
        ident.advance(5.0)
        ident.rotate(b"new", activates_at=8.0)
        assert ident.current_key_id == old_key
        ident.advance(8.0)
        assert ident.current_key_id != old_key

    def test_default_activates_at_uses_time_lock(self) -> None:
        ident = _ident(time_lock=5.0)
        ident.advance(10.0)
        pending = ident.rotate(b"new")
        assert pending.activates_at == 15.0


# ── Social recovery ──────────────────────────────────────────────────


def _setup_recovery() -> tuple[
    Ed25519RecoverableIdentity,
    Ed25519RecoverableIdentity,
    Ed25519RecoverableIdentity,
    Ed25519RecoverableIdentity,
]:
    """Create a target with 3 attesters (quorum=2)."""
    r1 = _attester("r1", b"seed-r1")
    r2 = _attester("r2", b"seed-r2")
    r3 = _attester("r3", b"seed-r3")
    target = _ident("victim", b"victim-seed", attesters=["r1", "r2", "r3"], quorum_k=2)
    target.register_peer(AgentId("r1"), r1.public_key)
    target.register_peer(AgentId("r2"), r2.public_key)
    target.register_peer(AgentId("r3"), r3.public_key)
    return target, r1, r2, r3


def _build_recovery_event(
    target: Ed25519RecoverableIdentity,
    attesters: list[Ed25519RecoverableIdentity],
    new_seed: bytes = b"recovery-key",
    recovered_at: float = 10.0,
) -> RecoveryEvent:
    """Build a recovery event signed by the given attesters."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )
    from nest_plugins_reference.identity.ed25519_recoverable import _derive_seed

    new_priv = Ed25519PrivateKey.from_private_bytes(_derive_seed(new_seed, target.agent_id, 99))
    new_pub = _public_bytes(new_priv.public_key())
    old_key_id = target.current_key_id
    new_key_id = _key_id_for(new_pub)

    sigs: dict[str, bytes] = {}
    for att in attesters:
        sig_bytes = att.sign_recovery(target.agent_id, old_key_id, new_pub, recovered_at)
        sigs[str(att.agent_id)] = sig_bytes

    return RecoveryEvent(
        target_agent=target.agent_id,
        old_key_id=old_key_id,
        new_key_id=new_key_id,
        new_public_key=new_pub,
        recovered_at=recovered_at,
        attester_signatures=sigs,
        new_epoch=target.current_epoch + 1,
    )


class TestSocialRecovery:
    def test_quorum_recovery_accepted(self) -> None:
        target, r1, r2, _r3 = _setup_recovery()
        recovery = _build_recovery_event(target, [r1, r2])
        assert target.observe_recovery(recovery)

    def test_full_quorum_recovery_accepted(self) -> None:
        target, r1, r2, r3 = _setup_recovery()
        recovery = _build_recovery_event(target, [r1, r2, r3])
        assert target.observe_recovery(recovery)

    def test_recovery_installs_new_key(self) -> None:
        target, r1, r2, _r3 = _setup_recovery()
        old_key = target.current_key_id
        recovery = _build_recovery_event(target, [r1, r2])
        target.observe_recovery(recovery)
        assert target.current_key_id != old_key

    def test_recovery_appears_in_resolve(self) -> None:
        target, r1, r2, _r3 = _setup_recovery()
        recovery = _build_recovery_event(target, [r1, r2])
        target.observe_recovery(recovery)
        info = asyncio.run(target.resolve(AgentId("victim")))
        assert len(info.metadata["recovery_events"]) == 1
        assert info.metadata["recovery_events"][0]["attester_count"] == 2


# ── Attack classes ───────────────────────────────────────────────────


class TestInstantRotationAttack:
    def test_attacker_cannot_rotate_instantly(self) -> None:
        ident = _ident()
        ident.advance(5.0)
        with pytest.raises(ValueError, match="activates_at"):
            ident.rotate(b"evil-key", activates_at=5.0)


class TestUnilateralRecovery:
    def test_single_attester_insufficient(self) -> None:
        target, r1, _r2, _r3 = _setup_recovery()
        recovery = _build_recovery_event(target, [r1])
        assert not target.observe_recovery(recovery)

    def test_zero_attesters_rejected(self) -> None:
        target, _r1, _r2, _r3 = _setup_recovery()
        recovery = _build_recovery_event(target, [])
        assert not target.observe_recovery(recovery)


class TestDuplicateAttesterInflation:
    def test_duplicate_signatures_not_counted_twice(self) -> None:
        target, r1, _r2, _r3 = _setup_recovery()
        recovery = _build_recovery_event(target, [r1])
        recovery.attester_signatures[str(r1.agent_id) + "_dup"] = recovery.attester_signatures[
            str(r1.agent_id)
        ]
        assert not target.observe_recovery(recovery)


class TestForgedAttesterSignature:
    def test_forged_attester_sig_rejected(self) -> None:
        target, r1, r2, _r3 = _setup_recovery()
        recovery = _build_recovery_event(target, [r1, r2])
        real_sig = recovery.attester_signatures[str(r1.agent_id)]
        recovery.attester_signatures[str(r1.agent_id)] = b"\x00" * len(real_sig)
        assert not target.observe_recovery(recovery)


class TestRecoveryStaleKey:
    def test_recovery_must_match_current_key(self) -> None:
        target, r1, r2, _r3 = _setup_recovery()
        recovery = _build_recovery_event(target, [r1, r2])
        recovery.old_key_id = KeyId("nonexistent_key_id")
        assert not target.observe_recovery(recovery)


class TestPostRotationForgery:
    def test_forged_old_key_sig_rejected_after_rotation(self) -> None:
        ident = _ident()
        old_key = ident.current_key_id
        ident.advance(5.0)
        ident.rotate(b"new")
        ident.advance(8.0)
        ident.advance(9.0)
        forged = ident.sign_with(b"forged-after-rotation", old_key)
        assert not ident.verify(b"forged-after-rotation", forged, AgentId("a1"), as_of=9.0)


class TestStaleKeyReuse:
    def test_stale_key_rejected_after_supersession(self) -> None:
        ident = _ident()
        ident.advance(1.0)
        old_sig = ident.sign(b"old")
        ident.advance(5.0)
        ident.rotate(b"new")
        ident.advance(8.0)
        assert not ident.verify(b"old", old_sig, AgentId("a1"), as_of=8.0)


class TestForgedSignedAtBypass:
    def test_verifier_anchors_on_own_tick(self) -> None:
        ident = _ident()
        ident.advance(1.0)
        sig = ident.sign(b"data")
        assert sig.signed_at == 1.0
        ident.advance(5.0)
        ident.rotate(b"new")
        ident.advance(8.0)
        assert not ident.verify(b"data", sig, AgentId("a1"))


# ── Determinism ──────────────────────────────────────────────────────


class TestDeterminism:
    def test_same_seed_same_signature(self) -> None:
        a = _ident(seed=b"fixed")
        b = _ident(seed=b"fixed")
        assert a.sign(b"msg").value == b.sign(b"msg").value

    def test_same_seed_same_key_id(self) -> None:
        a = _ident(seed=b"fixed")
        b = _ident(seed=b"fixed")
        assert a.current_key_id == b.current_key_id

    def test_different_seed_different_key(self) -> None:
        a = _ident(seed=b"seed-a")
        b = _ident(seed=b"seed-b")
        assert a.current_key_id != b.current_key_id


# ── Monotonic clock ──────────────────────────────────────────────────


class TestMonotonicClock:
    def test_backward_tick_ignored(self) -> None:
        ident = _ident()
        ident.advance(10.0)
        ident.advance(5.0)  # should be silently ignored
        sig = ident.sign(b"x")
        assert sig.signed_at == 10.0

    def test_equal_tick_ignored(self) -> None:
        ident = _ident()
        ident.advance(10.0)
        ident.advance(10.0)  # should be silently ignored (not advance)
        sig = ident.sign(b"x")
        assert sig.signed_at == 10.0


# ── Observer rotation verification ──────────────────────────────────


class TestObserverRotation:
    def test_observer_verifies_rotation_continuity(self) -> None:
        signer = _ident("signer")
        signer.advance(5.0)
        pending = signer.rotate(b"new")

        observer = _ident("observer")
        observer.register_peer(AgentId("signer"), signer._epochs[AgentId("signer")][0].public_key)  # noqa: SLF001
        assert observer.observe_rotation(AgentId("signer"), pending)

    def test_observer_rejects_tampered_continuity(self) -> None:
        signer = _ident("signer")
        signer.advance(5.0)
        pending = signer.rotate(b"new")
        pending.continuity_signature = b"\x00" * 64

        observer = _ident("observer")
        observer.register_peer(AgentId("signer"), signer._epochs[AgentId("signer")][0].public_key)  # noqa: SLF001
        assert not observer.observe_rotation(AgentId("signer"), pending)


# ── Adversarial validators ───────────────────────────────────────────


class TestAdversarialValidators:
    def test_validate_no_instant_rotations_passes(self) -> None:
        from nest_plugins_reference.identity.adversarial_validators import (
            validate_no_instant_rotations,
        )

        ident = _ident()
        report = validate_no_instant_rotations(ident)
        assert report.passed, report.detail

    def test_validate_no_unilateral_recoveries_passes(self) -> None:
        from nest_plugins_reference.identity.adversarial_validators import (
            validate_no_unilateral_recoveries,
        )

        target, r1, _r2, _r3 = _setup_recovery()
        report = validate_no_unilateral_recoveries(target, [r1])
        assert report.passed, report.detail

    def test_validate_identity_governance_all_pass(self) -> None:
        from nest_plugins_reference.identity.adversarial_validators import (
            validate_identity_governance,
        )

        target, r1, _r2, _r3 = _setup_recovery()
        reports = validate_identity_governance(target, [r1])
        assert all(r.passed for r in reports), [r.detail for r in reports]
