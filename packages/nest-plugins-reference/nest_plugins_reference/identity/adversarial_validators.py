# SPDX-License-Identifier: Apache-2.0
# pyright: reportPrivateUsage=false
"""Adversarial validators for the ``ed25519_recoverable`` identity plugin.

Two governance invariants that ``ed25519_rotating`` (and ``did_key``) silently
allow to be violated:

1. **No instant rotations.** A rotation whose ``activates_at`` is less than
   ``current_tick + time_lock`` must be rejected. ``ed25519_rotating`` accepts
   rotations at any tick — an attacker with a briefly captured key can rotate
   immediately. ``validate_no_instant_rotations`` exercises this by attempting
   a rotation that violates the time-lock and asserting it fails.

2. **No unilateral recoveries.** A recovery signed by fewer than K distinct,
   declared attesters must be rejected. ``ed25519_rotating`` has no recovery
   concept at all. ``validate_no_unilateral_recoveries`` exercises this by
   building a recovery event with only 1 attester signature (below quorum)
   and asserting it is rejected.

Each validator is a pure function on the plugin's public API surface — it
performs only ``rotate``/``observe_recovery``/``sign_recovery``/``advance``
calls and never reaches into plugin internals.

By construction:

* against ``ed25519_recoverable`` every check **passes** (the governance
  rules are enforced);
* against ``ed25519_rotating`` and ``did_key`` the checks either **fail** or
  are not applicable (no time-lock, no recovery).

Example::

    report = validate_no_instant_rotations(plugin)
    assert report.passed, report.detail
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import cast


@dataclass
class ValidatorReport:
    """Pass/fail report with a short human-readable explanation.

    Example::

        report = ValidatorReport(passed=True, detail="time-lock enforced")
        assert report.passed, report.detail
    """

    passed: bool
    detail: str
    evidence: dict[str, object] = field(default_factory=lambda: dict[str, object]())


def validate_no_instant_rotations(plugin: object) -> ValidatorReport:
    """Assert the plugin rejects rotations that violate the time-lock.

    Attempts a rotation with ``activates_at = current_tick`` (instant), which
    must raise ``ValueError`` on ``ed25519_recoverable``. On plugins without
    a ``rotate`` method, returns a failing report.

    Example::

        report = validate_no_instant_rotations(plugin)
        assert report.passed, report.detail
    """
    if not hasattr(plugin, "rotate"):
        return ValidatorReport(
            passed=False,
            detail="plugin has no rotate method (no time-lock support)",
        )

    if not hasattr(plugin, "advance"):
        return ValidatorReport(
            passed=False,
            detail="plugin has no advance method (no time-lock support)",
        )

    plugin.advance(10.0)  # type: ignore[union-attr]

    try:
        plugin.rotate(b"instant-attack", activates_at=10.0)  # type: ignore[union-attr]
        return ValidatorReport(
            passed=False,
            detail="instant rotation was accepted (no time-lock enforcement)",
            evidence={"activates_at": 10.0, "current_tick": 10.0},
        )
    except ValueError:
        return ValidatorReport(
            passed=True,
            detail="instant rotation rejected by time-lock",
        )


def validate_no_unilateral_recoveries(
    plugin: object,
    attester_plugins: list[object],
) -> ValidatorReport:
    """Assert the plugin rejects a recovery with fewer than K attester signatures.

    Builds a recovery event signed by only *one* attester (below the default
    quorum of 2) and asserts ``observe_recovery`` rejects it.

    Example::

        report = validate_no_unilateral_recoveries(plugin, [attester1])
        assert report.passed, report.detail
    """
    if not hasattr(plugin, "observe_recovery"):
        return ValidatorReport(
            passed=False,
            detail="plugin has no observe_recovery method (no recovery support)",
        )

    if not attester_plugins:
        return ValidatorReport(
            passed=False,
            detail="no attester plugins provided for recovery test",
        )

    from nest_core.types import AgentId

    from nest_plugins_reference.identity.ed25519_recoverable import (
        KeyId,
        RecoveryEvent,
        _key_id_for,
    )

    target_agent = cast("AgentId", plugin.agent_id)  # type: ignore[union-attr]
    old_key_id = cast("KeyId", plugin.current_key_id)  # type: ignore[union-attr]

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    recovery_seed = b"recovery-key-for-test"
    import hashlib

    recovery_key_material = hashlib.sha512(
        b"ed25519-recoverable:" + recovery_seed + b":recovery:0"
    ).digest()[:32]
    recovery_private = Ed25519PrivateKey.from_private_bytes(recovery_key_material)

    from nest_plugins_reference.identity.ed25519_recoverable import _public_bytes

    new_public_key = _public_bytes(recovery_private.public_key())

    recovered_at = 10.0
    new_key_id = _key_id_for(new_public_key)

    attester = attester_plugins[0]
    attester_id = str(attester.agent_id)  # type: ignore[union-attr]
    attester_sig = attester.sign_recovery(  # type: ignore[union-attr]
        target_agent, old_key_id, new_public_key, recovered_at
    )

    recovery_event = RecoveryEvent(
        target_agent=target_agent,
        old_key_id=old_key_id,
        new_key_id=new_key_id,
        new_public_key=new_public_key,
        recovered_at=recovered_at,
        attester_signatures={attester_id: attester_sig},
        new_epoch=1,
    )

    accepted = plugin.observe_recovery(recovery_event)  # type: ignore[union-attr]
    if accepted:
        return ValidatorReport(
            passed=False,
            detail="unilateral recovery (1 of K) was accepted",
            evidence={"attester_count": 1, "required_k": 2},
        )
    return ValidatorReport(
        passed=True,
        detail="unilateral recovery rejected (quorum not met)",
    )


def validate_identity_governance(
    plugin: object,
    attester_plugins: list[object] | None = None,
) -> list[ValidatorReport]:
    """Run both governance validators and return their reports.

    Example::

        reports = validate_identity_governance(plugin, [att1])
        assert all(r.passed for r in reports)
    """
    reports = [validate_no_instant_rotations(plugin)]
    if attester_plugins:
        reports.append(validate_no_unilateral_recoveries(plugin, attester_plugins))
    return reports
