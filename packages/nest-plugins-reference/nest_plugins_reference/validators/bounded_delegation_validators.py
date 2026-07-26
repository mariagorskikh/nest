# SPDX-License-Identifier: Apache-2.0
"""Adversarial validators for unbounded growth in delegatable auth.

The merged ``delegatable`` and ``mesh_revocable`` plugins are
cryptographically sound: the existing delegation validators (scope
escalation, stale ancestor, audience confusion) pass against both. The
two failure modes here are *resource* attacks that leave every crypto
invariant intact, which is exactly why the existing validators do not
catch them.

1. **Chain inflation.** ``delegate`` appends a segment and re-signs, with
   no depth cap. Attenuation is offline by design, so a holder needs no
   issuer contact. Each added segment is another the *verifier* must walk,
   so one holder inflates cost for every agent it presents to.
   ``check_chain_depth_bounded`` asserts no verified token exceeded the
   declared bound.

2. **Revocation set growth.** ``_revoked`` is a G-Set, so it only grows.
   An entry whose segment has expired can no longer change any outcome --
   ``_check_chain`` rejects the token on expiry before revocation is
   consulted -- yet it is retained on every replica and re-sent in every
   gossip round. ``check_revocations_pruned`` asserts entries eligible for
   pruning were actually dropped.

Both are pure functions over ``bounded_delegation_audit`` events, so they
compose with unit tests (hand-built events), integration tests, and trace
replays.

By construction: against **bounded_delegation** the over-deep mint is
refused and expired entries are dropped, so both checks pass; against
**delegatable** or **mesh_revocable** the same actions succeed unbounded,
the audits record the growth, and both checks fail.

Example::

    events = [json.loads(line) for line in trace.open()]
    audits = extract_bounded_audits(events)
    assert check_chain_depth_bounded(audits).passed
    assert check_revocations_pruned(audits).passed
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, cast

AuditEvent = dict[str, Any]
"""One ``bounded_delegation_audit`` payload as emitted by the scenario."""


@dataclass
class ValidatorReport:
    """Pass/fail report with a short human-readable explanation.

    Mirrors the shape used by the delegation and gossip validators so the
    three compose in a single scenario assertion block.

    Example::

        report = check_chain_depth_bounded(audits)
        assert report.passed, report.detail
    """

    passed: bool
    detail: str
    evidence: list[AuditEvent] = field(default_factory=list[AuditEvent])


def _payload(event: dict[str, Any]) -> dict[str, Any] | None:
    """Extract a ``bounded_delegation_audit`` payload from a raw trace event.

    Accepts both an already-decoded payload and one still wrapped in a
    ``msg`` string, matching how the shipped scenarios emit events.

    Example::

        audit = _payload({"msg": '{"type": "bounded_delegation_audit"}'})
    """
    candidate: object = event
    raw = event.get("msg")
    if isinstance(raw, str):
        try:
            candidate = json.loads(raw)
        except json.JSONDecodeError:
            return None
    if not isinstance(candidate, dict):
        return None
    payload = cast("dict[str, Any]", candidate)
    if payload.get("type") != "bounded_delegation_audit":
        return None
    return payload


def extract_bounded_audits(events: list[dict[str, Any]]) -> list[AuditEvent]:
    """Pull every ``bounded_delegation_audit`` payload out of a trace.

    Example::

        audits = extract_bounded_audits(events)
    """
    found = [_payload(event) for event in events]
    return [audit for audit in found if audit is not None]


def check_chain_depth_bounded(audits: list[AuditEvent]) -> ValidatorReport:
    """Assert no token verified past its declared ``max_depth``.

    Only ``verified=True`` audits count: a refused over-deep mint is the
    plugin working, and its audit records the attempt. What must never
    appear is a *successful* verification of a chain deeper than the
    bound the same audit declares.

    Fails against ``delegatable`` and ``mesh_revocable``, which have no
    bound and therefore verify chains of any depth.

    Example::

        >>> ok = [{"type": "bounded_delegation_audit", "verified": True,
        ...        "depth": 3, "max_depth": 8}]
        >>> check_chain_depth_bounded(ok).passed
        True
    """
    violations = [
        audit
        for audit in audits
        if audit.get("verified") is True
        and isinstance(audit.get("depth"), int)
        and isinstance(audit.get("max_depth"), int)
        and cast("int", audit["depth"]) > cast("int", audit["max_depth"])
    ]
    if violations:
        worst = max(violations, key=lambda a: cast("int", a["depth"]))
        return ValidatorReport(
            passed=False,
            detail=(
                f"{len(violations)} verification(s) exceeded max_depth; "
                f"deepest was {worst['depth']} against a bound of "
                f"{worst['max_depth']}"
            ),
            evidence=violations,
        )
    verified = [a for a in audits if a.get("verified") is True]
    return ValidatorReport(
        passed=True,
        detail=f"all {len(verified)} verified token(s) within max_depth",
    )


def check_depth_attack_refused(audits: list[AuditEvent]) -> ValidatorReport:
    """Assert at least one over-deep delegation was attempted and refused.

    Guards against a scenario that passes
    :func:`check_chain_depth_bounded` only because nobody ever tried the
    attack. A validator that cannot distinguish "defended" from "never
    provoked" is not adversarial.

    Example::

        >>> audits = [{"type": "bounded_delegation_audit",
        ...            "action": "delegate", "granted": False,
        ...            "reason": "depth"}]
        >>> check_depth_attack_refused(audits).passed
        True
    """
    attempts = [a for a in audits if a.get("action") == "delegate"]
    refused = [a for a in attempts if a.get("granted") is False and a.get("reason") == "depth"]
    if not attempts:
        return ValidatorReport(
            passed=False,
            detail="no delegation attempts recorded; scenario never exercised the bound",
        )
    if not refused:
        return ValidatorReport(
            passed=False,
            detail=(
                f"{len(attempts)} delegation(s) recorded, none refused for depth; "
                "the bound was never provoked"
            ),
            evidence=attempts,
        )
    return ValidatorReport(
        passed=True,
        detail=f"{len(refused)} over-deep delegation(s) refused",
        evidence=refused,
    )


def check_revocations_pruned(audits: list[AuditEvent]) -> ValidatorReport:
    """Assert no replica retained revocation entries eligible for pruning.

    An audit reports ``prunable``: entries whose segments expired more
    than ``prune_grace`` ago. Those can no longer affect verification,
    so a correct replica drops them. Any non-zero count at the end of a
    scenario is unbounded growth.

    Fails against ``mesh_revocable``, whose G-Set never removes anything.

    Example::

        >>> audits = [{"type": "bounded_delegation_audit",
        ...            "action": "gossip", "prunable": 0, "retained": 2}]
        >>> check_revocations_pruned(audits).passed
        True
    """
    reports = [a for a in audits if isinstance(a.get("prunable"), int)]
    if not reports:
        return ValidatorReport(
            passed=False,
            detail="no revocation-size audits recorded; pruning was never observed",
        )
    leaking = [a for a in reports if cast("int", a["prunable"]) > 0]
    if leaking:
        worst = max(leaking, key=lambda a: cast("int", a["prunable"]))
        return ValidatorReport(
            passed=False,
            detail=(
                f"{len(leaking)} replica report(s) retained prunable entries; "
                f"worst held {worst['prunable']} expired revocation(s)"
            ),
            evidence=leaking,
        )
    return ValidatorReport(
        passed=True,
        detail=f"all {len(reports)} replica report(s) free of prunable entries",
    )


def check_pruning_preserves_liveness(audits: list[AuditEvent]) -> ValidatorReport:
    """Assert pruning never let a still-live revocation stop taking effect.

    The risk in pruning a G-Set is dropping an entry that still matters:
    a token whose segment has *not* expired must keep failing after
    revocation. This asserts no audit recorded a successful verification
    of a token whose leaf was revoked and unexpired.

    Example::

        >>> audits = [{"type": "bounded_delegation_audit", "verified": True,
        ...            "leaf_revoked": False}]
        >>> check_pruning_preserves_liveness(audits).passed
        True
    """
    resurrected = [
        a
        for a in audits
        if a.get("verified") is True
        and a.get("leaf_revoked") is True
        and a.get("leaf_expired") is not True
    ]
    if resurrected:
        return ValidatorReport(
            passed=False,
            detail=(
                f"{len(resurrected)} token(s) verified despite a live revocation; "
                "pruning dropped an entry that still mattered"
            ),
            evidence=resurrected,
        )
    return ValidatorReport(
        passed=True,
        detail="no live revocation was lost to pruning",
    )
