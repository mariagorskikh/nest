# SPDX-License-Identifier: Apache-2.0
"""Validators for revocation propagation across a partitioned mesh.

The ``delegation_validators`` prove capability *semantics* against a single
verifier. These two checks prove capability *distribution* -- what happens
when every verifier owns its own auth replica and the network splits. They
are pure functions over the same ``delegation_audit`` events (as emitted by
the ``delegated_auth_partition`` scenario, whose verify audits carry a
``verifier`` field and whose revoke audits carry a ``revoker`` field).

1. **Convergence.** ``check_revocation_converges`` asserts that after a
   deadline (partition heal + a gossip-propagation bound) no verifier
   anywhere accepts a revoked lineage -- and, anti-vacuously, that at least
   one verifier *other than the revoker* explicitly denied it after the
   deadline. Against per-replica ``delegatable`` the gossip channel does
   not exist, remote replicas stay stale forever, and this check FAILS;
   against ``mesh_revocable`` it passes.
2. **Partition liveness.** ``check_partition_liveness`` asserts that a
   verifier other than the revoker accepted the revoked lineage *during*
   the partition window. That is honest CAP behavior -- a replica that
   cannot have heard of the revocation must not magically deny it. The
   check fails against the shared-single-instance wiring (which exhibits
   physically impossible instant knowledge), keeping the scenario honest.

Deliberately NOT asserted here: ``check_no_stale_ancestor_use``'s global
"no success at/after the revoke tick" -- under a partition that property is
unattainable (CAP); the bounded convergence check above is its honest
replacement.

Example::

    events = [json.loads(line) for line in trace.open()]
    audits = extract_delegation_audits(events)
    started, healed = find_partition_ticks(events)
    assert healed is not None
    assert check_partition_liveness(audits, heal_tick=healed).passed
    assert check_revocation_converges(audits, deadline_tick=healed + 10).passed
"""

from __future__ import annotations

from typing import Any, cast

from nest_plugins_reference.validators.delegation_validators import (
    AuditEvent,
    ValidatorReport,
)


def find_partition_ticks(events: list[dict[str, Any]]) -> tuple[float | None, float | None]:
    """Read the simulator's partition window from raw trace events.

    Returns ``(started_ts, healed_ts)``; either is ``None`` if the
    corresponding ``_simulator`` record is absent.

    Example::

        started, healed = find_partition_ticks(events)
    """
    started: float | None = None
    healed: float | None = None
    for event in events:
        kind = event.get("kind")
        if kind == "partition_started" and started is None:
            started = float(cast("float", event.get("ts", 0.0)))
        elif kind == "partition_healed" and healed is None:
            healed = float(cast("float", event.get("ts", 0.0)))
    return started, healed


def _revocations(audits: list[AuditEvent]) -> dict[str, tuple[int, str]]:
    """Map each revoked tid to ``(revoke_tick, revoker)``.

    Example::

        revoked = _revocations(audits)
    """
    revoked: dict[str, tuple[int, str]] = {}
    for audit in audits:
        if audit.get("op") == "revoke":
            tid = str(audit.get("tid", ""))
            revoked[tid] = (int(cast("int", audit.get("tick", 0))), str(audit.get("revoker", "")))
    return revoked


def _chain(audit: AuditEvent) -> list[str]:
    return [str(t) for t in cast("list[Any]", audit.get("chain_tids", []))]


def _verifies_of(audits: list[AuditEvent], tid: str) -> list[AuditEvent]:
    return [a for a in audits if a.get("op") == "verify" and tid in _chain(a)]


def check_revocation_converges(
    audits: list[AuditEvent],
    *,
    deadline_tick: float,
) -> ValidatorReport:
    """Assert every revocation is mesh-wide fatal after the deadline.

    For each revoked tid: no verifier anywhere reports ``verified=True``
    for a lineage containing it at ``tick >= deadline_tick``, AND at least
    one verifier other than the revoker explicitly denied that lineage
    after the deadline (so a scenario where presentations simply stopped
    cannot pass vacuously).

    Example::

        report = check_revocation_converges(audits, deadline_tick=67.0)
        assert report.passed, report.detail
    """
    revoked = _revocations(audits)
    if not revoked:
        return ValidatorReport(passed=False, detail="no revocation audits found")
    stale: list[AuditEvent] = []
    for tid, (_, revoker) in revoked.items():
        remote_denials = 0
        for audit in _verifies_of(audits, tid):
            tick = int(cast("int", audit.get("tick", 0)))
            if tick < deadline_tick:
                continue
            if audit.get("verified"):
                stale.append(audit)
            elif str(audit.get("verifier", "")) != revoker:
                remote_denials += 1
        if remote_denials == 0:
            detail = (
                f"no verifier other than the revoker ever denied lineage {tid} "
                f"after tick {deadline_tick} — convergence unproven"
            )
            return ValidatorReport(passed=False, detail=detail)
    if stale:
        detail = (
            f"{len(stale)} verification(s) accepted a revoked lineage after "
            f"tick {deadline_tick} — revocation never converged"
        )
        return ValidatorReport(passed=False, detail=detail, evidence=stale)
    return ValidatorReport(
        passed=True,
        detail=f"every revocation is mesh-wide fatal from tick {deadline_tick}",
    )


def check_partition_liveness(
    audits: list[AuditEvent],
    *,
    heal_tick: float,
) -> ValidatorReport:
    """Assert the isolated side stayed available during the partition.

    For each revoked tid: at least one verifier other than the revoker
    reported ``verified=True`` for that lineage between the revoke tick
    and the heal -- i.e. a replica that could not yet know about the
    revocation kept serving. A deployment where remote verifiers deny
    *instantly* is exhibiting knowledge the network cannot have delivered
    (the shared-single-instance shortcut) and fails this check.

    Example::

        report = check_partition_liveness(audits, heal_tick=57.0)
        assert report.passed, report.detail
    """
    revoked = _revocations(audits)
    if not revoked:
        return ValidatorReport(passed=False, detail="no revocation audits found")
    for tid, (revoke_tick, revoker) in revoked.items():
        window_accepts = [
            a
            for a in _verifies_of(audits, tid)
            if a.get("verified")
            and str(a.get("verifier", "")) != revoker
            and revoke_tick <= int(cast("int", a.get("tick", 0))) < heal_tick
        ]
        if not window_accepts:
            detail = (
                f"no verifier other than the revoker accepted lineage {tid} between "
                f"revocation (tick {revoke_tick}) and heal (tick {heal_tick}) — either "
                "the partition never isolated a verifier or revocation knowledge "
                "traveled faster than the network allows"
            )
            return ValidatorReport(passed=False, detail=detail)
    return ValidatorReport(
        passed=True,
        detail="isolated verifiers stayed available until revocation state reached them",
    )
