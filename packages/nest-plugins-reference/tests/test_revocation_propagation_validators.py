# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the revocation-propagation validators.

Hand-built audit streams cover every verdict path of both checks --
converged / stale-forever / vacuous for ``check_revocation_converges``,
and available / impossibly-instant / missing-revocation for
``check_partition_liveness`` -- plus ``find_partition_ticks`` extraction.
The full-runner discrimination test (both auth plugins through the real
simulator and partition machinery) lives in
``packages/nest-core/tests/test_delegated_auth_partition_scenario.py``.
"""

from __future__ import annotations

from typing import Any

from nest_plugins_reference.validators import (
    check_partition_liveness,
    check_revocation_converges,
    find_partition_ticks,
)

REVOKED_TID = "aaaa000011112222"


def _revoke(tick: int = 20) -> dict[str, Any]:
    return {
        "type": "delegation_audit",
        "op": "revoke",
        "tick": tick,
        "tid": REVOKED_TID,
        "target": "intermediary-1",
        "revoker": "coordinator-0",
    }


def _verify(tick: int, verifier: str, verified: bool, tid: str = REVOKED_TID) -> dict[str, Any]:
    return {
        "type": "delegation_audit",
        "op": "verify",
        "tick": tick,
        "verifier": verifier,
        "presenter": "leaf-3",
        "audience": "leaf-3",
        "chain_tids": ["rootroot", tid, "leafleaf"],
        "verified": verified,
    }


# -- check_revocation_converges ---------------------------------------------


def test_converges_passes_when_all_verifiers_deny_after_deadline() -> None:
    audits = [
        _revoke(),
        _verify(30, "gateway-0", verified=True),  # during partition: allowed
        _verify(70, "gateway-0", verified=False),
        _verify(76, "coordinator-0", verified=False),
    ]
    report = check_revocation_converges(audits, deadline_tick=67.0)
    assert report.passed, report.detail


def test_converges_fails_on_stale_accept_after_deadline() -> None:
    audits = [
        _revoke(),
        _verify(70, "gateway-0", verified=True),
        _verify(76, "gateway-0", verified=False),
    ]
    report = check_revocation_converges(audits, deadline_tick=67.0)
    assert not report.passed
    assert report.evidence


def test_converges_fails_vacuously_without_remote_denial() -> None:
    # Presentations simply stopped after the deadline: convergence unproven.
    audits = [
        _revoke(),
        _verify(30, "gateway-0", verified=True),
        _verify(70, "coordinator-0", verified=False),  # revoker's own denial doesn't count
    ]
    report = check_revocation_converges(audits, deadline_tick=67.0)
    assert not report.passed
    assert "unproven" in report.detail


def test_converges_fails_without_any_revocation() -> None:
    report = check_revocation_converges([_verify(70, "gateway-0", False)], deadline_tick=67.0)
    assert not report.passed


def test_converges_ignores_unrelated_lineages() -> None:
    audits = [
        _revoke(),
        _verify(70, "gateway-0", verified=True, tid="ffff999988887777"),  # different lineage
        _verify(72, "gateway-0", verified=False),
    ]
    report = check_revocation_converges(audits, deadline_tick=67.0)
    assert report.passed, report.detail


# -- check_partition_liveness ------------------------------------------------


def test_liveness_passes_when_isolated_side_kept_serving() -> None:
    audits = [_revoke(tick=20), _verify(30, "gateway-0", verified=True)]
    report = check_partition_liveness(audits, heal_tick=57.0)
    assert report.passed, report.detail


def test_liveness_fails_on_impossibly_instant_denial() -> None:
    # The shared-single-instance shortcut: the remote verifier denies within
    # the partition window despite never having been reachable.
    audits = [
        _revoke(tick=20),
        _verify(30, "gateway-0", verified=False),
        _verify(40, "gateway-0", verified=False),
    ]
    report = check_partition_liveness(audits, heal_tick=57.0)
    assert not report.passed


def test_liveness_ignores_revokers_own_denials() -> None:
    audits = [
        _revoke(tick=20),
        _verify(30, "coordinator-0", verified=False),  # the revoker knows, of course
        _verify(36, "gateway-0", verified=True),
    ]
    report = check_partition_liveness(audits, heal_tick=57.0)
    assert report.passed, report.detail


def test_liveness_fails_without_any_revocation() -> None:
    report = check_partition_liveness([_verify(30, "gateway-0", True)], heal_tick=57.0)
    assert not report.passed


# -- find_partition_ticks -----------------------------------------------------


def test_find_partition_ticks_reads_simulator_records() -> None:
    events = [
        {"ts": 1.0, "agent": "a", "kind": "receive", "msg": "{}"},
        {"ts": 9.0, "agent": "_simulator", "kind": "partition_started"},
        {"ts": 57.0, "agent": "_simulator", "kind": "partition_healed"},
    ]
    assert find_partition_ticks(events) == (9.0, 57.0)


def test_find_partition_ticks_handles_absence() -> None:
    assert find_partition_ticks([{"ts": 1.0, "kind": "receive"}]) == (None, None)
