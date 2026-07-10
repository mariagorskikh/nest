# SPDX-License-Identifier: Apache-2.0
"""Adversarial validators for the delegatable capability-token plugin.

Three attacks the default ``jwt`` auth plugin silently allows, because it
has no parent/child relationship between tokens (``JwtAuth._revoked`` is a
flat set of exact token strings):

1. **Scope escalation.**  A "delegated" token under ``jwt`` is simply a
   fresh issuance, so a child can be minted with scopes its delegator
   never held.  ``check_no_scope_escalation`` asserts every *granted*
   delegation's scopes are a subset of the delegator's scopes.
2. **Stale parent.**  Revoking or expiring a parent token leaves
   ``jwt`` children fully valid — there is no chain to walk.
   ``check_no_stale_ancestor_use`` asserts no successful verification
   happens at or after the tick where any ancestor was revoked.
3. **Audience confusion.**  ``jwt`` binds a token to a subject but never
   checks who *presents* it.  ``check_audience_binding`` asserts every
   successful presentation was made by the token's bound audience.

All three are pure functions over ``delegation_audit`` events emitted by
the ``delegated_auth`` scenario, so they compose with unit tests
(hand-built events), integration tests, and trace replays.

By construction: against the **delegatable** plugin every adversarial
action in the scenario is refused, the audits record ``granted=False`` /
``verified=False``, and all three checks pass; against the **jwt**
plugin the same actions succeed, the audits record successes, and the
checks fail — the charter's bar for "adversarial".

Example::

    events = [json.loads(line) for line in trace.open()]
    audits = extract_delegation_audits(events)
    assert check_no_scope_escalation(audits).passed
    assert check_no_stale_ancestor_use(audits).passed
    assert check_audience_binding(audits).passed
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, cast

AuditEvent = dict[str, Any]
"""One ``delegation_audit`` payload as emitted by the scenario agents."""


@dataclass
class ValidatorReport:
    """Pass/fail report with a short human-readable explanation.

    Example::

        report = check_audience_binding(audits)
        assert report.passed, report.detail
    """

    passed: bool
    detail: str
    evidence: list[AuditEvent] = field(default_factory=list[AuditEvent])


def _payload(event: dict[str, Any]) -> dict[str, Any] | None:
    """Extract a ``delegation_audit`` payload from a raw trace event.

    Example::

        audit = _payload({"msg": '{"type": "delegation_audit", ...}'})
    """
    import json

    msg: object = event.get("msg")
    if isinstance(msg, dict):
        data = cast("dict[str, Any]", msg)
    elif isinstance(msg, str):
        try:
            loaded: object = json.loads(msg)
        except json.JSONDecodeError:
            return None
        if not isinstance(loaded, dict):
            return None
        data = cast("dict[str, Any]", loaded)
    else:
        return None
    if data.get("type") != "delegation_audit":
        return None
    return data


def extract_delegation_audits(events: list[dict[str, Any]]) -> list[AuditEvent]:
    """Pull all ``delegation_audit`` payloads out of raw trace events.

    Example::

        audits = extract_delegation_audits(events)
    """
    audits: list[AuditEvent] = []
    for event in events:
        data = _payload(event)
        if data is not None:
            audits.append(data)
    return audits


def check_no_scope_escalation(audits: list[AuditEvent]) -> ValidatorReport:
    """Assert no granted delegation exceeds the delegator's scopes.

    Example::

        assert check_no_scope_escalation(audits).passed
    """
    violations: list[AuditEvent] = []
    for audit in audits:
        if audit.get("op") != "delegate" or not audit.get("granted"):
            continue
        parent = {str(s) for s in cast("list[Any]", audit.get("parent_scopes", []))}
        child = {str(s) for s in cast("list[Any]", audit.get("child_scopes", []))}
        if not child.issubset(parent):
            violations.append(audit)
    if violations:
        detail = f"{len(violations)} delegation(s) granted scopes beyond the parent"
        return ValidatorReport(passed=False, detail=detail, evidence=violations)
    return ValidatorReport(passed=True, detail="all granted delegations attenuate scopes")


def check_no_stale_ancestor_use(audits: list[AuditEvent]) -> ValidatorReport:
    """Assert no token verifies at/after the tick an ancestor was revoked.

    Example::

        assert check_no_stale_ancestor_use(audits).passed
    """
    revoked_at: dict[str, int] = {}
    for audit in audits:
        if audit.get("op") == "revoke":
            revoked_at[str(audit.get("tid", ""))] = int(cast("int", audit.get("tick", 0)))
    violations: list[AuditEvent] = []
    for audit in audits:
        if audit.get("op") != "verify" or not audit.get("verified"):
            continue
        tick = int(cast("int", audit.get("tick", 0)))
        chain = [str(t) for t in cast("list[Any]", audit.get("chain_tids", []))]
        for tid in chain:
            if tid in revoked_at and tick >= revoked_at[tid]:
                violations.append(audit)
                break
    if violations:
        detail = f"{len(violations)} verification(s) succeeded under a revoked ancestor"
        return ValidatorReport(passed=False, detail=detail, evidence=violations)
    return ValidatorReport(passed=True, detail="no token outlived a revoked ancestor")


def check_audience_binding(audits: list[AuditEvent]) -> ValidatorReport:
    """Assert every successful presentation came from the bound audience.

    Example::

        assert check_audience_binding(audits).passed
    """
    violations: list[AuditEvent] = []
    for audit in audits:
        if audit.get("op") != "verify" or not audit.get("verified"):
            continue
        presenter = str(audit.get("presenter", ""))
        audience = str(audit.get("audience", ""))
        if presenter and audience and presenter != audience:
            violations.append(audit)
    if violations:
        detail = f"{len(violations)} presentation(s) accepted from a non-audience agent"
        return ValidatorReport(passed=False, detail=detail, evidence=violations)
    return ValidatorReport(passed=True, detail="all presentations came from the bound audience")
