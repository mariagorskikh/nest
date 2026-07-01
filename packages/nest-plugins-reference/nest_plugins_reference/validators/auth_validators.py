# SPDX-License-Identifier: Apache-2.0
"""Adversarial validators for delegatable capability tokens.

Three attacks the default ``jwt`` plugin silently allows — because its tokens
are flat, unrelated strings with no parent/child relationship and no audience
binding:

1. **Scope escalation** — a "delegated" token grants a capability the delegator
   never held.  ``jwt`` re-issues an independent token with whatever scopes are
   asked for and ``verify`` accepts it.  ``check_no_scope_escalation`` catches
   any *verified* grant whose scopes are not a subset of its parent's.
2. **Stale ancestor** — a child still verifies after its parent was revoked (or
   expired).  ``jwt._revoked`` is keyed by exact token string, so revoking the
   parent does nothing to the child.  ``check_no_stale_ancestor`` catches any
   *verified* grant with a revoked/expired ancestor in its chain.
3. **Audience confusion** — a token minted for *B* is presented by *C* and
   still verifies.  ``jwt`` has no audience binding.
   ``check_no_audience_confusion`` catches any *verified* grant whose presenter
   is not its declared audience.

Each validator is a **pure function** over a list of :class:`GrantObservation`
records — the same shape whether the evidence was built by driving a live auth
plugin (unit/integration tests) or replayed from a scenario trace.  A grant is
only a violation if the plugin actually *accepted* it (``verified=True``); a
plugin that raises on the attack produces ``verified=False`` records and passes
cleanly.  That is exactly the charter's bar:

* against the **delegatable** plugin every attack raises, so no verified grant
  is a violation and all three checks PASS;
* against the **jwt** plugin every attack is accepted, so the matching check
  FAILS — the validator literally cannot be satisfied by the reference plugin.

Example::

    grants = [GrantObservation(jti="c", parent_jti="r", audience=AgentId("b"),
                               scopes=("read", "admin"), presenter=AgentId("b"),
                               verified=True)]
    parents = {"r": ("read",)}
    assert not check_no_scope_escalation(grants, parent_scopes=parents).passed
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from nest_plugins_reference.validators.gossip_validators import ValidatorReport

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from nest_core.types import AgentId


@dataclass(frozen=True)
class GrantObservation:
    """One observed capability grant and whether the plugin accepted it.

    ``verified`` records the plugin's own verdict when the (possibly malicious)
    token was presented — the validators only ever flag grants the plugin
    *accepted*.

    Example::

        obs = GrantObservation(
            jti="child-1", parent_jti="root-0", audience=AgentId("b"),
            scopes=("read",), presenter=AgentId("b"), verified=True,
        )
    """

    jti: str
    parent_jti: str | None
    audience: AgentId
    scopes: tuple[str, ...]
    presenter: AgentId
    verified: bool
    error: str | None = None


def check_no_scope_escalation(
    grants: Sequence[GrantObservation],
    *,
    parent_scopes: Mapping[str, tuple[str, ...]],
) -> ValidatorReport:
    """Assert no *verified* grant holds a scope its parent never held.

    ``parent_scopes`` maps a link id to the scope set that link legitimately
    held, so the check works even when the parent link itself is not among the
    supplied ``grants`` (e.g. a root minted separately).

    Returns ``passed=False`` with ``evidence["escalations"]`` listing
    ``(jti, gained_scopes)`` pairs when any accepted child widened its scopes.

    Example::

        report = check_no_scope_escalation(grants, parent_scopes={"r": ("read",)})
        assert report.passed, report.detail
    """
    escalations: list[tuple[str, list[str]]] = []
    for g in grants:
        if not g.verified or g.parent_jti is None:
            continue
        allowed = set(parent_scopes.get(g.parent_jti, ()))
        gained = sorted(set(g.scopes) - allowed)
        if gained:
            escalations.append((g.jti, gained))
    if escalations:
        return ValidatorReport(
            passed=False,
            detail=f"{len(escalations)} verified grant(s) escalated scope beyond parent",
            evidence={"escalations": escalations[:20]},
        )
    return ValidatorReport(passed=True, detail="no verified grant escalated scope")


def check_no_stale_ancestor(
    grants: Sequence[GrantObservation],
    *,
    revoked_jtis: set[str],
) -> ValidatorReport:
    """Assert no *verified* grant has a revoked ancestor in its chain.

    The chain is reconstructed transitively from each grant's ``parent_jti``
    pointers across the whole ``grants`` set, so revoking a *root* is caught on
    a deep descendant even when only the leaf was presented.

    Returns ``passed=False`` with ``evidence["stale"]`` listing
    ``(jti, revoked_ancestor)`` pairs.

    Example::

        report = check_no_stale_ancestor(grants, revoked_jtis={"root-0"})
        assert report.passed, report.detail
    """
    parent_of: dict[str, str | None] = {g.jti: g.parent_jti for g in grants}
    stale: list[tuple[str, str]] = []
    for g in grants:
        if not g.verified:
            continue
        seen: set[str] = set()
        cursor: str | None = g.jti
        while cursor is not None and cursor not in seen:
            seen.add(cursor)
            if cursor in revoked_jtis:
                stale.append((g.jti, cursor))
                break
            cursor = parent_of.get(cursor)
    if stale:
        return ValidatorReport(
            passed=False,
            detail=f"{len(stale)} verified grant(s) survived a revoked ancestor",
            evidence={"stale": stale[:20]},
        )
    return ValidatorReport(passed=True, detail="no verified grant had a revoked ancestor")


def check_no_audience_confusion(grants: Sequence[GrantObservation]) -> ValidatorReport:
    """Assert every *verified* grant was presented by its declared audience.

    Returns ``passed=False`` with ``evidence["confused"]`` listing
    ``(jti, audience, presenter)`` triples where an accepted token was
    presented by someone other than its audience.

    Example::

        report = check_no_audience_confusion(grants)
        assert report.passed, report.detail
    """
    confused: list[tuple[str, str, str]] = []
    for g in grants:
        if g.verified and g.presenter != g.audience:
            confused.append((g.jti, str(g.audience), str(g.presenter)))
    if confused:
        return ValidatorReport(
            passed=False,
            detail=f"{len(confused)} verified grant(s) presented by the wrong agent",
            evidence={"confused": confused[:20]},
        )
    return ValidatorReport(passed=True, detail="no verified grant confused its audience")


@dataclass(frozen=True)
class DelegationAudit:
    """Aggregate result of all three delegation-safety checks.

    Example::

        audit = check_delegation_safety(grants, parent_scopes=ps, revoked_jtis=set())
        assert audit.passed, audit.reports
    """

    passed: bool
    reports: dict[str, ValidatorReport] = field(default_factory=dict[str, ValidatorReport])


def check_delegation_safety(
    grants: Sequence[GrantObservation],
    *,
    parent_scopes: Mapping[str, tuple[str, ...]],
    revoked_jtis: set[str],
) -> DelegationAudit:
    """Run all three adversarial checks and report the combined verdict.

    ``passed`` is ``True`` only if none of scope escalation, stale-ancestor
    survival, or audience confusion is present among the accepted grants.

    Example::

        audit = check_delegation_safety(grants, parent_scopes=ps, revoked_jtis={"r"})
        assert audit.passed, audit.reports["stale_ancestor"].detail
    """
    reports = {
        "scope_escalation": check_no_scope_escalation(grants, parent_scopes=parent_scopes),
        "stale_ancestor": check_no_stale_ancestor(grants, revoked_jtis=revoked_jtis),
        "audience_confusion": check_no_audience_confusion(grants),
    }
    return DelegationAudit(
        passed=all(r.passed for r in reports.values()),
        reports=reports,
    )
