# SPDX-License-Identifier: Apache-2.0
"""Adversarial validators for delegatable auth — three attacks on capability tokens.

The default ``jwt`` plugin issues independent HMAC tokens with no parent-child
relationship, no audience binding, and revocation by exact string only. That
makes it silently vulnerable to the three attacks a delegation scheme must
resist:

1. **Scope escalation.** A "child" is minted with a scope its parent never held.
   :func:`check_scope_escalation_rejected` asserts the escalated scope is never
   granted — either the delegation is refused or the verified context omits it.
2. **Stale parent.** A parent token is revoked (or expires) but a child minted
   from it still verifies. :func:`check_stale_parent_rejected` asserts revoking
   the parent transitively invalidates the child.
3. **Audience confusion.** A child token bound to agent *bob* is presented by
   *mallory*. :func:`check_audience_confusion_rejected` asserts the impostor is
   rejected while the legitimate audience is accepted.

Each validator drives only the public auth surface, so the *same* check runs
against both plugins. A plugin with no ``delegate`` method (the ``jwt`` default)
can only model "delegation" as re-issuance by the authority — exactly the
anti-pattern the charter names — so :func:`_delegate` falls back to ``issue``.
Under that fallback every check **fails** against ``jwt`` and **passes** against
:class:`~nest_plugins_reference.auth.delegatable.DelegatableAuth`, which is the
charter's bar for "adversarial": the reference plugin literally cannot satisfy
them.

Example::

    from nest_plugins_reference.auth.delegatable import DelegatableAuth

    report = await check_stale_parent_rejected(DelegatableAuth(), scopes=["read"])
    assert report.passed, report.detail
"""

from __future__ import annotations

import inspect
from typing import TYPE_CHECKING, Any

from nest_core.types import AgentId

from nest_plugins_reference.validators.gossip_validators import ValidatorReport

if TYPE_CHECKING:
    from nest_core.types import Token


def _supports_presenter(auth: Any) -> bool:
    """Return ``True`` if ``auth.verify`` accepts a ``presenter`` keyword."""
    try:
        params = inspect.signature(auth.verify).parameters
    except (TypeError, ValueError):
        return False
    return "presenter" in params


async def _delegate(
    auth: Any, parent: Token, audience: AgentId, scopes: list[str], ttl: float
) -> Token:
    """Delegate a child token, falling back to re-issuance for non-delegating plugins.

    A real delegation plugin exposes ``delegate(parent, audience, scopes, ttl)``.
    A plugin without it (the ``jwt`` default) can only re-issue a fresh,
    unrelated token — which is precisely why it fails these validators.

    Example::

        child = await _delegate(auth, root, AgentId("bob"), ["read"], 600)
    """
    if hasattr(auth, "delegate"):
        result: Token = await auth.delegate(parent, audience, scopes, ttl)
        return result
    reissued: Token = await auth.issue(audience, scopes)
    return reissued


async def _verify_ok(auth: Any, token: Token, presenter: AgentId | None = None) -> bool:
    """Return ``True`` iff *token* verifies, honouring *presenter* when supported."""
    try:
        if presenter is not None and _supports_presenter(auth):
            await auth.verify(token, presenter=presenter)
        else:
            await auth.verify(token)
    except Exception:  # noqa: BLE001 - any failure is, for policy purposes, "rejected"
        return False
    return True


async def check_scope_escalation_rejected(
    auth: Any, *, root_scopes: list[str], escalated_scope: str
) -> ValidatorReport:
    """Assert a child never obtains a scope its parent does not hold.

    Issues a root limited to *root_scopes* (which must exclude *escalated_scope*),
    then attempts to delegate the escalated scope. Passes iff delegation is
    refused, or the resulting context does not carry the escalated scope. Against
    ``jwt`` the re-issued token simply grants it.

    Example::

        report = await check_scope_escalation_rejected(
            auth, root_scopes=["read"], escalated_scope="write"
        )
        assert report.passed, report.detail
    """
    root = await auth.issue(AgentId("esc-root"), root_scopes)
    try:
        child = await _delegate(auth, root, AgentId("esc-child"), [escalated_scope], 600.0)
    except Exception:  # noqa: BLE001 - refusing to broaden scope is the correct behaviour
        return ValidatorReport(passed=True, detail="delegation refused scope escalation")
    try:
        ctx = await auth.verify(child, presenter=AgentId("esc-child"))
    except TypeError:
        ctx = await auth.verify(child)
    if escalated_scope in ctx.scopes:
        return ValidatorReport(
            passed=False,
            detail=f"child obtained scope {escalated_scope!r} its parent never held",
            evidence={"granted_scopes": list(ctx.scopes)},
        )
    return ValidatorReport(passed=True, detail="escalated scope was not granted")


async def check_stale_parent_rejected(auth: Any, *, scopes: list[str]) -> ValidatorReport:
    """Assert revoking a parent transitively invalidates a child delegated from it.

    Delegates a child, confirms it verifies, revokes the *parent*, then re-checks
    the child. Passes iff the child verifies before revocation and fails after.
    Against ``jwt`` the child is an unrelated token, so revoking the parent leaves
    it valid.

    Example::

        report = await check_stale_parent_rejected(auth, scopes=["read"])
        assert report.passed, report.detail
    """
    parent = await auth.issue(AgentId("stale-parent"), scopes)
    child = await _delegate(auth, parent, AgentId("stale-child"), scopes, 600.0)
    if not await _verify_ok(auth, child, AgentId("stale-child")):
        return ValidatorReport(passed=False, detail="child failed to verify before revocation")
    await auth.revoke(parent)
    if await _verify_ok(auth, child, AgentId("stale-child")):
        return ValidatorReport(
            passed=False, detail="child still verifies after its parent was revoked"
        )
    return ValidatorReport(passed=True, detail="child invalidated by parent revocation")


async def check_audience_confusion_rejected(auth: Any, *, scopes: list[str]) -> ValidatorReport:
    """Assert a child token is rejected when presented by an agent other than its audience.

    Delegates a child bound to *bob*, confirms *bob* can present it, then has
    *mallory* present the same token. Passes iff the legitimate audience is
    accepted and the impostor is rejected. Against ``jwt`` (no audience binding)
    the impostor is accepted.

    Example::

        report = await check_audience_confusion_rejected(auth, scopes=["read"])
        assert report.passed, report.detail
    """
    if not _supports_presenter(auth):
        return ValidatorReport(
            passed=False,
            detail="verify() has no audience binding; any holder can present the token",
        )
    root = await auth.issue(AgentId("aud-root"), scopes)
    child = await _delegate(auth, root, AgentId("aud-bob"), scopes, 600.0)
    if not await _verify_ok(auth, child, AgentId("aud-bob")):
        return ValidatorReport(passed=False, detail="legitimate audience could not present token")
    if await _verify_ok(auth, child, AgentId("aud-mallory")):
        return ValidatorReport(
            passed=False, detail="impostor presented another agent's token successfully"
        )
    return ValidatorReport(passed=True, detail="impostor rejected; audience binding enforced")
