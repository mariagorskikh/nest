# SPDX-License-Identifier: Apache-2.0
"""Adversarial validators for the ``delegatable`` auth plugin.

Three attacks the default ``jwt`` auth plugin silently allows:

1. **Scope escalation.**  ``jwt`` has no delegation API, so any agent can
   call ``issue()`` with arbitrary scopes and the call succeeds. Our plugin's
   ``delegate()`` enforces a strict scope-subset check and raises
   ``ScopeEscalationError`` when the child requests scopes the parent does not
   hold.  ``check_scope_escalation_blocked`` verifies this.

2. **Stale-parent revocation.**  ``jwt`` tracks revocation per-token-string
   (``_revoked`` set).  There is no parent-child link, so revoking one token
   never affects independently issued tokens.  Our plugin chains token IDs via
   ``parent_id`` and ``verify()`` walks the full ancestry; revoking the parent
   raises ``RevokedAncestorError`` on any descendant.
   ``check_stale_parent_blocked`` verifies this.

3. **Audience confusion.**  ``jwt.verify()`` takes only a ``token`` argument
   and returns ``AuthContext`` with no audience binding.  Any agent can verify
   any token.  Our plugin's ``verify(token, caller=agent_id)`` raises
   ``AudienceConfusionError`` when *caller* does not match the token's declared
   audience.  ``check_audience_confusion_blocked`` verifies this.

Against ``jwt``:
  * attack 1 — ``issue()`` with escalated scopes silently succeeds → FAIL.
  * attack 2 — revoking one token leaves independently issued tokens live → FAIL.
  * attack 3 — ``verify()`` does not accept ``caller``; ``TypeError`` is caught
    and mapped to FAIL (no audience binding).

Against ``delegatable``:
  * all three attacks raise the appropriate typed exception → PASS.

Each validator is a pure ``async`` function on the ``Auth`` protocol surface —
it only calls ``issue`` / ``verify`` / ``revoke`` (and ``delegate`` where the
method exists).  No internals are reached into.

Example::

    auth = DelegatableAuth(secret=b"s")
    root  = await auth.issue(AgentId("coord"), ["read", "write"])
    child = await auth.delegate(root, AgentId("worker"), ["read"], ttl=600.0)

    r1 = await check_scope_escalation_blocked(auth, root, ["admin"])
    assert r1.passed

    r2 = await check_stale_parent_blocked(auth, root, child)
    assert r2.passed

    r3 = await check_audience_confusion_blocked(auth, child, AgentId("intruder"))
    assert r3.passed
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from nest_plugins_reference.validators.gossip_validators import ValidatorReport

if TYPE_CHECKING:
    from nest_core.types import AgentId, Token


async def check_scope_escalation_blocked(
    auth: object,
    parent_token: Token,
    escalated_scopes: list[str],
) -> ValidatorReport:
    """Assert the plugin refuses a child token whose scopes exceed the parent's.

    Calls ``auth.delegate(parent_token, audience, escalated_scopes, ttl)`` and
    expects a ``ValueError`` (or subclass, e.g. ``ScopeEscalationError``).
    Returns ``passed=False`` if the call succeeds silently, which is what
    ``jwt`` (which has no ``delegate`` method) does when you simply call
    ``issue()`` with elevated scopes.

    Example::

        report = await check_scope_escalation_blocked(auth, root, ["admin"])
        assert report.passed, report.detail
    """
    from nest_core.types import AgentId as _AgentId

    _sentinel = _AgentId("escalation-sentinel")

    # For plugins without delegation (e.g. jwt), fall back to issue().
    delegate = getattr(auth, "delegate", None)
    if delegate is None:
        issue = getattr(auth, "issue", None)
        if issue is None:
            return ValidatorReport(passed=False, detail="plugin has no issue() method")
        try:
            await issue(_sentinel, escalated_scopes)
        except ValueError:
            return ValidatorReport(passed=True, detail="scope escalation blocked by issue()")
        return ValidatorReport(
            passed=False,
            detail=f"plugin issued token with escalated scopes {escalated_scopes!r} without error",
        )

    try:
        await delegate(parent_token, _sentinel, escalated_scopes, 60.0)
    except ValueError as exc:
        return ValidatorReport(
            passed=True,
            detail=f"scope escalation correctly blocked: {exc}",
        )
    return ValidatorReport(
        passed=False,
        detail=f"plugin delegated escalated scopes {escalated_scopes!r} without error",
    )


async def check_stale_parent_blocked(
    auth: object,
    parent_token: Token,
    child_token: Token,
) -> ValidatorReport:
    """Assert that revoking the parent makes the child unverifiable.

    Revokes *parent_token* then attempts to verify *child_token*.  Returns
    ``passed=True`` iff a ``ValueError`` (e.g. ``RevokedAncestorError``) is
    raised.  Against ``jwt``, revoking a token removes only that exact string
    from the revocation set; the child token (a different string) is unaffected
    → FAIL.

    Example::

        report = await check_stale_parent_blocked(auth, root, child)
        assert report.passed, report.detail
    """
    revoke = getattr(auth, "revoke", None)
    verify = getattr(auth, "verify", None)
    if revoke is None or verify is None:
        return ValidatorReport(passed=False, detail="plugin missing revoke() or verify()")

    await revoke(parent_token)
    try:
        await verify(child_token)
    except ValueError as exc:
        return ValidatorReport(
            passed=True,
            detail=f"stale-parent attack correctly blocked: {exc}",
        )
    return ValidatorReport(
        passed=False,
        detail="child token verified successfully after parent was revoked",
    )


async def check_audience_confusion_blocked(
    auth: object,
    child_token: Token,
    wrong_caller: AgentId,
) -> ValidatorReport:
    """Assert that presenting a token to the wrong caller is rejected.

    Calls ``auth.verify(child_token, caller=wrong_caller)``.  Returns
    ``passed=True`` iff a ``ValueError`` (e.g. ``AudienceConfusionError``) is
    raised.  Against ``jwt``, ``verify()`` does not accept a ``caller``
    keyword; a ``TypeError`` is caught and mapped to FAIL (no audience
    binding means the attack is not blocked).

    Example::

        report = await check_audience_confusion_blocked(auth, child, AgentId("intruder"))
        assert report.passed, report.detail
    """
    verify = getattr(auth, "verify", None)
    if verify is None:
        return ValidatorReport(passed=False, detail="plugin missing verify()")

    try:
        await verify(child_token, caller=wrong_caller)
    except TypeError:
        return ValidatorReport(
            passed=False,
            detail="plugin does not support caller binding (TypeError on verify)",
        )
    except ValueError as exc:
        return ValidatorReport(
            passed=True,
            detail=f"audience confusion correctly blocked: {exc}",
        )
    return ValidatorReport(
        passed=False,
        detail=f"token verified successfully for wrong caller {wrong_caller!r}",
    )
