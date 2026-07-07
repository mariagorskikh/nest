# SPDX-License-Identifier: Apache-2.0
"""Adversarial validators for delegatable capability tokens.

These run concrete attacks against an auth plugin and report whether it defended.
They are written to FAIL against the default ``jwt`` plugin, which has no notion of
delegation, and PASS against the ``macaroons`` plugin, which attenuates authority and
chains revocation. Each check treats "the plugin cannot even model this" as a failure,
because an auth layer that can't express delegation can't secure it.

Example::

    from nest_plugins_reference.auth.macaroons import MacaroonAuth
    report = await run_all_delegation_checks(MacaroonAuth(secret=b"k", clock=0.0))
    assert report.passed
"""

from __future__ import annotations

from typing import Any

from nest_core.types import AgentId

from nest_plugins_reference.validators.gossip_validators import ValidatorReport


async def check_scope_escalation_blocked(auth: Any) -> ValidatorReport:
    """A child must never gain a scope its parent does not hold.

    Example::

        report = await check_scope_escalation_blocked(auth)
    """
    root = await auth.issue(AgentId("root"), ["read", "write"])
    delegate = getattr(auth, "delegate", None)
    if delegate is None:
        return ValidatorReport(
            passed=False,
            detail="plugin has no delegate(); it cannot attenuate authority",
            evidence={"plugin": type(auth).__name__},
        )
    try:
        await delegate(root, AgentId("b"), ["read", "write", "admin"], 60)
    except Exception as exc:  # noqa: BLE001 - any refusal counts as a defense
        return ValidatorReport(
            passed=True,
            detail="scope escalation was refused",
            evidence={"error": type(exc).__name__},
        )
    return ValidatorReport(
        passed=False,
        detail="a child token gained a scope its parent never held",
        evidence={"plugin": type(auth).__name__},
    )


async def check_cascading_revocation_blocked(auth: Any) -> ValidatorReport:
    """Revoking a parent token must invalidate every descendant.

    Example::

        report = await check_cascading_revocation_blocked(auth)
    """
    root = await auth.issue(AgentId("root"), ["read", "write"])
    delegate = getattr(auth, "delegate", None)
    if delegate is None:
        # No delegation: emulate a parent and child as two independent tokens.
        # A plugin with no chain cannot link them, so the child survives.
        child = await auth.issue(AgentId("b"), ["read"])
        await auth.revoke(root)
        try:
            await auth.verify(child)
        except Exception as exc:  # noqa: BLE001
            return ValidatorReport(
                passed=True,
                detail="child died with the parent",
                evidence={"error": type(exc).__name__},
            )
        return ValidatorReport(
            passed=False,
            detail="revoking the parent left the child valid (no delegation link)",
            evidence={"plugin": type(auth).__name__},
        )
    child = await delegate(root, AgentId("b"), ["read"], 600)
    await auth.verify(child)  # valid before revocation
    await auth.revoke(root)
    try:
        await auth.verify(child)
    except Exception as exc:  # noqa: BLE001
        return ValidatorReport(
            passed=True,
            detail="revoking the parent invalidated the child",
            evidence={"error": type(exc).__name__},
        )
    return ValidatorReport(
        passed=False,
        detail="child still verified after its parent was revoked",
        evidence={"plugin": type(auth).__name__},
    )


async def check_audience_confusion_blocked(auth: Any) -> ValidatorReport:
    """A token must be rejected when a different agent than its audience presents it.

    Example::

        report = await check_audience_confusion_blocked(auth)
    """
    verify_for = getattr(auth, "verify_for", None)
    if verify_for is None:
        return ValidatorReport(
            passed=False,
            detail="plugin has no audience-bound verification",
            evidence={"plugin": type(auth).__name__},
        )
    root = await auth.issue(AgentId("root"), ["read"])
    delegate = getattr(auth, "delegate", None)
    token = await delegate(root, AgentId("b"), ["read"], 60) if delegate is not None else root
    try:
        await verify_for(token, AgentId("attacker"))
    except Exception as exc:  # noqa: BLE001
        return ValidatorReport(
            passed=True,
            detail="token rejected when presented by the wrong audience",
            evidence={"error": type(exc).__name__},
        )
    return ValidatorReport(
        passed=False,
        detail="token accepted from an agent that is not its audience",
        evidence={"plugin": type(auth).__name__},
    )


async def check_ttl_extension_blocked(auth: Any) -> ValidatorReport:
    """A child token must not be allowed to outlive its parent.

    Example::

        report = await check_ttl_extension_blocked(auth)
    """
    delegate = getattr(auth, "delegate", None)
    if delegate is None:
        return ValidatorReport(
            passed=False,
            detail="plugin has no delegate(); it cannot bound a child's lifetime",
            evidence={"plugin": type(auth).__name__},
        )
    root = await auth.issue(AgentId("root"), ["read"])
    try:
        await delegate(root, AgentId("b"), ["read"], 10**9)
    except Exception as exc:  # noqa: BLE001
        return ValidatorReport(
            passed=True,
            detail="child forbidden from outliving its parent",
            evidence={"error": type(exc).__name__},
        )
    return ValidatorReport(
        passed=False,
        detail="child was allowed to outlive its parent",
        evidence={"plugin": type(auth).__name__},
    )


async def run_all_delegation_checks(auth: Any) -> ValidatorReport:
    """Run every delegation attack; pass only if the plugin defended against all.

    Example::

        report = await run_all_delegation_checks(auth)
        assert report.passed
    """
    reports = [
        await check_scope_escalation_blocked(auth),
        await check_cascading_revocation_blocked(auth),
        await check_audience_confusion_blocked(auth),
        await check_ttl_extension_blocked(auth),
    ]
    failed = [r for r in reports if not r.passed]
    if failed:
        return ValidatorReport(
            passed=False,
            detail=f"{len(failed)} of {len(reports)} delegation checks failed",
            evidence={"failures": [r.detail for r in failed]},
        )
    return ValidatorReport(
        passed=True,
        detail=f"all {len(reports)} delegation checks passed",
        evidence={},
    )
