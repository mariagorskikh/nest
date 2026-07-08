# SPDX-License-Identifier: Apache-2.0
"""Adversarial validators for the ``delegatable`` auth plugin.

Three attacks the default ``jwt_auth`` plugin silently allows — because it has
no delegation concept and no parent-child linking:

1. **Scope escalation.** A delegatee mints a child token with broader scopes than
   the parent holds.  ``check_no_scope_escalation`` asserts that ``delegate()``
   (or equivalent manual forging) produces a token whose scopes exceed the
   parent's, and that ``verify()`` rejects it.  Against ``jwt_auth`` there is no
   ``delegate()`` at all, so the check has no way to express a delegation — thus
   the ``jwt_auth`` path is trivially unable to pass this validator.

2. **Stale parent.** A child token whose parent was revoked still verifies.
   ``check_stale_parent_invalidates_child`` asserts that after revoking the
   parent, the child's verify fails.  Against ``jwt_auth`` there is no parent-
   child link so revoking the "parent" has no effect on the "child" — the
   validator fails.

3. **Audience confusion.** A token minted for audience ``B`` is presented by
   agent ``A``.  ``check_audience_enforced`` asserts that a presenter mismatch
   raises :class:`~nest_plugins_reference.auth.delegatable.AudienceMismatchError`.
   Against ``jwt_auth`` there is no audience field so any presenter is accepted.

Each validator is a pure ``async`` function on the ``DelegatableAuth`` plugin
surface — it performs only ``issue``/``delegate``/``verify``/``revoke`` calls.

Example::

    report = await check_no_scope_escalation(auth)
    assert report.passed, report.detail
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from nest_core.types import AgentId

from nest_plugins_reference.validators.gossip_validators import ValidatorReport

if TYPE_CHECKING:
    from nest_plugins_reference.auth.delegatable import DelegatableAuth


async def check_no_scope_escalation(auth: DelegatableAuth) -> ValidatorReport:
    """Assert a delegated token cannot hold scopes the parent does not have.

    Issues a root token with scopes ``["read"]``, then attempts to delegate
    with scopes ``["read", "write"]``.  Passes iff the delegation raises
    :class:`~nest_plugins_reference.auth.delegatable.ScopeEscalationError`.

    Against ``jwt_auth`` (no delegation) the validator cannot even invoke
    ``delegate()``, so it trivially fails the charter's adversarial bar.

    Example::

        report = await check_no_scope_escalation(auth)
        assert report.passed, report.detail
    """
    from nest_plugins_reference.auth.delegatable import ScopeEscalationError

    root = await auth.issue(AgentId("admin"), ["read"])
    try:
        await auth.delegate(
            root,
            audience=AgentId("worker"),
            scopes=["read", "write"],
            ttl=100,
        )
        return ValidatorReport(
            passed=False,
            detail="scope escalation: child got write despite parent only having read",
        )
    except ScopeEscalationError:
        return ValidatorReport(passed=True, detail="scope escalation correctly rejected")
    except Exception as exc:  # noqa: BLE001
        return ValidatorReport(
            passed=False,
            detail=f"scope check raised unexpected exception: {exc}",
        )


async def check_stale_parent_invalidates_child(auth: DelegatableAuth) -> ValidatorReport:
    """Assert revoking the parent token invalidates all descendants.

    Issues a root, delegates a child, verifies the child passes, revokes the
    root, then verifies the child fails with
    :class:`~nest_plugins_reference.auth.delegatable.RevokedAncestorError`.

    Against ``jwt_auth`` there is no parent-child relationship so the child
    continues to verify after the parent is revoked.

    Example::

        report = await check_stale_parent_invalidates_child(auth)
        assert report.passed, report.detail
    """
    from nest_plugins_reference.auth.delegatable import RevokedAncestorError

    root = await auth.issue(AgentId("admin"), ["read", "write"])
    try:
        child = await auth.delegate(
            root,
            audience=AgentId("worker"),
            scopes=["read"],
            ttl=100,
        )
    except AttributeError:
        return ValidatorReport(
            passed=False,
            detail="plugin does not support delegate() — stale-parent attack undefended",
        )
    except Exception as exc:  # noqa: BLE001
        return ValidatorReport(
            passed=False,
            detail=f"delegate() raised unexpected exception: {exc}",
        )

    # Child should verify before revocation
    try:
        await auth.verify(child, presenter=AgentId("worker"))
    except Exception as exc:  # noqa: BLE001
        return ValidatorReport(
            passed=False,
            detail=f"child token failed before revocation: {exc}",
        )

    # Revoke the root
    await auth.revoke(root)

    # Child must now fail
    try:
        await auth.verify(child, presenter=AgentId("worker"))
        return ValidatorReport(
            passed=False,
            detail="child token still verifies after parent revocation",
        )
    except RevokedAncestorError:
        return ValidatorReport(
            passed=True,
            detail="child token correctly rejected after parent revocation",
        )
    except Exception as exc:  # noqa: BLE001
        return ValidatorReport(
            passed=False,
            detail=f"post-revocation verify raised unexpected exception: {exc}",
        )


async def check_audience_enforced(auth: DelegatableAuth) -> ValidatorReport:
    """Assert a token presented by a non-audience agent is rejected.

    Issues a root, delegates a child with ``audience=AgentId("worker")``, then
    verifies the child with ``presenter=AgentId("eve")``.  Passes iff the
    verify raises
    :class:`~nest_plugins_reference.auth.delegatable.AudienceMismatchError`.

    Against ``jwt_auth`` there is no audience concept so any presenter passes.

    Example::

        report = await check_audience_enforced(auth)
        assert report.passed, report.detail
    """
    from nest_plugins_reference.auth.delegatable import AudienceMismatchError

    root = await auth.issue(AgentId("admin"), ["read"])
    try:
        child = await auth.delegate(
            root,
            audience=AgentId("worker"),
            scopes=["read"],
            ttl=100,
        )
    except AttributeError:
        return ValidatorReport(
            passed=False,
            detail="plugin does not support delegate() — audience confusion undefended",
        )
    except Exception as exc:  # noqa: BLE001
        return ValidatorReport(
            passed=False,
            detail=f"delegate() raised unexpected exception: {exc}",
        )

    try:
        await auth.verify(child, presenter=AgentId("eve"))
        return ValidatorReport(
            passed=False,
            detail="token accepted when presented by non-audience agent eve",
        )
    except AudienceMismatchError:
        return ValidatorReport(
            passed=True,
            detail="audience mismatch correctly rejected",
        )
    except Exception as exc:  # noqa: BLE001
        return ValidatorReport(
            passed=False,
            detail=f"audience check raised unexpected exception: {exc}",
        )
