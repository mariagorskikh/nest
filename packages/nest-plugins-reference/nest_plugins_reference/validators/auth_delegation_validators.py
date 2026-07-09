# SPDX-License-Identifier: Apache-2.0
"""Adversarial validators for capability-delegation auth plugins.

Three attacks the default ``jwt`` plugin
(``nest_plugins_reference.auth.jwt_auth.JwtAuth``) has no defense against,
because it has no concept of a parent-child relationship between tokens at
all -- "delegation" on top of it can only mean calling ``issue`` again,
which is exactly the re-issuance-by-authority anti-pattern the
``04-auth-capability-delegation`` problem doc warns against:

1. **Scope escalation.** A child token claims broader scopes than whatever
   it was "delegated" from. ``jwt``'s ``issue`` takes any scope list from
   any caller -- there is no parent to compare against, so nothing can be
   escalated *past*, but nothing is enforced *either*.
   ``check_scope_escalation_rejected`` drives an attempted mint of an
   over-scoped child and asserts the attempt is refused, either at mint
   time or at verification time.
2. **Stale parent.** A parent token is revoked (or expired) after a child
   was minted from it, and the child still verifies. ``jwt``'s
   ``_revoked: set[str]`` is keyed by exact token string with no chain, so
   revoking a "parent" token never touches an independently-issued "child"
   token. ``check_stale_parent_rejected`` revokes the parent *after* the
   child already exists and asserts the child stops verifying.
3. **Audience confusion.** A token minted for one agent is presented (and
   accepted) by a different agent. ``jwt``'s ``verify`` takes only the
   token -- there is no audience field and no presenter argument, so any
   holder of any token can present it as anyone.
   ``check_audience_confusion_rejected`` presents a token as the wrong
   agent and asserts it is refused.

Each validator is deliberately **plugin-agnostic**: it takes async
callables the caller constructs however that plugin exposes the relevant
operation, and only inspects the *outcome* (did the attack succeed or was
it blocked). That is what lets the exact same validator function run
against two structurally different plugins and produce the charter's
required differential result:

* against ``nest_plugins_reference.auth.delegatable.DelegatableAuth``,
  wired through its real ``delegate`` / ``verify`` /
  ``verify_presented_by`` surface, all three checks **pass** -- every
  attack is rejected with a typed exception
  (``ScopeEscalationError`` / ``RevokedAncestorError`` /
  ``AudienceMismatchError``);
* against ``JwtAuth``, wired through the only surface it has (``issue`` /
  ``verify``, with no parent-aware delegation at all), all three checks
  **fail** -- the validators literally cannot be satisfied by the
  reference plugin, which is the charter's bar for "adversarial". See
  ``packages/nest-plugins-reference/tests/test_delegatable_auth.py`` for
  the differential proof wired against both plugins side by side.

Example::

    report = await check_scope_escalation_rejected(
        attempt_mint=lambda: auth.delegate(parent, audience, ["read", "admin"], ttl=60.0),
        verify=auth.verify,
    )
    assert report.passed, report.detail
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING

from nest_plugins_reference.validators.gossip_validators import ValidatorReport

if TYPE_CHECKING:
    from nest_core.types import AgentId, AuthContext, Token


async def check_scope_escalation_rejected(
    attempt_mint: Callable[[], Awaitable[Token]],
    *,
    verify: Callable[[Token], Awaitable[AuthContext]] | None = None,
) -> ValidatorReport:
    """Assert an attempt to mint an over-scoped child token does not succeed.

    Calls *attempt_mint* (the caller's plugin-specific way of trying to
    obtain a token with escalated scopes) and treats any exception as the
    attack being rejected at mint time. If minting does not raise and
    *verify* is supplied, the resulting token is also verified -- a plugin
    that mints an escalated token but then refuses to verify it still
    counts as rejecting the attack. Only a token that is both minted *and*
    verified counts as a successful escalation.

    Against ``DelegatableAuth.delegate``, an over-scoped request raises
    ``ScopeEscalationError`` immediately. Against ``JwtAuth.issue`` (the
    only "delegation" surface it has), the call has no parent to compare
    against and always succeeds -- so does the subsequent verify -- and the
    attack goes through uncaught.

    Example::

        report = await check_scope_escalation_rejected(
            attempt_mint=lambda: auth.delegate(parent, aud, ["read", "admin"], ttl=60.0),
            verify=auth.verify,
        )
        assert report.passed, report.detail
    """
    try:
        token = await attempt_mint()
    except Exception as exc:  # noqa: BLE001 - any failure is a rejected attack
        return ValidatorReport(
            passed=True, detail=f"escalated scope request rejected at mint time ({exc})"
        )
    if verify is None:
        return ValidatorReport(
            passed=False,
            detail="escalated token was minted without error and no verify step was supplied",
            evidence={"token": str(token)},
        )
    try:
        ctx = await verify(token)
    except Exception as exc:  # noqa: BLE001 - any failure is a rejected attack
        return ValidatorReport(passed=True, detail=f"escalated token failed verification ({exc})")
    return ValidatorReport(
        passed=False,
        detail=f"escalated token verified successfully with scopes {ctx.scopes}",
        evidence={"scopes": ctx.scopes},
    )


async def check_stale_parent_rejected(
    child_token: Token,
    revoke_parent: Callable[[], Awaitable[None]],
    verify: Callable[[Token], Awaitable[AuthContext]],
) -> ValidatorReport:
    """Assert a child token stops verifying once its parent is revoked.

    *child_token* must already exist (legitimately minted while its parent
    was still valid). *revoke_parent* is called first -- exercising the
    revocation *after* the fact, the realistic ordering -- then *verify* is
    attempted on the child. Any exception counts as the attack being
    rejected.

    Against ``DelegatableAuth``, the chain walk in ``verify`` finds the
    revoked ancestor and raises ``RevokedAncestorError``. Against ``JwtAuth``,
    a "child" token has no structural link to its "parent" (there is no
    chain to walk), so revoking the parent token's own string never touches
    the child's, and the child keeps verifying.

    Example::

        report = await check_stale_parent_rejected(
            child_token, revoke_parent=lambda: auth.revoke(parent), verify=auth.verify
        )
        assert report.passed, report.detail
    """
    await revoke_parent()
    try:
        ctx = await verify(child_token)
    except Exception as exc:  # noqa: BLE001 - any failure is a rejected attack
        return ValidatorReport(
            passed=True, detail=f"child rejected after parent was revoked ({exc})"
        )
    return ValidatorReport(
        passed=False,
        detail=f"child verified after its parent was revoked (subject={ctx.subject})",
        evidence={"subject": str(ctx.subject)},
    )


async def check_audience_confusion_rejected(
    present: Callable[[AgentId], Awaitable[AuthContext]],
    wrong_presenter: AgentId,
) -> ValidatorReport:
    """Assert a token is refused when presented by an agent other than its audience.

    *present* is the caller's plugin-specific way of "presenting" a token
    as a given agent (e.g. ``lambda presenter: auth.verify_presented_by(token, presenter)``).
    It is called with *wrong_presenter*, an agent that is not the token's
    declared audience. Any exception counts as the attack being rejected.

    Against ``DelegatableAuth.verify_presented_by``, the audience check
    raises ``AudienceMismatchError``. Against ``JwtAuth.verify``, there is no
    audience field and no presenter argument at all -- the caller's
    ``present`` callable can only ignore *wrong_presenter* and verify the
    bare token, which always succeeds regardless of who "presents" it.

    Example::

        report = await check_audience_confusion_rejected(
            present=lambda p: auth.verify_presented_by(token, p),
            wrong_presenter=AgentId("attacker"),
        )
        assert report.passed, report.detail
    """
    try:
        ctx = await present(wrong_presenter)
    except Exception as exc:  # noqa: BLE001 - any failure is a rejected attack
        return ValidatorReport(
            passed=True, detail=f"presentation by non-audience agent rejected ({exc})"
        )
    return ValidatorReport(
        passed=False,
        detail=(f"token presented by {wrong_presenter!r} verified anyway (subject={ctx.subject})"),
        evidence={"presenter": str(wrong_presenter), "subject": str(ctx.subject)},
    )
