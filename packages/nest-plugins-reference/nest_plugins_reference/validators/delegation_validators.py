# SPDX-License-Identifier: Apache-2.0
"""Adversarial validators for the delegatable capability-token auth plugin.

Three attacks the default ``jwt`` plugin (no delegation concept at all)
trivially permits, because it has nothing to check against:

1. **Scope escalation.** A "child" token claims broader scopes than any
   token it was supposedly derived from. ``check_no_scope_escalation``
   compares the delegator's own scopes against what it handed out.
2. **Stale parent.** A token derived from an already-revoked or expired
   parent still verifies. ``check_no_stale_parent_use`` re-verifies every
   delegated token *after* its declared parent's revocation/expiry point
   and asserts it fails.
3. **Audience confusion.** A token minted for one agent is accepted when
   presented by a different agent. ``check_audience_enforced`` presents
   each token to a non-holder and asserts it is rejected.

Against ``jwt``, all three trivially pass the *attack* (i.e. the checks
below report ``passed=False``) because ``jwt`` has no ``delegate``, no
chain, and no audience concept — any token verifies for anyone, forever,
until its flat expiry. Against ``delegatable``, all three attacks are
caught by construction (the checks report ``passed=True``), which is the
charter's bar for "adversarial": the reference plugin cannot satisfy it.

Example::

    report = await check_no_stale_parent_use(auth, root, [child, grandchild])
    assert report.passed, report.detail
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, cast

from nest_plugins_reference.validators.gossip_validators import ValidatorReport

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from nest_core.types import AgentId, Token


class _DelegatingAuth(Protocol):
    """The base :class:`~nest_core.layers.auth.Auth` surface every plugin has.

    Deliberately does *not* require ``delegate``/``verify_with_audience`` —
    those are new API the base ``jwt`` plugin lacks entirely, and lacking
    them is precisely the vulnerability these validators demonstrate.
    Checks that need them fetch and call them dynamically via
    :func:`_extension_method`, so a plugin without them fails honestly at
    the call site instead of being rejected by the type checker before the
    adversarial comparison can even run.

    Example::

        async def run(auth: _DelegatingAuth) -> None:
            token = await auth.issue(AgentId("a1"), ["read"])
    """

    async def issue(self, subject: AgentId, scopes: list[str]) -> Token:
        """Issue a token for a subject with given scopes.

        Example::

            token = await auth.issue(AgentId("a1"), ["read"])
        """
        ...

    async def verify(self, token: Token) -> object:
        """Verify a token and return its auth context.

        Example::

            ctx = await auth.verify(token)
        """
        ...

    async def revoke(self, token: Token) -> None:
        """Revoke a previously issued token.

        Example::

            await auth.revoke(token)
        """
        ...


def _extension_method(auth: _DelegatingAuth, name: str) -> Callable[..., Awaitable[object]]:
    """Look up an optional method (``delegate``, ``verify_with_audience``) by name.

    Raises :class:`AttributeError` if ``auth`` doesn't have it — callers
    catch that as the honest "this plugin cannot even attempt the defense"
    outcome, rather than the type checker silently assuming every plugin
    implements the full extended surface.

    Example::

        delegate = _extension_method(auth, "delegate")
        child = await delegate(parent, audience, scopes, ttl=60.0)
    """
    method = getattr(auth, name, None)
    if method is None or not callable(method):
        msg = f"{type(auth).__name__!r} has no {name}()"
        raise AttributeError(msg)
    return cast("Callable[..., Awaitable[object]]", method)


async def check_no_scope_escalation(
    auth: _DelegatingAuth,
    delegator: AgentId,
    delegator_scopes: list[str],
    audience: AgentId,
    requested_scopes: list[str],
) -> ValidatorReport:
    """Assert that delegating a broader scope set than the delegator holds is rejected.

    Issues a token for ``delegator`` with ``delegator_scopes``, then attempts
    to delegate ``requested_scopes`` to ``audience``. ``passed=True`` iff the
    plugin refuses the delegation whenever ``requested_scopes`` is not a
    subset of ``delegator_scopes`` — including trivially passing when the
    request *is* a valid subset (nothing to reject).

    Example::

        report = await check_no_scope_escalation(
            auth, AgentId("a1"), ["read"], AgentId("a2"), ["read", "admin"]
        )
        assert report.passed
    """
    is_escalation = not set(requested_scopes) <= set(delegator_scopes)
    parent = await auth.issue(delegator, delegator_scopes)
    try:
        delegate = _extension_method(auth, "delegate")
        await delegate(parent, audience, requested_scopes, ttl=60.0)
    except AttributeError:
        return ValidatorReport(
            passed=False,
            detail="plugin has no delegate() — cannot express, let alone enforce, a scope subset",
        )
    except ValueError as exc:
        if is_escalation:
            return ValidatorReport(passed=True, detail=f"escalation correctly rejected: {exc}")
        return ValidatorReport(
            passed=False,
            detail=f"valid subset delegation was wrongly rejected: {exc}",
            evidence={"delegator_scopes": delegator_scopes, "requested": requested_scopes},
        )
    if is_escalation:
        return ValidatorReport(
            passed=False,
            detail="escalated delegation was accepted without error",
            evidence={"delegator_scopes": delegator_scopes, "requested": requested_scopes},
        )
    return ValidatorReport(passed=True, detail="valid subset delegation correctly accepted")


async def check_no_stale_parent_use(
    auth: _DelegatingAuth,
    root: Token,
    descendants: list[Token],
) -> ValidatorReport:
    """Assert every descendant of a revoked token fails to verify afterward.

    Revokes ``root`` and then calls ``verify`` on each token in
    ``descendants`` (expected to have been delegated, directly or
    transitively, from ``root`` *before* the revocation). ``passed=True``
    iff every descendant now raises on verify; any descendant that still
    verifies is the stale-parent bug this check exists to catch.

    Example::

        report = await check_no_stale_parent_use(auth, root, [child, grandchild])
        assert report.passed
    """
    await auth.revoke(root)
    still_valid: list[int] = []
    for i, token in enumerate(descendants):
        try:
            await auth.verify(token)
        except ValueError:
            continue
        still_valid.append(i)
    if still_valid:
        return ValidatorReport(
            passed=False,
            detail=f"{len(still_valid)} of {len(descendants)} descendants still verify"
            " after parent revocation",
            evidence={"stale_indices": still_valid},
        )
    return ValidatorReport(
        passed=True, detail=f"all {len(descendants)} descendants correctly rejected"
    )


async def check_audience_enforced(
    auth: _DelegatingAuth,
    token: Token,
    declared_holder: AgentId,
    impersonator: AgentId,
) -> ValidatorReport:
    """Assert a token presented by a non-holder agent is rejected.

    Calls ``verify_with_audience(token, impersonator)`` where ``impersonator
    != declared_holder`` and asserts it raises. Plugins with no audience
    concept (e.g. the default ``jwt``, which has no such method at all) are
    reported as failing this check via ``AttributeError`` capture, which is
    the honest "cannot even attempt audience enforcement" outcome.

    Example::

        report = await check_audience_enforced(auth, child, AgentId("a2"), AgentId("attacker"))
        assert report.passed
    """
    try:
        verify_with_audience = _extension_method(auth, "verify_with_audience")
        await verify_with_audience(token, impersonator)
    except AttributeError:
        return ValidatorReport(
            passed=False,
            detail="plugin has no verify_with_audience — audience is not enforced at all",
        )
    except ValueError as exc:
        return ValidatorReport(passed=True, detail=f"impersonation correctly rejected: {exc}")
    return ValidatorReport(
        passed=False,
        detail=f"token for {declared_holder!r} was accepted from impersonator {impersonator!r}",
    )
