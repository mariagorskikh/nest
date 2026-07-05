# SPDX-License-Identifier: Apache-2.0
"""Adversarial validators for capability delegation in the auth layer.

Three attacks the default ``jwt`` plugin structurally cannot stop, because
its only delegation story is *re-issuance by the central issuer* (the
anti-pattern the problem brief names) and its revocation is a flat
per-token-string set:

1. **Scope escalation.** A delegate obtains a "child" token with scopes its
   parent never held. Under naive JWT re-issuance nothing relates the child
   to the parent, so ``issue(audience, broader_scopes)`` simply succeeds.
   ``probe_scope_escalation`` passes only when the escalated mint (or its
   subsequent verification) is rejected.
2. **Stale parent.** The parent token is revoked, but the child keeps
   verifying. Under naive JWT the child is an independent token — revoking
   the parent string cannot touch it. ``probe_stale_parent`` passes only
   when the child fails to verify after the parent's revocation.
3. **Audience confusion.** A token delegated to agent B is presented by
   agent C and accepted. Plain JWT carries no audience binding at all.
   ``probe_audience_confusion`` passes only when presentation by a
   non-audience agent is rejected.

Each probe is a pure async function over an ``Auth`` implementation plus two
small adapter callables, so the *same* probe runs against both plugins:

* against ``DelegatableAuth`` (adapters: real ``delegate`` /
  presenter-aware ``verify``) — all three probes **pass**;
* against ``JwtAuth`` (adapters: :func:`naive_jwt_delegate` /
  presenter-blind verify) — all three probes **fail**, which is the
  charter's bar for "adversarial": the reference plugin literally cannot
  satisfy the validator.

A fourth, trace-level validator (:func:`validate_delegated_auth_trace`)
replays a ``delegated_auth`` scenario trace and asserts every attack
attempt was denied and every honest use (before its ancestor's revocation)
was allowed.

Example::

    report = await probe_stale_parent(auth, delegate_fn, verify_fn)
    assert report.passed, report.detail
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from nest_core.types import AgentId, AuthContext, Token

DelegateFn = Callable[[Any, Token, AgentId, list[str], float], Awaitable[Token]]
VerifyFn = Callable[[Any, Token, AgentId | None], Awaitable[AuthContext]]


@dataclass
class ValidatorReport:
    """Pass/fail report with a short human-readable explanation.

    Example::

        report = ValidatorReport(passed=True, detail="escalation rejected")
        assert report.passed, report.detail
    """

    passed: bool
    detail: str
    evidence: dict[str, object] = field(default_factory=dict[str, object])


async def naive_jwt_delegate(
    auth: Any,
    parent_token: Token,
    audience: AgentId,
    scopes: list[str],
    ttl: float,
) -> Token:
    """The anti-pattern baseline: "delegate" by central re-issuance.

    This is what teams actually do with a flat JWT plugin: the parent asks
    the issuer for a brand-new token in the delegate's name. The result has
    no cryptographic relationship to the parent — which is exactly why the
    stale-parent and escalation probes fail against it. Kept here so the
    probes have a faithful ``jwt`` adapter and the failure is demonstrated,
    not asserted.

    Example::

        child = await naive_jwt_delegate(jwt_auth, parent, AgentId("b"), ["read"], 600)
    """
    del parent_token, ttl  # nothing ties the child to either — the flaw itself
    return await auth.issue(audience, scopes)


async def delegatable_delegate(
    auth: Any,
    parent_token: Token,
    audience: AgentId,
    scopes: list[str],
    ttl: float,
) -> Token:
    """Adapter for plugins with a real ``delegate`` API.

    Example::

        child = await delegatable_delegate(auth, parent, AgentId("b"), ["read"], 600)
    """
    return await auth.delegate(parent_token, audience, scopes, ttl)


async def presenter_verify(auth: Any, token: Token, presenter: AgentId | None) -> AuthContext:
    """Adapter for presenter-aware ``verify`` implementations.

    Example::

        ctx = await presenter_verify(auth, token, AgentId("worker-1"))
    """
    return await auth.verify(token, presenter=presenter)


async def blind_verify(auth: Any, token: Token, presenter: AgentId | None) -> AuthContext:
    """Adapter for presenter-blind ``verify`` implementations (plain jwt).

    Example::

        ctx = await blind_verify(jwt_auth, token, AgentId("ignored"))
    """
    del presenter  # jwt cannot bind audiences — the flaw the probe exposes
    return await auth.verify(token)


async def probe_scope_escalation(
    auth: Any,
    delegate_fn: DelegateFn,
    verify_fn: VerifyFn,
) -> ValidatorReport:
    """Attack 1: mint a child with scopes the parent does not hold.

    Passes iff the escalated mint raises, or the minted child fails
    verification, or the verified context does not actually carry the
    escalated scope.

    Example::

        report = await probe_scope_escalation(auth, delegatable_delegate, presenter_verify)
        assert report.passed
    """
    parent = await auth.issue(AgentId("val-parent"), ["read"])
    try:
        child = await delegate_fn(auth, parent, AgentId("val-child"), ["read", "write"], 60.0)
    except ValueError as exc:
        return ValidatorReport(passed=True, detail=f"escalated mint rejected: {exc}")
    try:
        ctx = await verify_fn(auth, child, AgentId("val-child"))
    except ValueError as exc:
        return ValidatorReport(passed=True, detail=f"escalated child rejected at verify: {exc}")
    if "write" in ctx.scopes:
        return ValidatorReport(
            passed=False,
            detail="child holds scope 'write' its parent never had",
            evidence={"child_scopes": list(ctx.scopes)},
        )
    return ValidatorReport(passed=True, detail="escalated scope silently dropped")


async def probe_stale_parent(
    auth: Any,
    delegate_fn: DelegateFn,
    verify_fn: VerifyFn,
) -> ValidatorReport:
    """Attack 2: revoke the parent, then present the child.

    Passes iff the child fails verification after the parent's revocation
    (cascading revocation). Fails when the child still verifies — the flat
    per-token revocation set of plain jwt.

    Example::

        report = await probe_stale_parent(auth, delegatable_delegate, presenter_verify)
        assert report.passed
    """
    parent = await auth.issue(AgentId("val-parent"), ["read", "write"])
    child = await delegate_fn(auth, parent, AgentId("val-child"), ["read"], 60.0)
    await auth.revoke(parent)
    try:
        await verify_fn(auth, child, AgentId("val-child"))
    except ValueError as exc:
        return ValidatorReport(passed=True, detail=f"stale child rejected: {exc}")
    return ValidatorReport(
        passed=False,
        detail="child still verifies after its parent was revoked",
    )


async def probe_audience_confusion(
    auth: Any,
    delegate_fn: DelegateFn,
    verify_fn: VerifyFn,
) -> ValidatorReport:
    """Attack 3: present a token delegated to B as agent C.

    Passes iff presentation by a non-audience agent is rejected.

    Example::

        report = await probe_audience_confusion(auth, delegatable_delegate, presenter_verify)
        assert report.passed
    """
    parent = await auth.issue(AgentId("val-parent"), ["read"])
    child = await delegate_fn(auth, parent, AgentId("val-child-b"), ["read"], 60.0)
    try:
        await verify_fn(auth, child, AgentId("val-child-c"))
    except ValueError as exc:
        return ValidatorReport(passed=True, detail=f"confused presenter rejected: {exc}")
    return ValidatorReport(
        passed=False,
        detail="token bound to val-child-b accepted from val-child-c",
    )


async def run_all_probes(
    auth: Any,
    delegate_fn: DelegateFn,
    verify_fn: VerifyFn,
) -> list[ValidatorReport]:
    """Run all three attack probes against one auth implementation.

    Example::

        reports = await run_all_probes(auth, delegatable_delegate, presenter_verify)
        assert all(r.passed for r in reports)
    """
    return [
        await probe_scope_escalation(auth, delegate_fn, verify_fn),
        await probe_stale_parent(auth, delegate_fn, verify_fn),
        await probe_audience_confusion(auth, delegate_fn, verify_fn),
    ]


def validate_delegated_auth_trace(trace_path: str | Path) -> list[ValidatorReport]:
    """Replay a ``delegated_auth`` scenario trace and check its verdicts.

    The scenario's gatekeeper emits one line per capability presentation::

        cap:<presenter>:<expected>:<outcome>

    where ``expected`` is ``ok`` (honest use), ``escalate``, ``stale`` or
    ``confused`` (attacks), and ``outcome`` is ``allow`` or ``deny``.

    Checks, each reported separately:

    1. *No attack admitted*: every line with ``expected != ok`` has
       ``outcome == deny``.
    2. *No honest use denied*: every line with ``expected == ok`` has
       ``outcome == allow``.
    3. *Coverage*: at least one line per attack class is present (a
       scenario that never attacks proves nothing).

    Example::

        reports = validate_delegated_auth_trace("./traces/delegated_auth.jsonl")
        assert all(r.passed for r in reports)
    """
    admitted: list[str] = []
    denied_honest: list[str] = []
    seen: set[str] = set()
    with Path(trace_path).open() as f:
        for line in f:
            rec = json.loads(line)
            msg = rec.get("msg", "")
            if rec.get("kind") != "send" or not msg.startswith("cap:"):
                continue
            parts = msg.split(":")
            if len(parts) != 4:
                continue
            _tag, _presenter, expected, outcome = parts
            seen.add(expected)
            if expected != "ok" and outcome == "allow":
                admitted.append(msg)
            if expected == "ok" and outcome == "deny":
                denied_honest.append(msg)

    reports = [
        ValidatorReport(
            passed=not admitted,
            detail=(
                "no attack admitted"
                if not admitted
                else f"{len(admitted)} attack presentations were allowed"
            ),
            evidence={"admitted": admitted[:20]},
        ),
        ValidatorReport(
            passed=not denied_honest,
            detail=(
                "no honest use denied"
                if not denied_honest
                else f"{len(denied_honest)} honest presentations were denied"
            ),
            evidence={"denied_honest": denied_honest[:20]},
        ),
    ]
    required = {"ok", "escalate", "stale", "confused"}
    missing = sorted(required - seen)
    reports.append(
        ValidatorReport(
            passed=not missing,
            detail=(
                "all attack classes exercised"
                if not missing
                else f"missing attack classes in trace: {missing}"
            ),
            evidence={"seen": sorted(seen)},
        )
    )
    return reports
