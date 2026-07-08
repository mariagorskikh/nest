# SPDX-License-Identifier: Apache-2.0
"""Validators for delegatable capability-token auth scenarios."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from nest_plugins_reference.auth.delegatable import CapabilityError, DelegatableAuth


@dataclass(slots=True)
class AuthDelegationReport:
    """Pass/fail report for capability delegation scenario checks."""

    passed: bool
    detail: str
    evidence: dict[str, object] = field(default_factory=dict[str, object])


@dataclass(slots=True)
class DelegationEvent:
    kind: str
    token: str
    subject: str | None = None
    audience: str | None = None
    scopes: set[str] = field(default_factory=set[str])
    ttl_seconds: float | None = None
    expect: str = "ok"


class CapabilityDelegationValidator:
    """Exercise Problem 04 invariants against an auth plugin instance."""

    def __init__(self, auth: DelegatableAuth | None = None) -> None:
        self.auth = auth or DelegatableAuth()

    def validate_events(self, events: list[dict[str, Any]]) -> AuthDelegationReport:
        aliases: dict[str, str] = {}
        findings: list[str] = []
        for index, raw in enumerate(events):
            try:
                ttl_seconds = raw.get("ttl_seconds")
                event = DelegationEvent(
                    kind=str(raw["kind"]),
                    token=str(raw["token"]),
                    subject=None if raw.get("subject") is None else str(raw["subject"]),
                    audience=None if raw.get("audience") is None else str(raw["audience"]),
                    scopes={str(scope) for scope in raw.get("scopes", [])},
                    ttl_seconds=None if ttl_seconds is None else float(ttl_seconds),
                    expect=str(raw.get("expect", "ok")),
                )
                self._apply(event, aliases)
                if event.expect != "ok":
                    findings.append(
                        self._finding(index, event.expect, "operation unexpectedly succeeded")
                    )
            except (CapabilityError, KeyError, TypeError, ValueError) as exc:
                expected = str(raw.get("expect", "ok"))
                if expected == "ok":
                    findings.append(self._finding(index, "ok", str(exc)))
                elif expected not in str(exc):
                    findings.append(self._finding(index, expected, str(exc)))
        detail = "capability delegation invariants passed" if not findings else "; ".join(findings)
        return AuthDelegationReport(
            passed=not findings,
            detail=detail,
            evidence={"events": len(events), "findings": findings},
        )

    def _apply(self, event: DelegationEvent, aliases: dict[str, str]) -> None:
        if event.kind == "root":
            if event.subject is None or event.audience is None or not event.scopes:
                raise CapabilityError("root requires subject, audience, and scopes")
            aliases[event.token] = self.auth.issue_root(
                subject=event.subject,
                audience=event.audience,
                scopes=event.scopes,
                ttl_seconds=event.ttl_seconds or 3600.0,
                max_depth=2,
                now=1000.0,
            )
            return
        parent = aliases[event.token]
        if event.kind == "delegate":
            if event.subject is None:
                raise CapabilityError("delegate requires subject")
            child = self.auth.delegate(
                parent,
                subject=event.subject,
                audience=event.audience,
                scopes=event.scopes or None,
                ttl_seconds=event.ttl_seconds,
                now=1001.0,
            )
            aliases[str(event.subject)] = child
            return
        if event.kind == "verify":
            self.auth.verify_capability(
                parent,
                audience=event.audience,
                required_scopes=event.scopes,
                now=1002.0,
            )
            return
        if event.kind == "revoke":
            self.auth.revoke_tree(parent)
            return
        raise CapabilityError(f"unknown event kind: {event.kind}")

    def _finding(self, index: int, expected: str, actual: str) -> str:
        return f"event {index} expected {expected!r}, got {actual!r}"
