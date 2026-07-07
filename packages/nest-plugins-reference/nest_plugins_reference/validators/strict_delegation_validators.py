# SPDX-License-Identifier: Apache-2.0
"""Adversarial validators for strict delegated auth capability tokens.

The default ``jwt`` auth plugin can issue and revoke bearer tokens, but it
cannot model parent-issued child capabilities.  These validators check the
three attacks from the hackathon auth brief: scope escalation, stale parent,
and audience confusion. They also probe a delegated-token forgery shape that
would pass if an implementation reused the public parent signature directly
as a child-token HMAC key.

Example::

    report = await check_strict_delegated_auth_attack_suite(auth)
    assert report.passed, report.detail
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any, Protocol, cast

from nest_core.types import AgentId, AuthContext, Token

from nest_plugins_reference.validators.gossip_validators import ValidatorReport

_TOKEN_SIGN_DOMAIN = b"nest.delegatable-strict.token.v1|"


class _StrictDelegatedAuthLike(Protocol):
    async def issue(self, subject: AgentId, scopes: list[str]) -> Token: ...

    async def delegate(
        self,
        parent_token: Token,
        audience: AgentId,
        scopes_subset: list[str],
        ttl: float,
    ) -> Token: ...

    async def verify(self, token: Token) -> AuthContext: ...

    async def verify_for(self, token: Token, presenter: AgentId) -> AuthContext: ...

    async def revoke(self, token: Token) -> None: ...


async def check_strict_delegated_auth_attack_suite(auth: object) -> ValidatorReport:
    """Run the strict delegated-auth adversarial suite against ``auth``.

    Returns ``passed=True`` only if all attacks are blocked:

    * child scope escalation beyond the parent;
    * child verification after the parent is revoked;
    * presentation by an agent outside the child token's audience.
    * signature/key-confusion forgery against the delegated-token format.

    Example::

        report = await check_strict_delegated_auth_attack_suite(
            StrictDelegatableAuth()
        )
        assert report.passed
    """
    if not all(hasattr(auth, attr) for attr in ("issue", "delegate", "verify", "verify_for")):
        return ValidatorReport(
            passed=False,
            detail="auth plugin does not expose delegate/verify_for capability checks",
            evidence={"missing_api": True},
        )

    typed_auth = cast("_StrictDelegatedAuthLike", auth)
    issue = typed_auth.issue
    delegate = typed_auth.delegate
    verify = typed_auth.verify
    verify_for = typed_auth.verify_for
    failures: list[str] = []
    rejections: dict[str, str] = {}

    parent = await issue(AgentId("coordinator"), ["orders:read", "orders:write"])
    try:
        await delegate(parent, AgentId("worker-escalate"), ["orders:read", "admin"], 60.0)
    except Exception as exc:
        rejections["scope_escalation"] = type(exc).__name__
    else:
        failures.append("scope_escalation_allowed")

    stale_parent = await issue(AgentId("coordinator-stale"), ["docs:read", "docs:write"])
    child = await delegate(stale_parent, AgentId("worker-stale"), ["docs:read"], 60.0)
    revoke = typed_auth.revoke
    await revoke(stale_parent)
    try:
        await verify(child)
    except Exception as exc:
        rejections["stale_parent"] = type(exc).__name__
    else:
        failures.append("revoked_parent_child_verified")

    audience_parent = await issue(AgentId("coordinator-audience"), ["files:read", "files:write"])
    audience_child = await delegate(audience_parent, AgentId("worker-a"), ["files:read"], 60.0)
    try:
        await verify_for(Token(str(audience_child)), AgentId("worker-b"))
    except Exception as exc:
        rejections["audience_confusion"] = type(exc).__name__
    else:
        failures.append("audience_confusion_allowed")

    forge_parent = await issue(AgentId("coordinator-forge"), ["safe:read", "safe:write"])
    forged = _forged_key_confusion_child(forge_parent)
    try:
        await verify(forged)
    except Exception as exc:
        rejections["token_forgery"] = type(exc).__name__
    else:
        failures.append("forged_child_verified")

    if failures:
        return ValidatorReport(
            passed=False,
            detail=f"{len(failures)} delegated-auth attack(s) passed",
            evidence={"failures": failures, "rejections": rejections},
        )
    return ValidatorReport(
        passed=True,
        detail="scope escalation, stale parent, audience confusion, and token forgery were blocked",
        evidence={
            "attacks": [
                "scope_escalation",
                "stale_parent",
                "audience_confusion",
                "token_forgery",
            ],
            "rejections": rejections,
        },
    )


async def materialize_strict_delegation_report(auth: object) -> dict[str, Any]:
    """Return a JSON-serializable delegated-auth validator result.

    Example::

        report = await materialize_strict_delegation_report(
            StrictDelegatableAuth()
        )
        assert report["passed"] is True
    """
    result = await check_strict_delegated_auth_attack_suite(auth)
    return {
        "detail": result.detail,
        "evidence": result.evidence,
        "passed": result.passed,
    }


def _forged_key_confusion_child(parent_token: Token) -> Token:
    """Craft a child token that reuses the public parent signature as a key.

    This targets HMAC constructions where a root signature ``HMAC(secret,
    parent_payload)`` can also be interpreted as a delegated child signing
    key.  A correct implementation rejects the forged token at signature
    parsing, before any in-process ancestry lookup.

    Example::

        forged = _forged_key_confusion_child(parent)
        assert isinstance(forged, Token)
    """
    _, parent_signature = str(parent_token).rsplit(".", 1)
    parent_hash = hashlib.sha256(str(parent_token).encode()).hexdigest()
    payload = {
        "aud": "forge-worker",
        "exp": 1100.0,
        "iat": 1000.0,
        "jti": "forged-child",
        "parent": parent_hash,
        "scopes": ["safe:read", "admin"],
        "sub": "coordinator-forge",
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    forged_payload = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    forged_signature = hmac.new(
        parent_signature.encode(),
        _TOKEN_SIGN_DOMAIN + forged_payload.encode(),
        hashlib.sha256,
    ).hexdigest()
    return Token(f"{forged_payload}.{forged_signature}")
