# SPDX-License-Identifier: Apache-2.0
"""Property tests for the delegated_auth adversarial validators.

Feed the validators hand-crafted event streams -- an honest tree and one stream
per attack class -- and assert they PASS the honest case and FAIL each attack.
This proves the validators actually catch a buggy plugin that lets an attack
through, independent of the reference scenario.
"""

from __future__ import annotations

from typing import Any

from nest_core.validators import validate_events


def _bcast(agent: str, msg: str) -> dict[str, Any]:
    """Build a sender-recorded broadcast event as the trace writer would."""
    return {"kind": "broadcast", "agent": agent, "msg": msg}


def _issued(holder: str, scopes: list[str]) -> dict[str, Any]:
    return _bcast(holder, f"authz:issued:holder={holder}:scopes={'|'.join(scopes)}")


def _delegated(by: str, aud: str, parent: str, scopes: list[str]) -> dict[str, Any]:
    joined = "|".join(scopes)
    return _bcast(by, f"authz:delegated:by={by}:aud={aud}:parent={parent}:scopes={joined}")


def _verified(aud: str, presenter: str) -> dict[str, Any]:
    return _bcast(aud, f"authz:verified:by={aud}:aud={aud}:presenter={presenter}:result=ok")


def _revoked(by: str, aud: str) -> dict[str, Any]:
    return _bcast(by, f"authz:revoked:by={by}:aud={aud}")


def _honest_tree() -> list[dict[str, Any]]:
    """A minimal honest delegation tree: root -> mid -> leaf, all attenuating."""
    return [
        _issued("coordinator", ["read", "write", "exec"]),
        _delegated("coordinator", "mid", "coordinator", ["read", "write"]),
        _delegated("mid", "leaf", "mid", ["read"]),
        _verified("leaf", "leaf"),
    ]


def _names(results: list[Any]) -> dict[str, Any]:
    return {r.name: r for r in results}


# --- Honest baseline -------------------------------------------------------


def test_honest_tree_passes_all_validators() -> None:
    results = validate_events(_honest_tree(), "delegated_auth")
    assert results, "expected validators registered for delegated_auth"
    assert all(r.passed for r in results), [
        f"{r.name}: {r.detail}" for r in results if not r.passed
    ]


# --- Attack 1: scope escalation --------------------------------------------


def test_scope_escalation_is_caught() -> None:
    events = [
        _issued("coordinator", ["read", "write"]),
        _delegated("coordinator", "mid", "coordinator", ["read"]),
        # Child grabs 'exec', which neither parent ever held.
        _delegated("mid", "leaf", "mid", ["read", "exec"]),
        _verified("leaf", "leaf"),
    ]
    r = _names(validate_events(events, "delegated_auth"))["authz_no_scope_escalation"]
    assert not r.passed
    assert "exec" in r.detail


# --- Attack 2: cascading revocation (stale parent) -------------------------


def test_verify_after_ancestor_revoked_is_caught() -> None:
    events = [
        *_honest_tree(),
        _revoked("coordinator", "mid"),
        # A buggy plugin still honors the leaf after its parent 'mid' is revoked.
        _verified("leaf", "leaf"),
    ]
    r = _names(validate_events(events, "delegated_auth"))["authz_cascading_revocation"]
    assert not r.passed
    assert "mid" in r.detail


def test_verify_before_revocation_is_allowed() -> None:
    """An OK verification that precedes the revoke is legitimate, not a fault."""
    events = [
        *_honest_tree(),  # leaf verified here, before any revoke
        _revoked("coordinator", "mid"),
    ]
    r = _names(validate_events(events, "delegated_auth"))["authz_cascading_revocation"]
    assert r.passed


# --- Attack 3: audience confusion ------------------------------------------


def test_audience_confusion_is_caught() -> None:
    events = [
        *_honest_tree(),
        # 'attacker' presents leaf's token and the plugin honors it.
        _bcast("attacker", "authz:verified:by=attacker:aud=leaf:presenter=attacker:result=ok"),
    ]
    r = _names(validate_events(events, "delegated_auth"))["authz_audience_binding"]
    assert not r.passed
    assert "attacker" in r.detail


# --- Discrimination: an empty / non-delegating trace fails all three -------


def test_no_delegation_fails_all_validators() -> None:
    """The jwt-shaped trace: a root issue but no delegation or verification."""
    events = [_issued("coordinator", ["read", "write", "exec"])]
    results = validate_events(events, "delegated_auth")
    assert not any(r.passed for r in results)
    assert all("no " in r.detail for r in results)
