# SPDX-License-Identifier: Apache-2.0
"""Iteration-0 (outcome_verified_settlement_b0) registration tests.

Pin the registered surface of the plugin against upstream: the payments plugin
key, the scenario-factory key, the validator registry key, and a regression
that the invariants pass a clean run under the registered key. Upstream's own
``streaming`` plugin and ``streaming_payments`` validators are out of scope
and deliberately not asserted on.
"""

from __future__ import annotations

from typing import Any

from nest_core.plugins import PluginRegistry
from nest_core.scenarios import get_scenario_factory
from nest_core.scenarios_builtin.chainaim.outcome_verified_settlement import (
    outcome_verified_settlement_factory,
)
from nest_core.validators import (
    VALIDATORS,
    validate_events,
    validate_outcome_verified_settlement_no_drain_after_close,
    validate_outcome_verified_settlement_no_overbill,
    validate_outcome_verified_settlement_no_overbill_on_failed_verification,
    validate_outcome_verified_settlement_verdicts_match_committed_criterion,
)
from nest_plugins_reference.payments.chainaim.outcome_verified_settlement import (
    OutcomeVerifiedSettlement,
)

type Event = dict[str, Any]


def _send(agent: str, to: str, msg: str, ts: float = 1.0) -> Event:
    return {"ts": ts, "agent": agent, "kind": "send", "to": to, "msg": msg}


def _recv(agent: str, frm: str, msg: str, ts: float = 1.0) -> Event:
    return {"ts": ts, "agent": agent, "kind": "receive", "from": frm, "msg": msg}


def _clean_stream(ref: str = "buyer-0-stream", rate: int = 1, ticks: int = 5) -> list[Event]:
    """A fully delivered stream: every tick acked, drained == rate * ticks."""
    events: list[Event] = [
        _send("buyer-0", "seller-0", f"stream-open:{ref}:buyer-0:seller-0:{rate}:20:0"),
    ]
    for seq in range(ticks):
        now = seq + 1
        events.append(_send("buyer-0", "seller-0", f"tick:{ref}:{seq}:{rate}:{now}", ts=now))
        events.append(_recv("buyer-0", "seller-0", f"ack:{ref}:{seq}", ts=now))
    drained = rate * ticks
    events.append(
        _send("buyer-0", "seller-0", f"stream-close:{ref}:{ticks}:{drained}:{ticks}:done", ts=ticks)
    )
    return events


def test_outcome_verified_settlement_b0_payments_plugin_registered() -> None:
    """resolve("payments", "outcome_verified_settlement") returns OutcomeVerifiedSettlement."""
    reg = PluginRegistry()
    cls = reg.resolve("payments", "outcome_verified_settlement")
    assert cls is OutcomeVerifiedSettlement


def test_outcome_verified_settlement_b0_scenario_type_registered() -> None:
    """Scenario factory resolves under the outcome_verified_settlement key."""
    factory = get_scenario_factory("outcome_verified_settlement")
    assert factory is outcome_verified_settlement_factory


def test_outcome_verified_settlement_b0_validators_keyed_under_key() -> None:
    """VALIDATORS exposes the four validators under the outcome_verified_settlement key."""
    assert "outcome_verified_settlement" in VALIDATORS
    funcs = VALIDATORS["outcome_verified_settlement"]
    assert validate_outcome_verified_settlement_no_drain_after_close in funcs
    assert validate_outcome_verified_settlement_no_overbill in funcs
    assert validate_outcome_verified_settlement_no_overbill_on_failed_verification in funcs
    assert validate_outcome_verified_settlement_verdicts_match_committed_criterion in funcs
    assert len(funcs) == 4


def test_outcome_verified_settlement_b0_existing_invariants_still_pass() -> None:
    """The two original invariants still PASS a clean run under the renamed key."""
    results = validate_events(_clean_stream(), "outcome_verified_settlement")
    assert len(results) == 4
    assert all(r.passed for r in results)
