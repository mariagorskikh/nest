# SPDX-License-Identifier: Apache-2.0
"""Tests for the single policy decision core (all four governance dimensions)."""

from __future__ import annotations

from nest_core.types import AgentId
from nest_plugins_reference.policy.decide import PolicyState, decide
from nest_plugins_reference.policy.manifest import Approval, Budget, PolicyManifest


def _m(
    *,
    tools: list[str] | None = None,
    data: dict[str, list[str]] | None = None,
    budget: Budget | None = None,
    approvals: list[Approval] | None = None,
) -> PolicyManifest:
    return PolicyManifest(
        agent_id=AgentId("a1"),
        tools=tools or [],
        data=data or {},
        budget=budget,
        approvals=approvals or [],
    )


# --- tools dimension -------------------------------------------------------
def test_tool_allowed() -> None:
    assert decide(_m(tools=["buy"]), "tool", {"name": "buy"}, PolicyState()).allowed


def test_tool_denied() -> None:
    assert not decide(_m(tools=["buy"]), "tool", {"name": "sell"}, PolicyState()).allowed


def test_register_subset_allowed() -> None:
    d = decide(_m(tools=["buy", "sell"]), "register", {"capabilities": ["buy"]}, PolicyState())
    assert d.allowed


def test_register_overclaim_denied() -> None:
    d = decide(_m(tools=["buy"]), "register", {"capabilities": ["buy", "admin"]}, PolicyState())
    assert not d.allowed


# --- data exposure dimension ----------------------------------------------
def test_expose_allowed_audience() -> None:
    m = _m(data={"pii": ["seller-1"]})
    d = decide(m, "expose", {"data_class": "pii", "audience": ["seller-1"]}, PolicyState())
    assert d.allowed


def test_expose_disallowed_audience() -> None:
    m = _m(data={"pii": ["seller-1"]})
    d = decide(m, "expose", {"data_class": "pii", "audience": ["seller-2"]}, PolicyState())
    assert not d.allowed


def test_expose_wildcard_audience() -> None:
    m = _m(data={"public": ["*"]})
    d = decide(m, "expose", {"data_class": "public", "audience": ["anyone"]}, PolicyState())
    assert d.allowed


def test_expose_undeclared_class_denied() -> None:
    d = decide(_m(), "expose", {"data_class": "secret", "audience": ["x"]}, PolicyState())
    assert not d.allowed


# --- spend dimension -------------------------------------------------------
def test_pay_within_budget() -> None:
    assert decide(_m(budget=Budget(cap=100)), "pay", {"amount": 50}, PolicyState()).allowed


def test_pay_without_budget_denied() -> None:
    assert not decide(_m(), "pay", {"amount": 1}, PolicyState()).allowed


def test_pay_cumulative_exceeds_cap() -> None:
    state = PolicyState()
    state.record_spend("credits", 80)
    assert not decide(_m(budget=Budget(cap=100)), "pay", {"amount": 30}, state).allowed


def test_pay_currency_mismatch_denied() -> None:
    m = _m(budget=Budget(cap=100, currency="credits"))
    assert not decide(m, "pay", {"amount": 1, "currency": "usd"}, PolicyState()).allowed


def test_pay_negative_amount_denied() -> None:
    assert not decide(_m(budget=Budget(cap=100)), "pay", {"amount": -5}, PolicyState()).allowed


# --- authorization-required dimension -------------------------------------
def test_pay_over_threshold_needs_approval() -> None:
    m = _m(budget=Budget(cap=1000), approvals=[Approval(op="pay", threshold=200)])
    assert not decide(m, "pay", {"amount": 500}, PolicyState()).allowed


def test_pay_over_threshold_with_grant_allowed() -> None:
    m = _m(budget=Budget(cap=1000), approvals=[Approval(op="pay", threshold=200)])
    state = PolicyState()
    state.grant("pay:500")  # approval is bound to the specific amount
    assert decide(m, "pay", {"amount": 500}, state).allowed


def test_pay_grant_for_other_amount_does_not_authorize() -> None:
    # A grant for 500 must NOT authorize a different large amount.
    m = _m(budget=Budget(cap=100_000), approvals=[Approval(op="pay", threshold=200)])
    state = PolicyState()
    state.grant("pay:500")
    assert not decide(m, "pay", {"amount": 50_000}, state).allowed


def test_pay_under_threshold_no_approval_needed() -> None:
    m = _m(budget=Budget(cap=1000), approvals=[Approval(op="pay", threshold=200)])
    assert decide(m, "pay", {"amount": 100}, PolicyState()).allowed


def test_pay_threshold_boundary_equal_needs_no_grant() -> None:
    # amount == threshold does not require approval (rule is amount > threshold).
    m = _m(budget=Budget(cap=1000), approvals=[Approval(op="pay", threshold=200)])
    assert decide(m, "pay", {"amount": 200}, PolicyState()).allowed


def test_pay_multiple_rules_strictest_wins() -> None:
    # The lowest threshold applies regardless of declaration order.
    m = _m(
        budget=Budget(cap=10_000),
        approvals=[Approval(op="pay", threshold=1000), Approval(op="pay", threshold=10)],
    )
    assert not decide(m, "pay", {"amount": 500}, PolicyState()).allowed


# --- robustness: decide() must be total (never raise) ----------------------
def test_pay_float_amount_rejected_no_truncation_bypass() -> None:
    # int(100.9) == 100 must NOT slip past a cap of 100.
    assert not decide(_m(budget=Budget(cap=100)), "pay", {"amount": 100.9}, PolicyState()).allowed


def test_pay_bool_amount_rejected() -> None:
    assert not decide(_m(budget=Budget(cap=100)), "pay", {"amount": True}, PolicyState()).allowed


def test_pay_string_amount_does_not_raise() -> None:
    assert not decide(_m(budget=Budget(cap=100)), "pay", {"amount": "abc"}, PolicyState()).allowed


def test_pay_none_amount_does_not_raise() -> None:
    assert not decide(_m(budget=Budget(cap=100)), "pay", {"amount": None}, PolicyState()).allowed


def test_register_non_list_does_not_raise() -> None:
    assert not decide(_m(tools=["buy"]), "register", {"capabilities": "buy"}, PolicyState()).allowed


def test_expose_non_list_audience_does_not_raise() -> None:
    m = _m(data={"pii": ["x"]})
    assert not decide(m, "expose", {"data_class": "pii", "audience": None}, PolicyState()).allowed


# --- purity: decide() must not mutate state --------------------------------
def test_decide_does_not_mutate_state() -> None:
    m = _m(budget=Budget(cap=100), approvals=[Approval(op="pay", threshold=10)])
    state = PolicyState()
    state.record_spend("credits", 40)
    state.grant("pay:50")
    spent_before = dict(state.spent)
    approvals_before = set(state.approvals)
    decide(m, "pay", {"amount": 50}, state)  # allowed path
    decide(m, "pay", {"amount": 999}, state)  # denied path
    assert state.spent == spent_before
    assert state.approvals == approvals_before


def test_pay_exactly_at_cap_allowed() -> None:
    state = PolicyState()
    state.record_spend("credits", 90)
    assert decide(_m(budget=Budget(cap=100)), "pay", {"amount": 10}, state).allowed
    assert not decide(_m(budget=Budget(cap=100)), "pay", {"amount": 11}, state).allowed


def test_unknown_op_denied() -> None:
    assert not decide(_m(), "frobnicate", {}, PolicyState()).allowed
