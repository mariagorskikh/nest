# SPDX-License-Identifier: Apache-2.0
"""Hypothesis property-based tests for the policy decision core and manifest.

These check invariants over generated inputs, not just hand-picked cases:

1. Totality: :func:`decide` never raises for any op and arbitrary args mapping.
2. Purity: :func:`decide` never mutates the :class:`PolicyState` it is given.
3. Budget soundness: a single ``pay`` is allowed iff ``spent + amount`` is a
   valid non-negative integer within the cap (and approval, if required, holds).
4. Manifest canonicality: ``signing_bytes`` is independent of field-insertion
   order and changes whenever signed content changes.

Example::

    pytest packages/nest-plugins-reference/tests/test_policy_core_properties.py
"""

from __future__ import annotations

import copy
from typing import Any

from hypothesis import given, settings
from hypothesis import strategies as st
from nest_core.types import AgentId
from nest_plugins_reference.policy.decide import PolicyState, decide
from nest_plugins_reference.policy.manifest import Approval, Budget, PolicyManifest

_OPS = st.sampled_from(["tool", "register", "expose", "pay", "frobnicate", ""])
_SCALARS: st.SearchStrategy[Any] = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-1000, max_value=1000),
    st.floats(allow_nan=False, allow_infinity=False, width=32),
    st.text(max_size=8),
    st.lists(st.text(max_size=4), max_size=4),
)
_ARGS = st.dictionaries(
    keys=st.sampled_from(["name", "capabilities", "audience", "data_class", "amount", "currency"]),
    values=_SCALARS,
    max_size=6,
)


def _manifest() -> PolicyManifest:
    return PolicyManifest(
        agent_id=AgentId("a1"),
        tools=["buy", "sell"],
        data={"pii": ["seller-1"], "public": ["*"]},
        budget=Budget(cap=1000),
        approvals=[Approval(op="pay", threshold=200)],
    )


@settings(max_examples=300)
@given(op=_OPS, args=_ARGS)
def test_decide_is_total_and_pure(op: str, args: dict[str, Any]) -> None:
    state = PolicyState(spent={"credits": 100}, approvals={"pay:300"})
    before = copy.deepcopy(state)
    result = decide(_manifest(), op, args, state)  # must not raise
    assert isinstance(result.allowed, bool)
    assert state.spent == before.spent
    assert state.approvals == before.approvals


@settings(max_examples=300)
@given(
    spent=st.integers(min_value=0, max_value=2000),
    amount=st.integers(min_value=-100, max_value=2000),
)
def test_pay_budget_soundness(spent: int, amount: int) -> None:
    cap = 1000
    m = PolicyManifest(agent_id=AgentId("a1"), budget=Budget(cap=cap))  # no approval rule
    state = PolicyState(spent={"credits": spent})
    allowed = decide(m, "pay", {"amount": amount, "currency": "credits"}, state).allowed
    expected = amount >= 0 and spent + amount <= cap
    assert allowed == expected


@settings(max_examples=200)
@given(
    tools=st.lists(st.text(max_size=5), max_size=5),
    cap=st.integers(min_value=0, max_value=10_000),
)
def test_signing_bytes_order_independent(tools: list[str], cap: int) -> None:
    a = PolicyManifest(agent_id=AgentId("a1"), tools=tools, budget=Budget(cap=cap))
    b = PolicyManifest(agent_id=AgentId("a1"), budget=Budget(cap=cap), tools=tools)
    assert a.signing_bytes() == b.signing_bytes()


@settings(max_examples=200)
@given(
    cap1=st.integers(min_value=0, max_value=5000),
    delta=st.integers(min_value=1, max_value=5000),
)
def test_signing_bytes_changes_with_content(cap1: int, delta: int) -> None:
    a = PolicyManifest(agent_id=AgentId("a1"), budget=Budget(cap=cap1))
    b = PolicyManifest(agent_id=AgentId("a1"), budget=Budget(cap=cap1 + delta))
    assert a.signing_bytes() != b.signing_bytes()
