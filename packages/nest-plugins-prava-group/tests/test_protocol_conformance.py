# SPDX-License-Identifier: Apache-2.0
"""Conformance to the upstream contract — including the undocumented parts.

Two of the things Nanda Town actually requires of a payments plugin are
*not* in the `Payments` Protocol: the constructor shape the scenario
factories use, and the `balance()` method the marketplace agents call.
A plugin that implements only the Protocol will not run in the stock
scenario, so both are pinned here.
"""

from __future__ import annotations

import inspect

import pytest
from nanda_town_prava import PravaMandates
from nest_sdk import (
    AgentId,
    Money,
    PaymentRef,
    Payments,
    PaymentStatus,
    Quote,
    Receipt,
    ServiceRef,
)


def test_satisfies_the_payments_protocol() -> None:
    payments = PravaMandates(AgentId("a1"))
    assert isinstance(payments, Payments)


def test_every_protocol_method_is_a_coroutine_with_the_upstream_signature() -> None:
    expected = {
        "quote": ["self", "service"],
        "pay": ["self", "to", "amount", "ref"],
        "verify_payment": ["self", "ref"],
        "refund": ["self", "ref"],
    }
    for name, params in expected.items():
        method = getattr(PravaMandates, name)
        assert inspect.iscoroutinefunction(method), f"{name} must be async"
        assert list(inspect.signature(method).parameters)[: len(params)] == params, name


def test_constructs_the_way_the_scenario_factories_construct_it() -> None:
    """`nest_core.scenarios_builtin.marketplace._instantiate_plugins`, verbatim."""
    all_ids = [AgentId("buyer-0"), AgentId("seller-0")]
    balances: dict[AgentId, int] = {aid: 1000 for aid in all_ids}
    records: dict[PaymentRef, Receipt] = {}

    shared = PravaMandates(
        AgentId("system"), initial_balance=0, balances=balances, payments=records
    )
    per_agent = [
        PravaMandates(aid, initial_balance=0, balances=balances, payments=records)
        for aid in all_ids
    ]

    assert shared.balance(AgentId("buyer-0")) == 1000
    assert all(p.balance(AgentId("buyer-0")) == 1000 for p in per_agent)

    # And the TypeError fallback path the factory drops to.
    assert PravaMandates(AgentId("system"), initial_balance=0).balance(AgentId("system")) == 0


async def test_returns_the_upstream_model_types() -> None:
    payments = PravaMandates(AgentId("buyer-0"), initial_balance=1000, await_seconds=0.0)

    quote = await payments.quote(ServiceRef("svc"))
    assert isinstance(quote, Quote)
    assert isinstance(quote.price, Money)

    receipt = await payments.pay(AgentId("seller-0"), Money(amount=50), PaymentRef("p1"))
    assert isinstance(receipt, Receipt)
    assert receipt.ref == PaymentRef("p1")
    assert receipt.payer == AgentId("buyer-0")
    assert receipt.payee == AgentId("seller-0")
    assert receipt.amount.amount == 50

    assert isinstance(await payments.verify_payment(PaymentRef("p1")), PaymentStatus)


def test_never_references_a_paymentstatus_member_that_may_not_exist() -> None:
    """`STREAMING` is on git HEAD but not in nest-core 0.1.4 on PyPI.

    Referencing it would `AttributeError` on the published package, so this
    pins that we only use members present in every released version.
    """
    from nanda_town_prava import plugin  # noqa: PLC0415

    used = {status.name for status in plugin._MEMBER_STATUS.values()}  # noqa: SLF001
    assert used <= {"PENDING", "CONFIRMED", "FAILED", "REFUNDED"}
    assert used <= {member.name for member in PaymentStatus}


def test_rejects_a_mode_it_does_not_implement() -> None:
    with pytest.raises(ValueError, match="mode must be"):
        PravaMandates(AgentId("a1"), mode="telepathy")


def test_defaults_to_simulated_so_nest_run_works_with_no_engine() -> None:
    payments = PravaMandates(AgentId("a1"))
    assert payments.mode == "simulated"
    assert payments.rail == "prava_mandates"


async def test_live_mode_returns_without_waiting_for_a_human() -> None:
    """`pay()` in live mode must not block a tick on a passkey tap."""
    engine = _RecordingEngine()
    payments = PravaMandates(
        AgentId("organizer"),
        initial_balance=1000,
        mode="live",
        engine=engine,
        auto_approve=False,
    )
    assert payments.mode == "live"
    assert payments._await_seconds == 0.0, "live mode does not poll by default"  # noqa: SLF001

    receipt = await payments.pay(AgentId("seller-0"), Money(amount=50), PaymentRef("p1"))

    assert isinstance(receipt, Receipt)
    assert engine.approvals == [], "the agent must never approve on a human's behalf"

    auth = payments.authorization(PaymentRef("p1"))
    assert auth is not None
    assert auth.approval_urls == {"organizer": "https://pay.prava.space/s/abc"}
    assert auth.captured == 0, "nothing is charged until a passkey is tapped"
    assert await payments.verify_payment(PaymentRef("p1")) is PaymentStatus.PENDING


class _RecordingEngine:
    """Minimal transport that never commits anything."""

    def __init__(self) -> None:
        self.approvals: list[str] = []

    async def create_group(self, body: dict[str, object]) -> dict[str, object]:
        return {
            "group_id": "g1",
            "board_url": "",
            "members": [{"member_id": "mi1", "name": "organizer"}],
        }

    async def get_group(self, group_id: str) -> dict[str, object]:
        return {"status": "collecting", "members": []}

    async def cancel_group(self, group_id: str) -> dict[str, object]:
        return {"status": "aborted", "members": []}

    async def get_receipt(self, group_id: str) -> dict[str, object] | None:
        return None

    async def open_member(self, member_id: str) -> dict[str, object]:
        return {"name": "organizer", "approval_url": "https://pay.prava.space/s/abc"}

    async def get_member(self, member_id: str) -> dict[str, object]:
        return {}

    async def approve_member(self, member_id: str) -> bool:
        self.approvals.append(member_id)
        return False
