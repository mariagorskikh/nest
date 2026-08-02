# SPDX-License-Identifier: Apache-2.0
"""Conservation on a rail that has no inside.

The pooled ledger's invariant is "debits equal credits, within the box".
This rail has no box: money leaves a card and arrives at a merchant. What
must hold instead is that no unit of *authorization* is invented or lost,
that no agent is ever credited by someone else's payment, and that every
captured unit lands at exactly one merchant outside the simulator.
"""

from __future__ import annotations

from nanda_town_prava import PravaMandates, Principal
from nanda_town_prava._simulator import SimulatedEngine
from nest_sdk import AgentId, Money, PaymentRef, PaymentStatus


def _plugin(agent: str = "buyer-0", **kwargs: object) -> PravaMandates:
    return PravaMandates(AgentId(agent), initial_balance=1000, **kwargs)  # type: ignore[arg-type]


async def test_authorization_splits_into_captured_released_and_held() -> None:
    payments = _plugin()
    await payments.pay(AgentId("seller-0"), Money(amount=50), PaymentRef("p1"))

    auth = payments.authorization(PaymentRef("p1"))
    assert auth is not None
    # cap = 50 x (1 + 500bps) = 53 held, 50 captured, 3 released.
    assert auth.reserved == 53
    assert auth.captured == 50
    assert auth.released == 3
    assert auth.outstanding == 0
    assert auth.reserved == auth.captured + auth.released + auth.outstanding

    report = payments.conservation_report()
    assert report["authorization_conserved"]
    assert report["settlement_conserved"]
    assert report["headroom_consistent"]


async def test_no_agent_is_ever_credited_by_another() -> None:
    """The invariant `prepaid_credits` structurally cannot hold.

    There, `pay()` raises the payee's balance. Here the payee is a merchant
    outside the simulator, so no agent balance moves up — ever.
    """
    shared: dict[AgentId, int] = {AgentId("buyer-0"): 1000, AgentId("seller-0"): 1000}
    buyer = PravaMandates(AgentId("buyer-0"), initial_balance=0, balances=shared)
    seller = PravaMandates(AgentId("seller-0"), initial_balance=0, balances=shared)

    before = seller.balance(AgentId("seller-0"))
    await buyer.pay(AgentId("seller-0"), Money(amount=200), PaymentRef("p1"))

    assert seller.balance(AgentId("seller-0")) == before, "payee balance must not move"
    assert buyer.balance(AgentId("buyer-0")) < 1000, "payer headroom must be consumed"

    report = buyer.conservation_report()
    assert report["no_pooled_funds"]
    assert report["agents_credited_by_others"] == []


async def test_captured_value_lands_at_the_merchant_not_in_the_simulator() -> None:
    payments = _plugin()
    await payments.pay(AgentId("seller-0"), Money(amount=120), PaymentRef("p1"))
    await payments.pay(AgentId("seller-1"), Money(amount=80), PaymentRef("p2"))

    report = payments.conservation_report()
    assert report["merchants"] == {"seller-0": 120, "seller-1": 80}
    assert report["merchant_credited"] == report["captured"] == 200
    assert report["settlement_conserved"]


async def test_headroom_is_exactly_initial_minus_holds_plus_releases() -> None:
    payments = _plugin()
    await payments.pay(AgentId("seller-0"), Money(amount=100), PaymentRef("p1"))
    await payments.pay(AgentId("seller-0"), Money(amount=250), PaymentRef("p2"))

    # 1000 - 105 - 263 + 5 + 13 == 650, i.e. exactly the captured total.
    assert payments.balance(AgentId("buyer-0")) == 1000 - 350
    assert payments.conservation_report()["headroom_consistent"]


async def test_coordinator_that_is_not_a_principal_fronts_nothing() -> None:
    """Nobody fronts money for anybody — not even the agent driving the buy."""
    payments = PravaMandates(AgentId("organizer"), initial_balance=10)

    group = await payments.pay_group(
        AgentId("velvet-tickets"),
        Money(amount=18600),
        PaymentRef("g1"),
        principals=[Principal(name="Soham"), Principal(name="Arsh"), Principal(name="Dev")],
        policy={"type": "quorum", "m": 3},
    )

    assert group.status == "committed"
    # An 18,600 purchase settled while the coordinator held headroom of 10.
    assert payments.balance(AgentId("organizer")) == 10
    auth = payments.authorization(PaymentRef("g1"))
    assert auth is not None
    assert auth.agent_reserved == 0
    assert auth.captured == 18600
    assert payments.conservation_report()["authorization_conserved"]


async def test_abort_captures_nothing_and_returns_every_hold() -> None:
    """Policy unsatisfiable: every mandate cancelled, nobody ever charged."""
    engine = SimulatedEngine()
    payments = PravaMandates(
        AgentId("Soham"),
        initial_balance=1000,
        engine=engine,
        auto_approve=False,
        await_seconds=0.0,
    )

    await payments.pay_group(
        AgentId("velvet-tickets"),
        Money(amount=400),
        PaymentRef("g1"),
        principals=[Principal(name="Soham"), Principal(name="Arsh")],
        policy={"type": "all_of"},
    )
    auth = payments.authorization(PaymentRef("g1"))
    assert auth is not None
    assert auth.agent_reserved > 0, "the agent is a principal, so it holds its own share"
    assert payments.balance(AgentId("Soham")) < 1000

    # One principal declines. Under all_of the policy can never be met again.
    await engine.decline_member(auth.member_ids[1])

    assert await payments.verify_payment(PaymentRef("g1")) is PaymentStatus.REFUNDED
    assert auth.captured == 0
    assert auth.released == auth.reserved
    assert auth.outstanding == 0
    assert payments.balance(AgentId("Soham")) == 1000, "every hold returned"

    report = payments.conservation_report()
    assert report["captured"] == 0
    assert report["merchant_credited"] == 0
    assert report["authorization_conserved"]
    assert report["headroom_consistent"]


async def test_insufficient_headroom_is_refused_before_any_mandate_is_minted() -> None:
    payments = _plugin()
    try:
        await payments.pay(AgentId("seller-0"), Money(amount=5000), PaymentRef("p1"))
    except ValueError as exc:
        assert "headroom" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("over-cap payment should have been refused")

    assert payments.authorization(PaymentRef("p1")) is None
    assert payments.balance(AgentId("buyer-0")) == 1000
    assert await payments.verify_payment(PaymentRef("p1")) is PaymentStatus.FAILED


async def test_duplicate_reference_is_refused() -> None:
    """`ref` is the provider idempotency key; reuse is how a retry double-charges."""
    payments = _plugin()
    await payments.pay(AgentId("seller-0"), Money(amount=50), PaymentRef("p1"))
    try:
        await payments.pay(AgentId("seller-0"), Money(amount=50), PaymentRef("p1"))
    except ValueError as exc:
        assert "Duplicate payment reference" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("duplicate reference should have been refused")

    assert payments.conservation_report()["captured"] == 50
