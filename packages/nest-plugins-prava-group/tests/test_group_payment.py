# SPDX-License-Identifier: Apache-2.0
"""The differentiator: one pay(), N principals, N cards, N passkeys.

Every test in this file runs a complete group mandate end to end with no
network and no keys. `prepaid_credits` cannot express any of it — a pooled
ledger has one balance per agent and no notion of a second human.
"""

from __future__ import annotations

import pytest
from nanda_town_prava import PravaMandates, Principal
from nanda_town_prava._simulator import SimulatedEngine
from nest_sdk import AgentId, Money, PaymentRef, PaymentStatus


def _organizer(engine: SimulatedEngine | None = None, **kwargs: object) -> PravaMandates:
    return PravaMandates(
        AgentId("organizer"),
        initial_balance=1000,
        engine=engine or SimulatedEngine(),
        await_seconds=0.0,
        **kwargs,  # type: ignore[arg-type]
    )


async def test_full_group_commit_charges_every_principal_on_their_own_card() -> None:
    payments = _organizer()

    group = await payments.pay_group(
        AgentId("velvet-tickets"),
        Money(amount=18600),
        PaymentRef("ratatat"),
        principals=[
            Principal(name="Soham"),
            Principal(name="Arsh"),
            Principal(name="Dev"),
            Principal(name="Maya"),
        ],
        policy={"type": "all_of"},
    )

    assert group.status == "committed"
    assert group.total == 18600
    assert await payments.verify_payment(PaymentRef("ratatat")) is PaymentStatus.CONFIRMED

    auth = payments.authorization(PaymentRef("ratatat"))
    assert auth is not None
    # Four principals, four distinct mandates, four distinct transactions.
    assert len(auth.mandate_ids) == 4
    assert len(set(auth.mandate_ids.values())) == 4
    assert len(set(auth.transaction_ids.values())) == 4
    assert auth.captured == 18600
    assert payments.conservation_report()["merchants"] == {"velvet-tickets": 18600}


async def test_each_principal_gets_their_own_approval_url() -> None:
    """The agent hands out URLs. It cannot and must not approve for anybody."""
    payments = _organizer(auto_approve=False)

    group = await payments.pay_group(
        AgentId("velvet-tickets"),
        Money(amount=300),
        PaymentRef("g1"),
        principals=[Principal(name="Soham"), Principal(name="Arsh"), Principal(name="Dev")],
    )

    assert set(group.approval_urls) == {"Soham", "Arsh", "Dev"}
    assert len(set(group.approval_urls.values())) == 3, "no two people share a ceremony"
    assert group.status == "collecting", "nothing commits until humans approve"
    assert await payments.verify_payment(PaymentRef("g1")) is PaymentStatus.PENDING
    assert payments.conservation_report()["captured"] == 0


async def test_quorum_commits_without_the_whole_group() -> None:
    """Tolerance is what lets a drop-out re-pro-rate without re-consent (§1)."""
    engine = SimulatedEngine()
    payments = _organizer(engine, auto_approve=False)

    await payments.pay_group(
        AgentId("velvet-tickets"),
        Money(amount=400),
        PaymentRef("g1"),
        principals=[
            Principal(name="Soham"),
            Principal(name="Arsh"),
            Principal(name="Dev"),
            Principal(name="Maya"),
        ],
        policy={"type": "quorum", "m": 3},
        # 100 each at a 4-way split; a 3-way split is 134, so each consent has
        # to have been given with enough headroom to absorb it.
        tolerance_bps=5000,
    )
    auth = payments.authorization(PaymentRef("g1"))
    assert auth is not None

    await engine.decline_member(auth.member_ids[3])  # Maya is out
    for member_id in auth.member_ids[:3]:
        await engine.approve_member(member_id)

    assert await payments.verify_payment(PaymentRef("g1")) is PaymentStatus.CONFIRMED
    assert auth.captured == 400, "the cart is still funded in full"
    # Maya's share redistributed across the three who approved; nobody was
    # charged beyond the cap they consented to.
    assert set(auth.transaction_ids) == {"Soham", "Arsh", "Dev"}


async def test_caps_too_tight_to_re_pro_rate_is_reported_as_underfunded() -> None:
    """Consent cannot stretch, and an underfunded cart does not claim success.

    With only 5% tolerance a 4-way split cannot absorb a drop-out. Each
    remaining principal is charged their cap and no further, the merchant is
    short, and `PaymentStatus` has no word for "three of four paid" — so
    this reports FAILED and puts the truth on the authorization record
    rather than overclaiming CONFIRMED.
    """
    engine = SimulatedEngine()
    payments = _organizer(engine, auto_approve=False)

    await payments.pay_group(
        AgentId("velvet-tickets"),
        Money(amount=400),
        PaymentRef("g1"),
        principals=[
            Principal(name="Soham"),
            Principal(name="Arsh"),
            Principal(name="Dev"),
            Principal(name="Maya"),
        ],
        policy={"type": "quorum", "m": 3},
        tolerance_bps=500,
    )
    auth = payments.authorization(PaymentRef("g1"))
    assert auth is not None

    await engine.decline_member(auth.member_ids[3])
    for member_id in auth.member_ids[:3]:
        await engine.approve_member(member_id)

    assert await payments.verify_payment(PaymentRef("g1")) is PaymentStatus.FAILED
    assert auth.group_status == "partial"
    assert auth.partial_settlement, "flagged, not hidden"
    assert auth.captured == 315, "3 x their 105 cap — consent did not stretch"
    assert payments.conservation_report()["settlement_conserved"]


async def test_all_of_with_one_decline_charges_nobody() -> None:
    """Atomically enough: either everyone is charged, or nobody ever was."""
    engine = SimulatedEngine()
    payments = _organizer(engine, auto_approve=False)

    await payments.pay_group(
        AgentId("velvet-tickets"),
        Money(amount=400),
        PaymentRef("g1"),
        principals=[Principal(name="Soham"), Principal(name="Arsh"), Principal(name="Dev")],
        policy={"type": "all_of"},
    )
    auth = payments.authorization(PaymentRef("g1"))
    assert auth is not None

    await engine.approve_member(auth.member_ids[0])
    await engine.approve_member(auth.member_ids[1])
    await engine.decline_member(auth.member_ids[2])

    assert await payments.verify_payment(PaymentRef("g1")) is PaymentStatus.REFUNDED
    assert auth.captured == 0
    assert auth.mandate_ids == {}, "the approved mandates were cancelled, not charged"
    assert payments.conservation_report()["merchant_credited"] == 0


async def test_backstop_absorbs_a_shortfall_with_zero_pooled_funds() -> None:
    """A pre-approved intra-group trust line, executed on its own card."""
    engine = SimulatedEngine()
    payments = _organizer(engine, auto_approve=False)

    await payments.pay_group(
        AgentId("velvet-tickets"),
        Money(amount=900),
        PaymentRef("g1"),
        principals=[
            Principal(name="Soham"),
            Principal(name="Arsh"),
            Principal(name="Dev"),
            Principal(name="Maya", role="backstop", backstop_cap=600),
        ],
        policy={"type": "quorum", "m": 2},
        tolerance_bps=0,  # no headroom, so a drop-out creates a real shortfall
    )
    auth = payments.authorization(PaymentRef("g1"))
    assert auth is not None

    await engine.approve_member(auth.member_ids[3])  # Maya arms her backstop
    await engine.approve_member(auth.member_ids[0])
    await engine.decline_member(auth.member_ids[2])
    await engine.approve_member(auth.member_ids[1])

    await payments.verify_payment(PaymentRef("g1"))
    assert auth.captured == 900, "the merchant is paid in full"
    assert "Maya" in auth.transaction_ids, "the backstop was charged on her own card"
    assert payments.conservation_report()["settlement_conserved"]


async def test_declare_group_makes_a_plain_pay_fan_out() -> None:
    """An unmodified scenario only ever calls pay(). It can still go multi-principal."""
    payments = _organizer()
    payments.declare_group(PaymentRef("p1"), [Principal(name="Soham"), Principal(name="Arsh")])

    await payments.pay(AgentId("seller-0"), Money(amount=200), PaymentRef("p1"))

    auth = payments.authorization(PaymentRef("p1"))
    assert auth is not None
    assert auth.principals == ("Soham", "Arsh")
    assert len(auth.transaction_ids) == 2
    assert await payments.verify_payment(PaymentRef("p1")) is PaymentStatus.CONFIRMED


async def test_an_unimplemented_policy_refuses_rather_than_guessing() -> None:
    """Guessing at a commit rule is how the wrong people get charged."""
    payments = _organizer(auto_approve=False)
    await payments.pay_group(
        AgentId("velvet-tickets"),
        Money(amount=100),
        PaymentRef("g1"),
        principals=[Principal(name="Soham")],
        policy={"type": "deadline", "at": "2026-01-01T00:00:00Z"},
    )
    auth = payments.authorization(PaymentRef("g1"))
    assert auth is not None

    with pytest.raises(NotImplementedError, match="commit policy"):
        # Approving forces a policy evaluation, which refuses the unknown type
        # rather than silently degrading to all_of.
        await payments._bundle.transport.approve_member(auth.member_ids[0])  # noqa: SLF001


async def test_a_requote_cascade_is_followed_to_a_commit() -> None:
    """Regression: the engine can cancel a consent and ask for a bigger one.

    Found by running `live` mode against the deployed engine for the first
    time. The plugin opened each mandate session exactly once and then polled
    a group that could never move again, because a requote had put every
    survivor back to `viewed` with their old mandate cancelled. `pay()` now
    re-mints the session — which on a real rail is the same human tapping
    their passkey a second time, at the new number.
    """
    from .conftest import RequotingEngine

    engine = RequotingEngine()
    payments = PravaMandates(
        AgentId("organizer"),
        initial_balance=1000,
        engine=engine,
        auto_approve=True,
        await_seconds=5.0,
        poll_interval=0.0,
    )

    group = await payments.pay_group(
        AgentId("velvet-tickets"),
        Money(amount=100),
        PaymentRef("g1"),
        principals=[Principal(name="Soham"), Principal(name="Arsh"), Principal(name="Dev")],
        policy={"type": "quorum", "m": 2},
    )

    auth = payments.authorization(PaymentRef("g1"))
    assert auth is not None
    assert group.status == "committed"
    assert await payments.verify_payment(PaymentRef("g1")) is PaymentStatus.CONFIRMED
    assert auth.captured == 100, "the merchant is paid in full after the requote"
    assert auth.requote_rounds == {"Soham": 1, "Arsh": 1}, "recorded, not swallowed"
    assert engine.opens == ["mi_0", "mi_1", "mi_0", "mi_1"], (
        "the two survivors were re-minted; the dropped member never got a session"
    )
    # `reserved` is the peak the network held: 3 x 35 in round 0, then
    # 2 x 53 once the dropped member's mandate was cancelled.
    assert auth.reserved == 106
    assert auth.reserved == auth.captured + auth.released + auth.outstanding
    report = payments.conservation_report()
    assert report["authorization_conserved"]
    assert report["no_pooled_funds"]
    assert report["settlement_conserved"]


async def test_a_requoted_principal_gets_a_new_approval_url() -> None:
    """The old URL is dead: its mandate was cancelled. Handing it out is a bug."""
    from .conftest import RequotingEngine

    engine = RequotingEngine()
    payments = PravaMandates(
        AgentId("organizer"),
        initial_balance=1000,
        engine=engine,
        auto_approve=False,  # nobody taps yet; we only want the URLs
        await_seconds=0.0,
    )
    await payments.pay_group(
        AgentId("velvet-tickets"),
        Money(amount=100),
        PaymentRef("g1"),
        principals=[Principal(name="Soham"), Principal(name="Arsh"), Principal(name="Dev")],
        policy={"type": "quorum", "m": 2},
    )
    auth = payments.authorization(PaymentRef("g1"))
    assert auth is not None
    first = dict(auth.approval_urls)
    assert len(first) == 3

    # Soham and Arsh tap. The engine drops Dev and requotes the other two.
    await engine.approve_member("mi_0")
    await engine.approve_member("mi_1")
    await payments.verify_payment(PaymentRef("g1"))
    assert auth.requote_rounds == {"Soham": 1, "Arsh": 1}

    # pay() is over, so re-minting is the next caller's move: ask again.
    await payments._drive_members(auth)  # noqa: SLF001
    assert auth.approval_urls["Soham"] != first["Soham"], "a fresh session, not the dead one"
    assert "_r1" in auth.approval_urls["Soham"]
    assert auth.approval_urls["Dev"] == first["Dev"], "a dropped member is not re-invited"
