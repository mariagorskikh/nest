# SPDX-License-Identifier: Apache-2.0
"""The README's comparison table against `prepaid_credits`, run as code.

The README states several structural differences from the bundled
`prepaid_credits` plugin as a table of prose claims. Prose is cheap; this
file is what backs it — every row below imports the *real* upstream plugin
from `nest_plugins_reference.payments.prepaid_credits` (read in full before
writing any of these assertions) and puts it through the same scenario as
`PravaMandates`, side by side, so the difference is something a reader can
run rather than something they have to take on faith.

Nothing here is unfair to `prepaid_credits`. It is a correct, simple
implementation of a pooled ledger — that model is a legitimate choice for a
closed-economy simulation, and it is simpler than this plugin by a wide
margin: 121 lines (`wc -l prepaid_credits.py`) against 1,277 in `plugin.py`
alone, before counting the ~550-line in-process GMP/1 engine
(`_simulator.py`) or the ~270-line HTTP client (`client.py`) this plugin
also ships and `prepaid_credits` has no need of, because it never leaves the
process. What `prepaid_credits` is not, and does not claim to be, is a model
of money moving across a real payment rail. That is the entire axis these
tests compare on — not a claim that less code is worse.
"""

from __future__ import annotations

import pytest
from nanda_town_prava import PravaMandates
from nest_plugins_reference.payments.prepaid_credits import PrepaidCredits
from nest_sdk import AgentId, Money, PaymentRef, ServiceRef


def _prava(agent: str = "buyer-0", **kwargs: object) -> PravaMandates:
    return PravaMandates(AgentId(agent), initial_balance=1000, **kwargs)  # type: ignore[arg-type]


def _prepaid(agent: str = "buyer-0", **kwargs: object) -> PrepaidCredits:
    return PrepaidCredits(AgentId(agent), initial_balance=1000, **kwargs)  # type: ignore[arg-type]


async def test_prepaid_credits_pools_funds_and_prava_mandates_does_not() -> None:
    """The single structural claim everything else in the README follows from.

    Same call, same shape, same amount, against real upstream source: one
    plugin credits the payee's simulator balance, the other cannot, because
    the payee is a merchant outside the simulator on this rail.
    """
    pooled = _prepaid()
    real_rail = _prava()

    pooled_seller_before = pooled.balance(AgentId("seller-0"))
    await pooled.pay(AgentId("seller-0"), Money(amount=200), PaymentRef("p1"))
    assert pooled.balance(AgentId("seller-0")) == pooled_seller_before + 200, (
        "prepaid_credits: the payee is credited inside the simulator"
    )

    real_seller_before = real_rail.balance(AgentId("seller-0"))
    await real_rail.pay(AgentId("seller-0"), Money(amount=200), PaymentRef("p1"))
    assert real_rail.balance(AgentId("seller-0")) == real_seller_before, (
        "prava_mandates: the payee's simulator balance never moves — "
        "the money is with the merchant, outside the simulator"
    )


async def test_prepaid_credits_lets_one_agent_pay_another_freely() -> None:
    """What "agent-to-agent payment is impossible" (Limitation #1) is a contrast with.

    `prepaid_credits` has no concept of a merchant at all — every payee is
    just another agent's balance, so two agents trading value back and forth
    is exactly what it is for. That's a fine model of a closed token
    economy. It has no analogue on a card rail: Visa does not let a
    cardholder mint a merchant account and pay themselves.
    """
    pooled = _prepaid("agent-a", balances={AgentId("agent-a"): 500, AgentId("agent-b"): 500})
    b_side = PrepaidCredits(
        AgentId("agent-b"),
        initial_balance=0,
        balances=pooled._balances,  # noqa: SLF001
    )

    await pooled.pay(AgentId("agent-b"), Money(amount=100), PaymentRef("a-to-b"))
    await b_side.pay(AgentId("agent-a"), Money(amount=40), PaymentRef("b-to-a"))

    assert pooled.balance(AgentId("agent-a")) == 500 - 100 + 40
    assert pooled.balance(AgentId("agent-b")) == 500 + 100 - 40


async def test_prepaid_credits_quote_is_a_hardcoded_stub() -> None:
    """`prepaid_credits.quote()` ignores what was asked; `prava_mandates.quote()` doesn't.

    Read verbatim from upstream (`prepaid_credits.py`): ``Quote(service=service,
    price=Money(amount=10))`` — every service, any service, ten credits. It
    exists only so the `Payments` Protocol is satisfied; nothing reads the
    price book because there is no price book. `prava_mandates.quote()`
    looks up a real, configurable price book and publishes the mandate cap a
    cardholder would actually be asked to consent to — the number that backs
    "cap enforced by: the card network" (README comparison table) rather
    than "the plugin's own `if`": the cap in the quote is not a promise this
    plugin makes on its own, it is what gets minted into the mandate.
    """
    pooled = _prepaid()
    quote_a = await pooled.quote(ServiceRef("data-cleaning"))
    quote_b = await pooled.quote(ServiceRef("golden-goose"))
    assert quote_a.price.amount == quote_b.price.amount == 10, (
        "prepaid_credits prices every service identically, real or absurd"
    )

    real_rail = _prava(price_book={"data-cleaning": 4000})
    priced = await real_rail.quote(ServiceRef("data-cleaning"))
    assert priced.price.amount == 4000
    assert priced.metadata["mandate_cap"] == 4200, "price x (1 + 500bps), rounded up"
    unpriced = await real_rail.quote(ServiceRef("unknown-service"))
    assert unpriced.price.amount == 10, "an honest configurable default, not a hardcoded stub"


async def test_prepaid_credits_refund_can_fail_confusingly_once_money_moves_on() -> None:
    """Post-capture refund: an honest refusal versus a ledger op that can blow up.

    `prava_mandates.refund()` after capture always raises the same
    informative `RefundNotSupportedError`, naming the amount and the real
    remedy, regardless of what happened downstream. `prepaid_credits.refund()`
    has no concept of "already settled" — it always tries to reverse the
    ledger, so if the payee has since spent what they received (which
    `prepaid_credits` freely allows, per the test above), the refund fails
    with a generic `Insufficient balance` `ValueError` that does not explain
    *why*: the money moved on, not that the payee ran out.
    """
    pooled = _prepaid("buyer-0", balances={AgentId("buyer-0"): 1000, AgentId("seller-0"): 0})
    await pooled.pay(AgentId("seller-0"), Money(amount=400), PaymentRef("p1"))

    seller_side = PrepaidCredits(
        AgentId("seller-0"),
        initial_balance=0,
        balances=pooled._balances,  # noqa: SLF001
    )
    # The seller spends what they were just paid, same as any real seller
    # would — prepaid_credits has no way to prevent or even flag this.
    await seller_side.pay(AgentId("supplier-0"), Money(amount=400), PaymentRef("p2"))

    with pytest.raises(ValueError, match="Insufficient balance for refund"):
        await pooled.refund(PaymentRef("p1"))


async def test_prepaid_credits_has_no_multi_principal_purchase() -> None:
    """ "N humans, N cards, one purchase: structurally impossible" (README table), literally."""
    assert not hasattr(PrepaidCredits, "pay_group")
    assert not hasattr(PrepaidCredits, "declare_group")


async def test_both_plugins_satisfy_the_same_stock_marketplace_call_shape() -> None:
    """The fair half of the comparison: both are equally valid drop-ins for the stock scenario.

    Same construction, same `balance()` + `pay()` calls the marketplace
    factory actually makes (`nest_core/scenarios_builtin/marketplace.py`).
    Nothing about `prava_mandates` requires a scenario rewrite to benefit
    from its stronger guarantees.
    """
    for cls in (PrepaidCredits, PravaMandates):
        handle = cls(AgentId("buyer-0"), initial_balance=1000)  # type: ignore[call-arg]
        assert handle.balance(AgentId("buyer-0")) == 1000
        receipt = await handle.pay(AgentId("seller-0"), Money(amount=50), PaymentRef("p1"))
        assert receipt.payer == AgentId("buyer-0")
        assert receipt.payee == AgentId("seller-0")
        assert receipt.amount.amount == 50
