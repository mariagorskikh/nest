# SPDX-License-Identifier: Apache-2.0
"""What the plugin does under concurrency and mid-flight failure.

Nanda Town's own Tier-1 simulator awaits one agent's whole turn before
starting the next, so it cannot itself produce these races. That is not the
same as the plugin being safe under them: an LLM-driven shell agent buying
from two sellers with `asyncio.gather`, a Tier-2 simulator, or simply `live`
mode's real HTTP round trip (`GmpHttpClient` hands the request to a worker
thread and genuinely suspends — see `client.py`) all can. A payments plugin
that is only correct when its caller happens to await serially is not
correct; it is untested.

Every test here was written against a live bug, confirmed by hand before the
fix: two concurrent `pay()` calls for the same agent, individually within
its headroom but not together, both read the same starting balance and both
reserved — headroom went negative and `conservation_report()` said nothing
was wrong. That gap is closed in `PravaMandates._pay_principals` with a
per-agent `asyncio.Lock` around the check-and-reserve step, and independently
hardened in `conservation_report()` with `no_agent_overspent_its_cap`, which
would have named the bug even if the lock had not existed.
"""

from __future__ import annotations

import asyncio

import pytest
from nanda_town_prava import PravaMandates, Principal, RefundNotSupportedError
from nanda_town_prava._simulator import SimulatedEngine
from nanda_town_prava.client import EngineTransportError
from nest_sdk import AgentId, Money, PaymentRef, PaymentStatus

JsonDict = dict[str, object]


class RendezvousEngine(SimulatedEngine):
    """``create_group`` suspends the first caller until released.

    Models the one genuine suspension point `live` mode has that
    ``SimulatedEngine`` does not: nothing in ``_simulator.py`` ever really
    yields control, so two `pay()` calls issued back to back against it run
    to completion one at a time regardless of any lock. A real HTTP round
    trip does yield — this stands in for that, deterministically, with no
    reliance on `asyncio.sleep` timing.
    """

    def __init__(self) -> None:
        super().__init__()
        self.first_entered = asyncio.Event()
        self.release_first = asyncio.Event()
        self._seen_first = False

    async def create_group(self, body: JsonDict) -> JsonDict:
        if not self._seen_first:
            self._seen_first = True
            self.first_entered.set()
            await self.release_first.wait()
        return await super().create_group(body)


class FlakyOnceEngine(SimulatedEngine):
    """The first ``create_group`` call fails as if the engine were down; the next succeeds.

    Models a `live`-mode outage at exactly the moment a mandate would be
    minted — the point where nothing has happened at the engine yet, so the
    honest response is "this purchase never started", not a partially
    reserved hold nor a consumed idempotency key.
    """

    def __init__(self) -> None:
        super().__init__()
        self._fail_next = True

    async def create_group(self, body: JsonDict) -> JsonDict:
        if self._fail_next:
            self._fail_next = False
            msg = "POST /v1/groups did not complete: connection refused"
            raise EngineTransportError(msg)
        return await super().create_group(body)


class HangingEngine(SimulatedEngine):
    """``create_group`` never returns on its own — only cancellation ends it.

    Stands in for a scenario that aborts mid-purchase (a tick budget
    exhausted, a task group cancelled) while the engine call is in flight.
    """

    async def create_group(self, body: JsonDict) -> JsonDict:
        await asyncio.sleep(10)
        return await super().create_group(body)  # pragma: no cover - never reached


class CommitsDuringCancelEngine(SimulatedEngine):
    """The group commits in the gap between ``refund()``'s refresh and its cancel call.

    Nothing serialises "a principal's passkey tap lands" against "the
    organizer calls refund()" — GMP/1 has no such lock, by design, since the
    whole point is that a human can act at any time. This models that race
    directly rather than hoping timing produces it.
    """

    async def cancel_group(self, group_id: str) -> JsonDict:
        group = self._must_group(group_id)  # noqa: SLF001
        for member in group.members:
            if member.status != "charged":
                member.status = "approved"
                member.mandate_id = self._next("md")  # noqa: SLF001
        self._commit(group)  # noqa: SLF001
        # The group is now terminal, so the real cancel_group (which this
        # calls next) raises "already {status}" -- precisely the race.
        return await super().cancel_group(group_id)


async def test_concurrent_pay_by_the_same_agent_cannot_overspend_its_cap() -> None:
    """Two purchases that individually fit but not together: one wins, one is refused.

    Before the per-agent lock in `_pay_principals`, both of these would
    check the same starting headroom (100) before either reserved, and both
    would succeed — 120 authorized against a 100 cap. Confirmed by hand
    against the unlocked code: final headroom -20, and
    `conservation_report()` reported every invariant green.
    """
    engine = RendezvousEngine()
    payments = PravaMandates(
        AgentId("buyer-0"), initial_balance=100, engine=engine, await_seconds=0.0
    )

    first = asyncio.ensure_future(
        payments.pay(AgentId("seller-0"), Money(amount=60), PaymentRef("p1"))
    )
    # First call has passed its check-and-reserve step (headroom is already
    # down to 37) and is now blocked inside create_group, exactly the window
    # a real network round trip opens.
    await engine.first_entered.wait()
    assert payments.balance(AgentId("buyer-0")) == 37, "reserved before the network call, not after"

    with pytest.raises(ValueError, match="Insufficient authorization headroom"):
        await payments.pay(AgentId("seller-1"), Money(amount=60), PaymentRef("p2"))

    engine.release_first.set()
    receipt = await first
    assert receipt.ref == "p1"

    assert payments.balance(AgentId("buyer-0")) == 40, (
        "60 captured, 3 released, nothing double-spent"
    )
    report = payments.conservation_report()
    assert report["no_agent_overspent_its_cap"]
    assert report["agents_over_their_cap"] == []
    assert report["headroom_consistent"]


async def test_two_different_agents_pay_at_once_without_contending() -> None:
    """The per-agent lock must not serialise agents that do not share a key."""
    shared: dict[AgentId, int] = {AgentId("buyer-0"): 100, AgentId("buyer-1"): 100}
    engine = SimulatedEngine()
    a = PravaMandates(
        AgentId("buyer-0"), initial_balance=0, balances=shared, engine=engine, await_seconds=0.0
    )
    b = PravaMandates(
        AgentId("buyer-1"), initial_balance=0, balances=shared, engine=engine, await_seconds=0.0
    )

    receipts = await asyncio.gather(
        a.pay(AgentId("seller-0"), Money(amount=60), PaymentRef("pa")),
        b.pay(AgentId("seller-0"), Money(amount=60), PaymentRef("pb")),
    )
    assert {r.ref for r in receipts} == {"pa", "pb"}
    assert a.balance(AgentId("buyer-0")) == 40
    assert b.balance(AgentId("buyer-1")) == 40
    report = a.conservation_report()
    assert report["authorization_conserved"]
    assert report["no_agent_overspent_its_cap"]


async def test_engine_unreachable_at_creation_leaves_no_partial_state() -> None:
    """A `create_group` failure must not consume the ref or leak a hold.

    Before this was fixed, headroom was only ever reserved *after*
    `create_group` returned, so failure here already left no partial state —
    but there was also no test pinning it, and the fix above changed *when*
    the reservation happens (now before the call). This is the regression
    test for both facts at once: reserve-then-roll-back must net to exactly
    where it started.
    """
    engine = FlakyOnceEngine()
    payments = PravaMandates(
        AgentId("buyer-0"), initial_balance=1000, engine=engine, await_seconds=0.0
    )

    with pytest.raises(EngineTransportError):
        await payments.pay(AgentId("seller-0"), Money(amount=50), PaymentRef("p1"))

    assert payments.balance(AgentId("buyer-0")) == 1000, "the failed hold must be given back"
    assert payments.authorization(PaymentRef("p1")) is None, (
        "never authorized -- ref is free to retry"
    )

    # The engine is back (FlakyOnceEngine only fails once). The same ref,
    # retried on the same handle, must succeed cleanly -- this is the
    # replay-safety the ref-as-idempotency-key design promises.
    receipt = await payments.pay(AgentId("seller-0"), Money(amount=50), PaymentRef("p1"))
    assert receipt.ref == "p1"
    assert await payments.verify_payment(PaymentRef("p1")) is PaymentStatus.CONFIRMED
    assert payments.conservation_report()["no_agent_overspent_its_cap"]


async def test_a_cancelled_purchase_releases_its_hold() -> None:
    """A scenario aborting mid-purchase must not leave headroom permanently short.

    `except BaseException` in `_pay_principals`, not `except Exception` --
    `asyncio.CancelledError` is a `BaseException` and a plain `except
    Exception:` would let a cancelled task's hold leak silently.
    """
    engine = HangingEngine()
    payments = PravaMandates(
        AgentId("buyer-0"), initial_balance=1000, engine=engine, await_seconds=0.0
    )

    task = asyncio.ensure_future(
        payments.pay(AgentId("seller-0"), Money(amount=50), PaymentRef("p1"))
    )
    await asyncio.sleep(0)  # let it reserve and reach the hanging create_group call
    assert payments.balance(AgentId("buyer-0")) == 947, "reserved while the call is in flight"

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert payments.balance(AgentId("buyer-0")) == 1000, "a cancelled pay() must not leak a hold"
    assert payments.authorization(PaymentRef("p1")) is None


async def test_refund_racing_a_commit_reports_the_charge_not_a_generic_error() -> None:
    """If a principal's passkey tap lands while `refund()` is cancelling, say so honestly.

    The dishonest failure mode here is not "refund raises" -- it is *which*
    exception. A bare `ValueError("could not cancel group")` reads like a
    transient error worth retrying. `RefundNotSupportedError` is the true
    story: money already moved, and it names how much and to reverse it.
    """
    engine = CommitsDuringCancelEngine()
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
        principals=[Principal(name="Soham")],
    )
    auth = payments.authorization(PaymentRef("g1"))
    assert auth is not None
    assert auth.group_status == "collecting", "refund() still believes this is pre-capture"

    with pytest.raises(RefundNotSupportedError) as excinfo:
        await payments.refund(PaymentRef("g1"))

    assert excinfo.value.captured > 0
    assert "merchant-initiated refund" in excinfo.value.remedy
    assert payments.conservation_report()["settlement_conserved"]
