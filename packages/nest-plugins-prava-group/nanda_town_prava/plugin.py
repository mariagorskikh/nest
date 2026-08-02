# SPDX-License-Identifier: Apache-2.0
"""Nanda Town ``payments`` plugin backed by Prava mandates and GMP/1.

The bundled ``prepaid_credits`` plugin is a pooled internal ledger: agents
hold balances, and ``pay()`` moves value from one agent's balance to
another's. Value never leaves the simulator, and it is conserved because
nothing ever crosses a boundary.

This plugin is the opposite, and that inversion is the whole design:

    **pay() never moves pooled funds.**

It maps onto a real card-network authorization. Each principal's consent
mints a Prava mandate scoped to one merchant and capped at one amount,
charged once and reported once. Money leaves a real card and arrives at a
real merchant. The simulator holds no balance, fronts nothing, and never
touches a card number — it coordinates *authorizations*, which is why the
engine behind it is software in front of a regulated rail rather than a
money transmitter.

The consequence worth stating plainly: with this plugin installed, a
Nanda Town agent cannot pay another agent. There is no rail for that.
What it can do is something ``prepaid_credits`` structurally cannot —
:meth:`PravaMandates.pay_group` puts N humans, N cards and N passkeys
behind a single purchase, atomically enough that either the policy is met
and everyone is charged in one window, or every mandate is cancelled and
nobody was ever charged.

Example::

    payments = PravaMandates(AgentId("buyer-0"))
    receipt = await payments.pay(AgentId("seller-0"), Money(amount=50), PaymentRef("p1"))
    assert await payments.verify_payment(PaymentRef("p1")) is PaymentStatus.CONFIRMED
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import math
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any

from nest_sdk import (
    AgentId,
    Money,
    PaymentRef,
    PaymentStatus,
    Quote,
    Receipt,
    ServiceRef,
)

from ._redaction import redact
from ._simulator import SimulatedEngine
from .client import DEFAULT_BASE_URL, EngineError, EngineTransport, GmpHttpClient

# GMP responses enter as JSON dictionaries and are narrowed field-by-field;
# preserve that honest boundary rather than pretending every remote shape is
# statically known before protocol validation.
# pyright: reportUnknownArgumentType=false, reportUnknownMemberType=false, reportUnknownVariableType=false

__all__ = [
    "Authorization",
    "GroupAuthorization",
    "Principal",
    "PravaMandates",
    "RefundNotSupportedError",
]

MODE_SIMULATED = "simulated"
MODE_LIVE = "live"

# Nanda Town prices things in `credits`. A card network prices things in
# minor units of an ISO-4217 currency. Nothing in the simulator knows what a
# credit is worth, so the conversion is stated here, configurable, and
# defaulted to 1 credit = 1 minor unit rather than silently assumed.
DEFAULT_SETTLEMENT_CURRENCY = "USD"
DEFAULT_CREDIT_MINOR_UNITS = 1
DEFAULT_TOLERANCE_BPS = 500

_RAIL = "prava_mandates"
_SLUG_RE = re.compile(r"[^a-z0-9-]+")

# GMP/1 member states -> PaymentStatus. Anything absent is UNKNOWN, and an
# unknown state is never allowed to become CONFIRMED.
_MEMBER_STATUS: dict[str, PaymentStatus] = {
    "invited": PaymentStatus.PENDING,
    "viewed": PaymentStatus.PENDING,
    "awaiting_approval": PaymentStatus.PENDING,
    "approved": PaymentStatus.PENDING,
    "charging": PaymentStatus.PENDING,
    "charged": PaymentStatus.CONFIRMED,
    # at_venue rail: the member agreed their amount and owes the venue
    # directly. Deliberately NOT confirmed — this engine charged no card.
    "settled": PaymentStatus.PENDING,
    "declined": PaymentStatus.FAILED,
    "expired": PaymentStatus.FAILED,
    "dropped": PaymentStatus.FAILED,
    "failed": PaymentStatus.FAILED,
}

_GROUP_STATUS_TERMINAL = frozenset({"committed", "partial", "aborted", "expired"})
_GROUP_STATUS_KNOWN = _GROUP_STATUS_TERMINAL | {"draft", "collecting", "deciding", "committing"}

# Member states in which the engine has already cancelled that member's
# mandate, so the card network is no longer holding their cap.
_MANDATE_RELEASED = frozenset({"declined", "expired", "dropped", "failed"})

# Member states that mean "no live mandate session exists for this member".
# `invited` is the initial state; a member is put back to `viewed` by a
# requote (GMP/1 §4.1), which cancels their old mandate first.
_NEEDS_SESSION = frozenset({"invited", "viewed"})


class RefundNotSupportedError(NotImplementedError):
    """A settled card charge does not roll back. Raised by :meth:`PravaMandates.refund`.

    This is not a gap in the implementation. Once an authorization is
    captured, the money is at the merchant, and the only instrument that can
    return it is a merchant-initiated refund or a cardholder-initiated
    chargeback — both of which happen on the acquirer's timeline, days
    later, outside any simulation tick. A payments layer that quietly
    reversed a ledger entry here would be reporting a settlement property
    the rail does not have.

    Example::

        raise RefundNotSupportedError(ref="p1", captured=4500, currency="USD")
    """

    def __init__(self, *, ref: str, captured: int, currency: str) -> None:
        self.ref = ref
        self.captured = captured
        self.currency = currency
        self.remedy = (
            "issue a merchant-initiated refund against the Prava transaction id on the "
            "authorization record, or have the cardholder open a chargeback"
        )
        super().__init__(
            f"refund not supported on the {_RAIL} rail: {captured} {currency} was already "
            f"captured for {ref}. A settled card charge does not roll back. Remedy: "
            f"{self.remedy}."
        )


@dataclass(frozen=True)
class Principal:
    """One human with one card and one passkey.

    Example::

        Principal(name="Soham"), Principal(name="Arsh", role="backstop", backstop_cap=6000)
    """

    name: str
    weight: int = 1
    role: str = "payer"
    backstop_cap: int | None = None
    email: str | None = None

    def to_member(self) -> dict[str, Any]:
        """Render as a GMP/1 ``members[]`` entry.

        Example::

            Principal(name="Soham").to_member()
        """
        member: dict[str, Any] = {"name": self.name, "role": self.role, "weight": self.weight}
        if self.backstop_cap is not None:
            member["backstop_cap"] = self.backstop_cap
        if self.email:
            member["email"] = self.email
        return member


@dataclass
class Authorization:
    """Everything this plugin knows about one ``PaymentRef``.

    ``Receipt`` upstream carries no metadata field (verified against
    ``nest_core.types``: ``ref``, ``payer``, ``payee``, ``amount``,
    ``timestamp``, and a default pydantic config that silently *drops*
    extra kwargs). So the mandate identifiers live here, reachable via
    :meth:`PravaMandates.authorization`, rather than being smuggled into a
    model that would discard them.

    Example::

        auth = payments.authorization(PaymentRef("p1"))
        print(auth.approval_urls, auth.captured)
    """

    ref: str
    payer: str
    payee: str
    group_id: str
    board_url: str
    currency: str
    principals: tuple[str, ...]
    member_ids: tuple[str, ...] = ()
    approval_urls: dict[str, str] = field(default_factory=dict)
    mandate_ids: dict[str, str] = field(default_factory=dict)
    transaction_ids: dict[str, str] = field(default_factory=dict)
    # Total authorization minted across *every* principal — including the
    # humans holding cards outside the simulator. This is what the card
    # networks are holding.
    reserved: int = 0
    captured: int = 0
    released: int = 0
    # The slice of the above drawn from this simulator agent's own headroom,
    # which is zero whenever the agent is coordinating rather than paying.
    agent_reserved: int = 0
    agent_captured: int = 0
    agent_released: int = 0
    group_status: str = "collecting"
    # How many times the engine sent each principal back for a fresh passkey
    # tap at a larger share (GMP/1 §4.1, capped at 2 by the engine). Zero for
    # every member on the happy path.
    requote_rounds: dict[str, int] = field(default_factory=dict)
    rail: str | None = None
    voided: bool = False
    partial_settlement: bool = False
    unknown_states: tuple[str, ...] = ()
    simulated: bool = True

    @property
    def outstanding(self) -> int:
        """Authorization still on hold: reserved minus captured minus released."""
        return self.reserved - self.captured - self.released

    def as_dict(self) -> dict[str, Any]:
        """A redacted, JSON-safe view. Safe to log, trace, or hand to a judge.

        Example::

            auth.as_dict()
        """
        return redact(
            {
                "ref": self.ref,
                "payer": self.payer,
                "payee": self.payee,
                "group_id": self.group_id,
                "board_url": self.board_url,
                "currency": self.currency,
                "rail": self.rail,
                "principals": list(self.principals),
                "member_ids": list(self.member_ids),
                "approval_urls": dict(self.approval_urls),
                "mandate_ids": dict(self.mandate_ids),
                "transaction_ids": dict(self.transaction_ids),
                "reserved": self.reserved,
                "captured": self.captured,
                "released": self.released,
                "outstanding": self.outstanding,
                "agent_reserved": self.agent_reserved,
                "agent_captured": self.agent_captured,
                "agent_released": self.agent_released,
                "group_status": self.group_status,
                "requote_rounds": dict(self.requote_rounds),
                "voided": self.voided,
                "partial_settlement": self.partial_settlement,
                "unknown_states": list(self.unknown_states),
                "simulated": self.simulated,
                "pooled_funds": False,
            }
        )


@dataclass(frozen=True)
class GroupAuthorization:
    """The result of one multi-principal :meth:`PravaMandates.pay_group`.

    Example::

        group = await payments.pay_group(...)
        for name, url in group.approval_urls.items():
            print(name, "->", url)   # each person taps their own passkey
    """

    ref: str
    group_id: str
    board_url: str
    total: int
    currency: str
    approval_urls: dict[str, str]
    status: str
    receipt: Receipt | None = None


@dataclass
class _Bundle:
    """Engine transport plus the state every co-located agent handle shares."""

    transport: EngineTransport
    authorizations: dict[str, Authorization] = field(default_factory=dict)
    merchant_credited: dict[str, int] = field(default_factory=dict)
    initial_headroom: dict[str, int] = field(default_factory=dict)
    # One lock per agent name. Guards the window between "read remaining
    # headroom" and "commit the reservation for it" in `_pay_principals`.
    # Without it, two `pay()` calls for the same agent that both suspend on
    # a real network round trip (an `await` that actually yields — nothing
    # in `_simulator.py` does, `GmpHttpClient` always does) can both read the
    # same starting headroom, both pass the check, and both reserve: the
    # agent authorizes more than its configured cap and `balance()` goes
    # negative with nothing in `conservation_report()` naming it. Locks are
    # per *agent*, not global, so two different agents paying at once never
    # contend.
    locks: dict[str, asyncio.Lock] = field(default_factory=dict)


_BUNDLES: dict[tuple[str, str, str], _Bundle] = {}


def _bundle_for(mode: str, base_url: str, token: str, timeout: float) -> _Bundle:
    """One transport per (mode, engine, credential) in a process.

    The scenario factories build one plugin handle *per agent* over shared
    dicts; without this the 100 handles in a marketplace run would each get
    a private engine and no group could ever span two agents.
    """
    fingerprint = hashlib.sha256(token.encode()).hexdigest()[:12] if token else "anon"
    key = (mode, base_url, fingerprint)
    bundle = _BUNDLES.get(key)
    if bundle is None:
        transport: EngineTransport = (
            SimulatedEngine()
            if mode == MODE_SIMULATED
            else GmpHttpClient(base_url, token=token, timeout=timeout)
        )
        bundle = _Bundle(transport=transport)
        _BUNDLES[key] = bundle
    return bundle


def reset_shared_state() -> None:
    """Drop every cached engine bundle. For tests and repeated in-process runs.

    Example::

        reset_shared_state()
    """
    _BUNDLES.clear()


def _slug(value: str) -> str:
    return _SLUG_RE.sub("-", value.strip().lower()).strip("-") or "merchant"


class PravaMandates:
    """Nanda Town ``payments`` layer over real Prava mandates via GMP/1.

    The constructor accepts the exact shape Nanda Town's scenario
    factories use — ``cls(agent_id, initial_balance=..., balances=...,
    payments=...)`` — so this plugin is a drop-in for ``prepaid_credits``
    in the stock ``marketplace`` scenario. Everything specific to the card
    rail is keyword-only and optional.

    Example::

        payments = PravaMandates(AgentId("buyer-0"), mode="simulated")
        quote = await payments.quote(ServiceRef("data-cleaning"))
    """

    def __init__(
        self,
        agent_id: AgentId,
        initial_balance: int = 1000,
        balances: dict[AgentId, int] | None = None,
        payments: dict[PaymentRef, Receipt] | None = None,
        *,
        mode: str | None = None,
        engine: EngineTransport | None = None,
        base_url: str | None = None,
        token: str | None = None,
        timeout: float | None = None,
        merchants: dict[str, dict[str, Any]] | None = None,
        price_book: dict[str, int] | None = None,
        tolerance_bps: int | None = None,
        settlement_currency: str | None = None,
        credit_minor_units: int | None = None,
        default_price: int = 10,
        deadline_minutes: int = 60,
        auto_approve: bool | None = None,
        await_seconds: float | None = None,
        poll_interval: float = 0.25,
    ) -> None:
        self._agent_id = agent_id
        # Not a wallet. See `balance()` — this is remaining authorization
        # headroom, a spending cap, and it is never credited by anyone else.
        self._headroom: dict[AgentId, int] = balances if balances is not None else {}
        self._headroom.setdefault(agent_id, initial_balance)
        self._receipts: dict[PaymentRef, Receipt] = payments if payments is not None else {}

        self._mode = (mode or os.environ.get("NANDA_PRAVA_MODE") or MODE_SIMULATED).lower()
        if self._mode not in (MODE_SIMULATED, MODE_LIVE):
            msg = f"mode must be {MODE_SIMULATED!r} or {MODE_LIVE!r}, got {self._mode!r}"
            raise ValueError(msg)

        resolved_base = base_url or os.environ.get("GMP_API", DEFAULT_BASE_URL)
        resolved_token = token if token is not None else os.environ.get("ENGINE_API_TOKEN", "")
        resolved_timeout = (
            timeout if timeout is not None else _env_float("NANDA_PRAVA_TIMEOUT", 10.0)
        )

        if engine is not None:
            self._bundle = _Bundle(transport=engine)
        else:
            self._bundle = _bundle_for(self._mode, resolved_base, resolved_token, resolved_timeout)
        self._bundle.initial_headroom.setdefault(str(agent_id), self._headroom.get(agent_id, 0))

        self._merchants = merchants or {}
        self._price_book = price_book or {}
        self._tolerance_bps = (
            tolerance_bps
            if tolerance_bps is not None
            else _env_int("NANDA_PRAVA_TOLERANCE_BPS", DEFAULT_TOLERANCE_BPS)
        )
        self._settlement_currency = (
            settlement_currency
            or os.environ.get("NANDA_PRAVA_CURRENCY", DEFAULT_SETTLEMENT_CURRENCY)
        ).upper()
        self._credit_minor_units = (
            credit_minor_units
            if credit_minor_units is not None
            else _env_int("NANDA_PRAVA_CREDIT_MINOR_UNITS", DEFAULT_CREDIT_MINOR_UNITS)
        )
        self._default_price = default_price
        self._deadline_minutes = deadline_minutes

        # Auto-approval stands in for a human's passkey tap. It is on by
        # default in `simulated` (there is no human and no card), and off in
        # `live` unless the operator opts in AND the engine happens to be
        # running its own Prava mock — see GmpHttpClient.approve_member,
        # which cannot succeed against a real rail.
        if auto_approve is None:
            auto_approve = self._mode == MODE_SIMULATED or _env_flag(
                "NANDA_PRAVA_AUTO_APPROVE_MOCK"
            )
        self._auto_approve = auto_approve
        if await_seconds is None:
            await_seconds = _env_float(
                "NANDA_PRAVA_AWAIT_SECONDS", 0.0 if self._mode == MODE_LIVE else 5.0
            )
        self._await_seconds = await_seconds
        self._poll_interval = poll_interval
        self._group_plans: dict[str, tuple[Principal, ...]] = {}
        self._counter = 0

    # -- introspection -------------------------------------------------------

    @property
    def mode(self) -> str:
        """``simulated`` or ``live``."""
        return self._mode

    @property
    def rail(self) -> str:
        """The settlement rail this plugin will accept. Always ``prava_mandates``."""
        return _RAIL

    def balance(self, agent: AgentId) -> int:
        """Remaining **authorization headroom** for *agent*. Not a wallet balance.

        The stock ``marketplace`` scenario calls this before every purchase,
        so the method has to exist — but what it returns here is a spending
        cap, not custody of anything. No agent's headroom is ever increased
        by another agent's payment; the only thing that can raise it is the
        release of that same agent's own uncaptured hold, exactly as a card
        authorization behaves.

        Example::

            headroom = payments.balance(AgentId("buyer-0"))
        """
        return self._headroom.get(agent, 0)

    def authorization(self, ref: PaymentRef) -> Authorization | None:
        """The mandate record behind a ``PaymentRef``, or ``None``.

        Example::

            payments.authorization(PaymentRef("p1")).approval_urls
        """
        return self._bundle.authorizations.get(str(ref))

    def conservation_report(self) -> dict[str, Any]:
        """The invariants this plugin holds itself to, computed from live state.

        Three of them, and they are the honest analogue of the pooled
        ledger's "debits equal credits":

        ``authorization_conserved``
            For every authorization, ``reserved == captured + released +
            outstanding``. No unit of authorized headroom is invented or
            lost; it is captured, released, or still on hold.
        ``no_pooled_funds``
            No agent's headroom exceeds what it started with. Value never
            flows *into* a simulator agent, because value never entered the
            simulator at all.
        ``settlement_conserved``
            Every unit captured from a card is credited to exactly one
            merchant outside the simulator. Funds are conserved across the
            boundary rather than within it.
        ``no_agent_overspent_its_cap``
            No agent's headroom ever goes negative. Distinct from
            ``no_pooled_funds`` above: that one catches being *credited* by
            someone else's payment; this one catches authorizing *more* than
            the agent's own configured cap — the failure mode a same-agent
            concurrency race produces, which ``headroom_consistent`` alone
            does not name (see ``_pay_principals``'s per-agent lock).

        Example::

            assert payments.conservation_report()["authorization_conserved"]
        """
        auths = list(self._bundle.authorizations.values())
        reserved = sum(a.reserved for a in auths)
        captured = sum(a.captured for a in auths)
        released = sum(a.released for a in auths)
        outstanding = sum(a.outstanding for a in auths)
        credited = sum(self._bundle.merchant_credited.values())

        # Every authorization splits into captured + released + still-held,
        # with no negative parts, and nothing is left held once terminal.
        conserved = all(
            a.reserved >= 0
            and a.captured >= 0
            and a.released >= 0
            and a.captured + a.released <= a.reserved
            and (a.outstanding == 0 or a.group_status not in _GROUP_STATUS_TERMINAL)
            for a in auths
        )

        # Each agent's headroom is exactly what it started with, minus its own
        # holds, plus its own releases. Nothing else can move it.
        #
        # Scoped to the ledger *this handle* shares. Nanda Town's factory hands
        # every agent handle the same `balances` dict, so that is normally all
        # of them; two independently constructed handles pointed at the same
        # engine share a transport but not a ledger, and this report will not
        # pretend to audit an agent whose balance it cannot see.
        audited = {a for a in self._bundle.initial_headroom if AgentId(a) in self._headroom}
        drift: dict[str, int] = {}
        for agent, initial in self._bundle.initial_headroom.items():
            if agent not in audited:
                continue
            expected = (
                initial
                - sum(a.agent_reserved for a in auths if a.payer == agent)
                + sum(a.agent_released for a in auths if a.payer == agent)
            )
            actual = self._headroom.get(AgentId(agent), 0)
            if actual != expected:
                drift[agent] = actual - expected
        overdrawn = [
            agent
            for agent, initial in self._bundle.initial_headroom.items()
            if agent in audited and self._headroom.get(AgentId(agent), 0) > initial
        ]
        # Distinct from `overdrawn` above: this catches an agent authorizing
        # *more* than its own configured cap, not being credited by someone
        # else's payment. `headroom_consistent` alone would miss this — a
        # race that reserves twice against the same starting balance still
        # matches "actual == initial - reserved + released" on the nose, it
        # just does it with a reserved total nobody's balance could actually
        # cover. This is the check that would have caught the concurrent
        # same-agent `pay()` race in `tests/test_concurrency.py` even before
        # that race was closed with the per-agent lock in `_pay_principals`.
        negative = [agent for agent in audited if self._headroom.get(AgentId(agent), 0) < 0]
        return {
            "reserved": reserved,
            "captured": captured,
            "released": released,
            "outstanding": outstanding,
            "merchant_credited": credited,
            "authorization_conserved": conserved,
            "no_pooled_funds": not overdrawn,
            "settlement_conserved": captured == credited,
            "headroom_consistent": not drift,
            "headroom_drift": drift,
            "agents_credited_by_others": overdrawn,
            "no_agent_overspent_its_cap": not negative,
            "agents_over_their_cap": negative,
            "merchants": dict(self._bundle.merchant_credited),
        }

    # -- Payments protocol ---------------------------------------------------

    async def quote(self, service: ServiceRef) -> Quote:
        """Price a service and state the mandate cap that would authorize it.

        The price is the real one — from the configured price book, which
        an operator points at a catalog — and the cap is that price with
        GMP/1 tolerance applied (``cap = price x (1 + tolerance_bps/10^4)``,
        §1). The cap is the number the cardholder actually consents to, and
        it is enforced at the card network rather than by this process, so
        publishing it in the quote is what makes the consent meaningful.

        Example::

            quote = await payments.quote(ServiceRef("data-cleaning"))
            quote.metadata["mandate_cap"]
        """
        price = self._price_book.get(str(service), self._default_price)
        minor = self._to_minor(price)
        cap = minor + math.ceil(minor * self._tolerance_bps / 10_000)
        return Quote(
            service=service,
            price=Money(amount=price, currency="credits"),
            ttl_seconds=self._deadline_minutes * 60,
            metadata=redact(
                {
                    "rail": _RAIL,
                    "mandate_cap": cap,
                    "quoted_minor_units": minor,
                    "settlement_currency": self._settlement_currency,
                    "tolerance_bps": self._tolerance_bps,
                    "credit_minor_units": self._credit_minor_units,
                    "pooled_funds": False,
                    "mode": self._mode,
                    "consent_model": "one mandate per principal, merchant-scoped, "
                    "amount-capped, charged once",
                }
            ),
        )

    async def pay(self, to: AgentId, amount: Money, ref: PaymentRef) -> Receipt:
        """Authorize and charge *amount* to the merchant behind *to*.

        No pooled funds move. This mints a Prava mandate scoped to that one
        merchant and capped at that one amount, and charges it once under
        ``ref`` as the idempotency key. The payee's simulator balance is
        **not** credited, because the money is not in the simulator — it is
        at the merchant.

        When a group has been declared for *ref* via :meth:`declare_group`,
        this fans out to every declared principal instead: N cards, N
        passkeys, one purchase.

        Example::

            receipt = await payments.pay(AgentId("seller-0"), Money(amount=50), PaymentRef("p1"))
        """
        principals = self._group_plans.get(str(ref))
        if principals:
            group = await self.pay_group(to, amount, ref, principals=list(principals))
            return (
                self._receipts[ref]
                if ref in self._receipts
                else self._receipt(ref, to, amount, group.status)
            )
        return await self._pay_principals(
            to, amount, ref, principals=(Principal(name=str(self._agent_id)),)
        )

    async def verify_payment(self, ref: PaymentRef) -> PaymentStatus:
        """Real mandate state, mapped onto ``PaymentStatus`` without embellishment.

        ``CONFIRMED`` is returned only when the engine's **signed receipt**
        says the rail was ``prava_mandates`` and the captured total covers
        what was owed. Not when the UI looks right, not when the group is
        merely terminal, and never on a state string this plugin does not
        recognise — an unrecognised state resolves to ``PENDING`` and is
        recorded on the authorization, because GMP/1 §4.2 is explicit that
        unknown is not failed: an unresolved charge may well have landed,
        and calling it failed invites a double charge.

        Example::

            status = await payments.verify_payment(PaymentRef("p1"))
        """
        auth = self._bundle.authorizations.get(str(ref))
        if auth is None:
            # Never authorized through this plugin. Same answer prepaid_credits
            # gives for a ref it has never seen.
            return PaymentStatus.FAILED
        if auth.voided:
            return PaymentStatus.REFUNDED

        try:
            view = await self._bundle.transport.get_group(auth.group_id)
        except (EngineError, KeyError):
            # The engine is unreachable; the charge state is genuinely unknown.
            return PaymentStatus.PENDING

        self._absorb_group_view(auth, view)

        status = str(view.get("status", ""))
        if status not in _GROUP_STATUS_KNOWN:
            auth.unknown_states = tuple(dict.fromkeys((*auth.unknown_states, status)))
            return PaymentStatus.PENDING
        if status not in _GROUP_STATUS_TERMINAL:
            return PaymentStatus.PENDING
        if status in ("aborted", "expired"):
            return PaymentStatus.REFUNDED if auth.captured == 0 else PaymentStatus.FAILED

        receipt = await self._fetch_receipt(auth)
        if receipt is None:
            # Terminal but unprovable. Refusing to confirm is the whole point.
            return PaymentStatus.PENDING
        if str(receipt.get("rail")) != _RAIL:
            # An at_venue receipt describes an agreement, not a charge.
            return PaymentStatus.PENDING

        totals = receipt.get("totals") or {}
        charged = int(totals.get("charged", 0))
        owed = int(totals.get("owed", 0))
        if charged > 0 and charged >= owed:
            return PaymentStatus.CONFIRMED
        # `partial`: some principals paid, the cart was not fully funded.
        # PaymentStatus has no word for that, so this does not claim one —
        # read `authorization(ref).captured` for what actually moved.
        auth.partial_settlement = charged > 0
        return PaymentStatus.FAILED

    async def refund(self, ref: PaymentRef) -> None:
        """Void a pre-capture authorization. Refuse to fake a post-capture reversal.

        Before capture there is nothing to give back: cancelling the group
        cancels every mandate, and nobody is ever charged. That is a void,
        and it is what this method does.

        After capture the money is at the merchant. Card charges do not roll
        back on request, and this rail has no instrument that makes them —
        so this raises :class:`RefundNotSupportedError` with the transaction
        id and the actual remedy, rather than mutating a number and
        reporting a settlement guarantee the rail does not offer. The
        dishonest version of this method is four lines shorter and wrong.

        Example::

            await payments.refund(PaymentRef("p1"))   # pre-capture: voided
        """
        auth = self._bundle.authorizations.get(str(ref))
        if auth is None:
            msg = f"Payment not found: {ref}"
            raise ValueError(msg)

        with contextlib.suppress(EngineError, KeyError):
            self._absorb_group_view(auth, await self._bundle.transport.get_group(auth.group_id))

        if auth.captured > 0:
            raise RefundNotSupportedError(
                ref=str(ref), captured=auth.captured, currency=auth.currency
            )
        if auth.voided:
            return

        if auth.group_status not in _GROUP_STATUS_TERMINAL:
            try:
                view = await self._bundle.transport.cancel_group(auth.group_id)
                self._absorb_group_view(auth, view)
            except (EngineError, KeyError, ValueError) as exc:
                # The group can commit in the gap between the refresh above
                # and this cancel call — a real race, not a hypothetical one:
                # nothing serialises "someone's passkey tap lands" against
                # "the organizer calls refund()". Re-check before reporting
                # anything, so a charge that landed during that gap is never
                # flattened into a generic "could not cancel" error. That
                # would be the dishonest failure mode here: money moved and
                # the caller was told only that an operation didn't work.
                with contextlib.suppress(EngineError, KeyError):
                    self._absorb_group_view(
                        auth, await self._bundle.transport.get_group(auth.group_id)
                    )
                if auth.captured > 0:
                    raise RefundNotSupportedError(
                        ref=str(ref), captured=auth.captured, currency=auth.currency
                    ) from None
                msg = f"could not cancel group for {ref}: {exc}"
                raise ValueError(msg) from None

        if auth.captured > 0:  # raced a commit
            raise RefundNotSupportedError(
                ref=str(ref), captured=auth.captured, currency=auth.currency
            )
        auth.voided = True
        self._release(auth)

    def can_refund(self, ref: PaymentRef) -> tuple[bool, str]:
        """Ask before raising: ``(possible, reason)``.

        Example::

            ok, why = payments.can_refund(PaymentRef("p1"))
        """
        auth = self._bundle.authorizations.get(str(ref))
        if auth is None:
            return False, "no authorization exists for this reference"
        if auth.voided:
            return False, "already voided; no card was ever charged"
        if auth.captured > 0:
            return False, (
                f"{auth.captured} {auth.currency} already captured — a settled card charge "
                "does not roll back on this rail"
            )
        return True, "pre-capture: cancelling releases every mandate and charges nobody"

    # -- the multi-principal extra -------------------------------------------

    def declare_group(self, ref: PaymentRef, principals: list[Principal]) -> None:
        """Make the next :meth:`pay` for *ref* fan out to *principals*.

        Lets an unmodified scenario — which only ever calls ``pay()`` —
        exercise the multi-principal path.

        Example::

            payments.declare_group(
                PaymentRef("p1"),
                [Principal(name="Soham"), Principal(name="Arsh")],
            )
        """
        self._group_plans[str(ref)] = tuple(principals)

    async def pay_group(
        self,
        to: AgentId,
        amount: Money,
        ref: PaymentRef,
        *,
        principals: list[Principal],
        policy: dict[str, Any] | None = None,
        tolerance_bps: int | None = None,
        deadline_minutes: int | None = None,
    ) -> GroupAuthorization:
        """One purchase, N principals, N cards, N passkeys.

        This is the capability a pooled ledger cannot express. Each
        principal gets their own merchant-scoped, amount-capped mandate on
        their own card and approves it with their own passkey; the commit
        policy decides when the set is good enough to charge. Either the
        policy is met and everyone is charged inside one window, or every
        mandate is cancelled and nobody was ever charged. Nobody fronts
        money for anybody, and the coordinating agent's own headroom is
        untouched unless it is itself one of the principals.

        Example::

            group = await payments.pay_group(
                AgentId("velvet-tickets"), Money(amount=18600), PaymentRef("g1"),
                principals=[Principal(name="Soham"), Principal(name="Arsh")],
                policy={"type": "quorum", "m": 2},
            )
        """
        return await self._pay_principals(
            to,
            amount,
            ref,
            principals=tuple(principals),
            policy=policy,
            tolerance_bps=tolerance_bps,
            deadline_minutes=deadline_minutes,
            as_group=True,
        )

    # -- internals -----------------------------------------------------------

    async def _pay_principals(
        self,
        to: AgentId,
        amount: Money,
        ref: PaymentRef,
        *,
        principals: tuple[Principal, ...],
        policy: dict[str, Any] | None = None,
        tolerance_bps: int | None = None,
        deadline_minutes: int | None = None,
        as_group: bool = False,
    ) -> Any:
        if amount.amount <= 0:
            msg = f"Payment amount must be positive: {amount.amount}"
            raise ValueError(msg)
        if not principals:
            msg = "at least one principal is required"
            raise ValueError(msg)

        total_minor = self._to_minor(amount.amount)
        tolerance = self._tolerance_bps if tolerance_bps is None else tolerance_bps
        currency = self._currency_for(amount)

        # Headroom is reserved only for principals this simulator actually
        # runs. A coordinating agent that is not itself a principal reserves
        # nothing — it fronts nothing, which is the point.
        self_share = self._self_reservation(principals, total_minor, tolerance)

        # The duplicate-ref check and the headroom check-and-reserve both
        # read shared state (`self._bundle`) and must not straddle an
        # `await`, or a second `pay()` for this same agent can observe the
        # pre-reservation balance and over-authorize. `create_group` is a
        # real suspension point in `live` mode (`GmpHttpClient` hands the
        # HTTP call to a worker thread and awaits it) even though nothing in
        # `_simulator.py` yields, so this lock is live-mode load-bearing,
        # not theoretical. See `tests/test_concurrency.py`.
        lock = self._bundle.locks.setdefault(str(self._agent_id), asyncio.Lock())
        async with lock:
            if str(ref) in self._bundle.authorizations:
                # `ref` is the provider idempotency key. Reusing one is how a
                # retry becomes a double charge.
                msg = f"Duplicate payment reference: {ref}"
                raise ValueError(msg)
            if self_share > self.balance(self._agent_id):
                msg = (
                    f"Insufficient authorization headroom: "
                    f"{self.balance(self._agent_id)} < {self_share}"
                )
                raise ValueError(msg)
            # Commit the reservation now, before releasing the lock, so a
            # concurrent `pay()` for this agent sees the reduced headroom the
            # instant it acquires the lock — not after this call's network
            # round trip finishes. `_reserve` below (against the engine's
            # real caps) only ever ratchets this up, never re-deducts it.
            self._headroom[self._agent_id] = self.balance(self._agent_id) - self_share

        body = self._group_body(
            to=to,
            total_minor=total_minor,
            currency=currency,
            principals=principals,
            policy=policy,
            tolerance_bps=tolerance,
            deadline_minutes=deadline_minutes or self._deadline_minutes,
            ref=ref,
        )
        try:
            created = await self._bundle.transport.create_group(body)
        except BaseException:
            # Nothing was minted at the engine — including when the scenario
            # itself aborted this call (`asyncio.CancelledError`, a
            # `BaseException`, not an `Exception`: a scenario timeout or a
            # cancelled task must release the hold too, not just an engine
            # error). Give the provisional hold back rather than leaving this
            # agent's headroom permanently short for a purchase that never
            # happened.
            async with lock:
                self._headroom[self._agent_id] = self.balance(self._agent_id) + self_share
            raise

        auth = Authorization(
            ref=str(ref),
            payer=str(self._agent_id),
            payee=str(to),
            group_id=str(created["group_id"]),
            board_url=str(created.get("board_url", "")),
            currency=currency,
            principals=tuple(p.name for p in principals),
            member_ids=tuple(str(m["member_id"]) for m in created.get("members", [])),
            simulated=self._mode == MODE_SIMULATED,
            # The provisional hold above already moved this agent's headroom;
            # record it here so `_reserve` below only accounts for the delta
            # against the engine's real caps instead of re-deducting it.
            agent_reserved=self_share,
        )
        self._bundle.authorizations[str(ref)] = auth

        # Reserve against the caps the engine actually minted rather than our
        # pre-flight estimate, so the ledger can never drift from the consent
        # the cardholders gave.
        first_view: dict[str, Any] | None = None
        with contextlib.suppress(EngineError, KeyError):
            first_view = await self._bundle.transport.get_group(auth.group_id)
        if first_view is None:
            self._reserve(auth, self_share, self_share)
        else:
            self._reserve(auth, *self._caps_from_view(first_view))

        # Each member's own hosted passkey ceremony. The agent cannot approve
        # for them and must not try — it hands out URLs.
        await self._drive_members(auth, first_view)

        await self._await_terminal(auth)

        status = auth.group_status
        receipt = self._receipt(ref, to, amount, status)
        if as_group:
            return GroupAuthorization(
                ref=str(ref),
                group_id=auth.group_id,
                board_url=auth.board_url,
                total=total_minor,
                currency=currency,
                approval_urls=dict(auth.approval_urls),
                status=status,
                receipt=receipt,
            )
        return receipt

    def _caps_from_view(self, view: dict[str, Any]) -> tuple[int, int]:
        """``(total live cap, this agent's slice of it)`` from a group view.

        The cap is what the card network is actually holding, so a member
        whose mandate the engine has already cancelled — dropped by a quorum
        decision, declined, expired — contributes nothing. An *armed*
        backstop is holding a second mandate on the same card, so its
        standing offer counts too.

        Both numbers are read off the engine rather than recomputed here:
        the plugin's arithmetic is not the consent, the mandate is.
        """
        total = 0
        mine = 0
        for member in view.get("members", []):
            if str(member.get("status", "")) in _MANDATE_RELEASED:
                continue
            cap = int(member.get("cap_amount") or 0)
            if member.get("backstop_armed"):
                cap += int(member.get("backstop_cap") or 0)
            total += cap
            if str(member.get("name", "")) == str(self._agent_id):
                mine += cap
        return total, mine

    async def _drive_members(self, auth: Authorization, view: dict[str, Any] | None = None) -> None:
        """Mint (or re-mint) each principal's hosted approval session.

        Deliberately re-entrant. GMP/1 §4.1 can send a member back to
        ``viewed`` with a **larger** share when the locked set shrinks — a
        *requote* — and doing so cancels the mandate they already approved,
        because consent cannot stretch. On a real engine the next actor is
        the same human tapping their passkey a second time, on a page that
        now shows the new number; here that is a second ``open_member``,
        and, when the engine is running its own Prava mock, a second
        auto-approval.

        Without this the plugin opens each session exactly once and then
        polls a group that can never move again. That is precisely what
        happened the first time ``live`` mode was pointed at the deployed
        engine — see ``docs/NANDA-EVIDENCE.md``.
        """
        if view is None:
            try:
                view = await self._bundle.transport.get_group(auth.group_id)
            except (EngineError, KeyError):
                return
        by_id = {str(m.get("member_id")): m for m in view.get("members", []) if m.get("member_id")}
        for member_id in auth.member_ids:
            status = str(by_id.get(member_id, {}).get("status", ""))
            if status and status not in _NEEDS_SESSION:
                # A session already exists. Re-approving is a no-op on an
                # already-active mandate, and impossible on a real rail.
                if self._auto_approve and status == "awaiting_approval":
                    with contextlib.suppress(EngineError, KeyError):
                        await self._bundle.transport.approve_member(member_id)
                continue
            try:
                opened = await self._bundle.transport.open_member(member_id)
            except (EngineError, KeyError):
                continue
            url = opened.get("approval_url")
            if url:
                auth.approval_urls[str(opened.get("name", member_id))] = str(url)
            if self._auto_approve:
                with contextlib.suppress(EngineError, KeyError):
                    await self._bundle.transport.approve_member(member_id)

    def _self_reservation(
        self, principals: tuple[Principal, ...], total_minor: int, tolerance_bps: int
    ) -> int:
        """Headroom this agent must put up: its own capped share, or zero."""
        paying = [p for p in principals if p.role != "backstop"]
        mine = [p for p in paying if p.name == str(self._agent_id)]
        if not mine or not paying:
            return 0
        weight_sum = sum(p.weight for p in paying) or 1
        share = total_minor * sum(p.weight for p in mine) // weight_sum
        return share + math.ceil(share * tolerance_bps / 10_000)

    def _group_body(
        self,
        *,
        to: AgentId,
        total_minor: int,
        currency: str,
        principals: tuple[Principal, ...],
        policy: dict[str, Any] | None,
        tolerance_bps: int,
        deadline_minutes: int,
        ref: PaymentRef,
    ) -> dict[str, Any]:
        merchant = self._merchant_for(to)
        paying = [p for p in principals if p.role != "backstop"] or list(principals)
        return {
            "title": f"{merchant['name']} — {ref}",
            "merchant": merchant,
            "cart": {
                "items": [
                    {
                        "sku": _slug(str(to)),
                        "name": str(to),
                        "unit_amount": total_minor,
                        "qty": 1,
                        "claimants": ["mi_all"],
                    }
                ],
                "fees": [],
                "currency": currency,
            },
            "members": [p.to_member() for p in principals],
            "policy": policy or ({"type": "all_of"} if len(paying) > 1 else {"type": "all_of"}),
            "tolerance_bps": tolerance_bps,
            "deadline_minutes": deadline_minutes,
            # Explicit: this plugin only understands the charging rail. If the
            # engine cannot honour it, verify_payment will refuse to confirm.
            "rail": _RAIL,
            "origin": "nanda-town",
            "created_by": str(self._agent_id),
        }

    def _merchant_for(self, to: AgentId) -> dict[str, Any]:
        configured = self._merchants.get(str(to))
        if configured:
            return dict(configured)
        slug = _slug(str(to))
        return {
            "id": slug,
            "name": str(to),
            "url": f"https://{slug}.merchant.example",
            "country_code_iso2": "US",
        }

    def _currency_for(self, amount: Money) -> str:
        # `credits` is not an ISO-4217 code and a card network will not take
        # it. The mapping is declared, not assumed.
        code = (amount.currency or "credits").upper()
        return code if len(code) == 3 else self._settlement_currency

    def _to_minor(self, credits_amount: int) -> int:
        return credits_amount * self._credit_minor_units

    async def _await_terminal(self, auth: Authorization) -> None:
        deadline = time.monotonic() + self._await_seconds
        while True:
            try:
                view = await self._bundle.transport.get_group(auth.group_id)
            except (EngineError, KeyError):
                return
            self._absorb_group_view(auth, view)
            if auth.group_status in _GROUP_STATUS_TERMINAL:
                await self._fetch_receipt(auth)
                return
            # A requote cancelled somebody's mandate and is waiting on a fresh
            # one. Polling alone would wait forever.
            await self._drive_members(auth, view)
            if time.monotonic() >= deadline:
                return
            await asyncio.sleep(self._poll_interval)

    def _absorb_group_view(self, auth: Authorization, view: dict[str, Any]) -> None:
        status = str(view.get("status", auth.group_status))
        auth.group_status = status
        if status not in _GROUP_STATUS_KNOWN:
            auth.unknown_states = tuple(dict.fromkeys((*auth.unknown_states, status)))

        captured = 0
        agent_captured = 0
        for member in view.get("members", []):
            member_status = str(member.get("status", ""))
            if member_status and member_status not in _MEMBER_STATUS:
                auth.unknown_states = tuple(
                    dict.fromkeys((*auth.unknown_states, f"member:{member_status}"))
                )
            round_ = int(member.get("requote_round") or 0)
            if round_:
                auth.requote_rounds[str(member.get("name", ""))] = round_
            charged = int(member.get("charged_amount") or 0)
            captured += charged
            if str(member.get("name", "")) == auth.payer:
                agent_captured += charged
        # A requote mints larger mandates, so the hold can grow after `pay()`.
        # `_reserve` only ever ratchets up: `reserved` is the peak the network
        # held, which is what `captured + released + outstanding` must equal.
        self._reserve(auth, *self._caps_from_view(view))
        self._capture(auth, captured, agent_captured)
        if auth.group_status in _GROUP_STATUS_TERMINAL:
            # Terminal: the network releases every hold it did not capture.
            self._release(auth)

    async def _fetch_receipt(self, auth: Authorization) -> dict[str, Any] | None:
        try:
            receipt = await self._bundle.transport.get_receipt(auth.group_id)
        except (EngineError, KeyError):
            return None
        if receipt is None:
            return None
        auth.rail = str(receipt.get("rail") or "") or None
        for entry in receipt.get("entries", []):
            name = str(entry.get("name", ""))
            if entry.get("mandate_id"):
                auth.mandate_ids[name] = str(entry["mandate_id"])
            if entry.get("charge_txn_id"):
                auth.transaction_ids[name] = str(entry["charge_txn_id"])
        return receipt

    # -- ledger movements ----------------------------------------------------

    def _reserve(self, auth: Authorization, total_caps: int, agent_cap: int) -> None:
        """Record the holds: the network's total, and this agent's slice of it.

        Ratchets up and is idempotent under repeated polling, so re-reading a
        group view can never double-debit an agent's headroom.
        """
        auth.reserved = max(total_caps, auth.reserved)
        delta = max(agent_cap, auth.agent_reserved) - auth.agent_reserved
        if delta <= 0:
            return
        auth.agent_reserved += delta
        self._headroom[self._agent_id] = self.balance(self._agent_id) - delta

    def _release(self, auth: Authorization) -> None:
        """Release every hold the rail no longer needs. Idempotent under polling."""
        auth.released = max(auth.reserved - auth.captured, 0)
        target = max(auth.agent_reserved - auth.agent_captured, 0)
        delta = target - auth.agent_released
        if delta <= 0:
            return
        auth.agent_released = target
        payer = AgentId(auth.payer)
        # Gives back only this agent's own uncaptured hold, and never more
        # than it reserved. No agent is ever credited by someone else's
        # payment — that is the invariant `prepaid_credits` cannot hold.
        self._headroom[payer] = self._headroom.get(payer, 0) + delta

    def _capture(self, auth: Authorization, captured_total: int, agent_captured: int) -> None:
        delta = captured_total - auth.captured
        auth.agent_captured = agent_captured
        if delta == 0:
            return
        auth.captured = captured_total
        # The money is now at the merchant, outside the simulator. No agent
        # balance is credited — there is nothing here to credit.
        self._bundle.merchant_credited[auth.payee] = (
            self._bundle.merchant_credited.get(auth.payee, 0) + delta
        )

    def _receipt(self, ref: PaymentRef, to: AgentId, amount: Money, status: str) -> Receipt:
        # Receipt has no metadata field upstream, and pydantic drops extra
        # kwargs silently — the mandate ids live on `authorization(ref)`.
        receipt = Receipt(
            ref=ref,
            payer=self._agent_id,
            payee=to,
            amount=amount,
            timestamp=time.time(),
        )
        self._receipts[ref] = receipt
        return receipt


def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default
