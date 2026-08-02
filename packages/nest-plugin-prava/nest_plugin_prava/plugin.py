# SPDX-License-Identifier: Apache-2.0
"""Prava payments plugin: real sandbox money under a human-granted policy.

Implements the NANDA Town ``Payments`` protocol (``quote``, ``pay``,
``verify_payment``, ``refund``) against a Quartermaster console, which
owns the mandate arbiter, the envelope router, and the append-only ledger.

Two locks stand between an agent and money. LOCK 2 (biometrics) is the
owner's passkey, granted ONCE per envelope before the simulation runs and
never automated here. LOCK 1 (policy) is a deterministic arbiter that
evaluates every single charge. This plugin can only spend inside an
envelope a human already approved, and only when the arbiter says so.

Example::

    payments = PravaPayments(AgentId("agent_a"), console_url="http://localhost:3000")
    quote = await payments.quote(ServiceRef("gpu-compute-small"))
    receipt = await payments.pay(AgentId("agent_b"), quote.price, PaymentRef("p1"))
    assert await payments.verify_payment(PaymentRef("p1")) is PaymentStatus.CONFIRMED
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import httpx
from nest_core.types import Money, PaymentStatus, Quote, Receipt

from nest_plugin_prava.errors import PravaPaymentError

if TYPE_CHECKING:
    from nest_core.types import AgentId, PaymentRef, ServiceRef

DEFAULT_CONSOLE_URL = "http://localhost:3000"

#: Service references the plugin knows how to price. A scenario may pass
#: its own catalogue, or use the dynamic ``gpu:<vram_gb>:<hours>`` form.
DEFAULT_SERVICE_CATALOG: dict[str, dict[str, Any]] = {
    "gpu-compute": {"vramGb": 80, "durationH": 4, "maxPriceCents": 4000},
    "gpu-compute-small": {"vramGb": 40, "durationH": 2, "maxPriceCents": 2000},
    "gpu-compute-xl": {"vramGb": 80, "durationH": 6, "maxPriceCents": 8000},
}


@dataclass(frozen=True)
class _QuoteRecord:
    """A merchant-issued price, held so ``pay`` can never invent one."""

    service: str
    run_id: str
    quote_id: str
    amount_cents: int
    currency: str
    counterparty_id: str


class PravaPayments:
    """Payments layer backed by Prava agentic credentials.

    ``initial_balance`` and ``balances`` are accepted so this class is a
    drop-in for the bundled ``marketplace`` scenario, which constructs
    payments plugins with those keywords. They are deliberately IGNORED:
    funds do not live in a simulated balance, they live in envelopes the
    owner approved with a passkey, and the network enforces the caps.

    Example::

        payments = PravaPayments(AgentId("agent_a"))
        quote = await payments.quote(ServiceRef("gpu-compute-small"))
    """

    def __init__(
        self,
        agent_id: AgentId,
        initial_balance: int = 0,
        balances: dict[AgentId, int] | None = None,
        payments: dict[PaymentRef, Receipt] | None = None,
        *,
        console_url: str | None = None,
        service_catalog: dict[str, dict[str, Any]] | None = None,
        timeout_seconds: float = 120.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._agent_id = agent_id
        self._console_url = (
            console_url or os.environ.get("QUARTERMASTER_CONSOLE_URL") or DEFAULT_CONSOLE_URL
        ).rstrip("/")
        self._catalog = dict(service_catalog or DEFAULT_SERVICE_CATALOG)
        self._timeout = timeout_seconds
        self._client = client
        self._owns_client = client is None
        # Shared with other agent handles when a scenario passes one in.
        self._payments: dict[PaymentRef, Receipt] = payments if payments is not None else {}
        self._quotes_by_service: dict[str, _QuoteRecord] = {}
        self._quotes_by_amount: dict[int, _QuoteRecord] = {}
        self._capacity_cents = 0

    def balance(self, agent: AgentId) -> int:
        """Spendable capacity right now, in cents.

        Not part of the ``Payments`` protocol, but the bundled
        ``marketplace`` scenario calls it before buying, so a drop-in
        replacement needs it.

        There is no play-money balance to report. This answers the only
        question worth asking: how much could actually be drawn at this
        moment? That is the funding still available in envelopes whose
        cycle is open, capped by the policy mandate's remaining cumulative
        headroom. It is not a promise: the arbiter still rules on every
        charge.

        Example::

            spendable = payments.balance(AgentId("agent_a"))
        """
        try:
            with httpx.Client(timeout=10.0) as client:
                data = client.get(f"{self._console_url}/api/portfolio").json()
        except (httpx.HTTPError, ValueError):
            return self._capacity_cents

        envelopes = data.get("envelopes", [])
        open_capacity = sum(
            int(env.get("per_charge_cap_cents", 0))
            for env in envelopes
            if env.get("cycle") == "OPEN"
        )
        policy = data.get("policy") or {}
        cap_cents = policy.get("cap_cents")
        if cap_cents is None:
            headroom = open_capacity
        else:
            headroom = int(cap_cents) - int(policy.get("cumulative_cents", 0))
        self._capacity_cents = max(0, min(open_capacity, headroom))
        return self._capacity_cents

    # ------------------------------------------------------------------
    # Payments protocol
    # ------------------------------------------------------------------

    async def quote(self, service: ServiceRef) -> Quote:
        """Ask the merchant what a service costs, through the console registry.

        The price is the merchant's, computed by its own published rule. The
        plugin never sets or adjusts it.

        Example::

            q = await payments.quote(ServiceRef("gpu-compute-small"))
        """
        need = self._need_for(str(service))
        data = await self._request("POST", "/api/nanda/quote", json=need)
        record = _QuoteRecord(
            service=str(service),
            run_id=str(data["runId"]),
            quote_id=str(data["quoteId"]),
            amount_cents=int(data["amountCents"]),
            currency=str(data["currency"]),
            counterparty_id=str(data["counterpartyId"]),
        )
        self._quotes_by_service[record.service] = record
        self._quotes_by_amount[record.amount_cents] = record
        return Quote(
            service=service,
            price=Money(amount=record.amount_cents, currency=record.currency),
            ttl_seconds=int(data.get("ttlSeconds", 300)),
            metadata={
                "run_id": record.run_id,
                "quote_id": record.quote_id,
                "counterparty_id": record.counterparty_id,
                "pricing_rule": data.get("pricingRule"),
                "attributes": data.get("attributes", {}),
                "environment": "SANDBOX",
            },
        )

    async def pay(self, to: AgentId, amount: Money, ref: PaymentRef) -> Receipt:
        """Settle a quoted price against a pre-approved envelope.

        Routes to an envelope with cycle capacity, mints a one-time
        merchant-scoped credential, pays the merchant, and appends to the
        ledger. No passkey is requested and none is simulated.

        Raises:
            PravaPaymentError: if the arbiter refuses the charge
                (``POLICY_REFUSE`` / ``POLICY_NEEDS_HUMAN``), if no envelope
                has cycle capacity (``NO_ENVELOPE_CAPACITY``), or if the
                amount was never quoted (``NO_QUOTE`` / ``AMOUNT_MISMATCH``).

        Example::

            receipt = await payments.pay(AgentId("agent_b"), quote.price, PaymentRef("p1"))
        """
        if amount.amount <= 0:
            msg = f"Payment amount must be positive: {amount.amount}"
            raise PravaPaymentError("INVALID_AMOUNT", msg)
        if ref in self._payments:
            msg = f"Duplicate payment reference: {ref}"
            raise PravaPaymentError("DUPLICATE_REF", msg)

        record = self._quotes_by_amount.get(amount.amount)
        if record is None:
            msg = (
                f"No quote for {amount.amount} {amount.currency}; call quote() first. "
                "Prices come from the merchant, never from the caller."
            )
            raise PravaPaymentError("NO_QUOTE", msg, {"amount": amount.amount})

        data = await self._request(
            "POST",
            "/api/nanda/pay",
            json={
                "ref": str(ref),
                "runId": record.run_id,
                "quoteId": record.quote_id,
                "payer": str(self._agent_id),
                "payee": str(to),
                "amountCents": amount.amount,
            },
        )
        receipt = Receipt(
            ref=ref,
            payer=self._agent_id,
            payee=to,
            amount=Money(amount=int(data["amountCents"]), currency=str(data["currency"])),
            timestamp=time.time(),
        )
        self._payments[ref] = receipt
        return receipt

    async def verify_payment(self, ref: PaymentRef) -> PaymentStatus:
        """Verify a payment against the console's append-only ledger.

        ``CONFIRMED`` is returned only when a ledger row backs the payment,
        so verification cannot pass on a cached receipt alone.

        Example::

            status = await payments.verify_payment(PaymentRef("p1"))
        """
        data = await self._request("GET", "/api/nanda/payment", params={"ref": str(ref)})
        status = str(data.get("status"))
        if status == "confirmed":
            return PaymentStatus.CONFIRMED if data.get("ledgerConfirmed") else PaymentStatus.PENDING
        return PaymentStatus.FAILED

    async def refund(self, ref: PaymentRef) -> None:
        """Refunds are not supported and never silently succeed.

        Prava exposes no refund on the mandate-charge surface Quartermaster
        uses, so this raises rather than pretending. Reverse a settled
        charge out of band with the merchant.

        Raises:
            PravaPaymentError: always, with code ``REFUND_NOT_SUPPORTED``.

        Example::

            with pytest.raises(PravaPaymentError):
                await payments.refund(PaymentRef("p1"))
        """
        msg = (
            "Prava mandate charges cannot be refunded through this adapter; "
            "settle reversals out of band with the merchant."
        )
        raise PravaPaymentError("REFUND_NOT_SUPPORTED", msg, {"ref": str(ref)})

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def aclose(self) -> None:
        """Close the HTTP client if this instance created it.

        Example::

            await payments.aclose()
        """
        if self._client is not None and self._owns_client:
            await self._client.aclose()
            self._client = None

    def _need_for(self, service: str) -> dict[str, Any]:
        """Map a ServiceRef onto a capacity need the registry understands."""
        spec = self._catalog.get(service)
        if spec is None and service.startswith("gpu:"):
            parts = service.split(":")
            if len(parts) >= 3:
                try:
                    spec = {
                        "vramGb": int(parts[1]),
                        "durationH": int(parts[2]),
                        "maxPriceCents": int(parts[3]) if len(parts) > 3 else 100_000,
                    }
                except ValueError:
                    spec = None
        if spec is None:
            known = ", ".join(sorted(self._catalog))
            msg = f"Unknown service {service!r}; known services: {known}"
            raise PravaPaymentError("UNKNOWN_SERVICE", msg, {"service": service})
        need = dict(spec)
        need.setdefault("deadline", _deadline_iso())
        return need

    def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self._timeout)
            self._owns_client = True
        return self._client

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        url = f"{self._console_url}{path}"
        try:
            response = await self._http().request(method, url, json=json, params=params)
        except httpx.HTTPError as exc:
            msg = f"console unreachable at {url}: {exc}"
            raise PravaPaymentError("CONSOLE_UNREACHABLE", msg) from exc

        try:
            payload = response.json()
        except ValueError as exc:
            msg = f"console returned non-JSON ({response.status_code}) from {path}"
            raise PravaPaymentError("BAD_RESPONSE", msg) from exc

        if response.is_success:
            return dict(payload)

        error = payload.get("error", {}) if isinstance(payload, dict) else {}
        raise PravaPaymentError(
            str(error.get("code", f"HTTP_{response.status_code}")),
            str(error.get("message", f"console returned {response.status_code}")),
            dict(error.get("details", {})),
        )


def _deadline_iso(hours_ahead: int = 12) -> str:
    """ISO 8601 deadline used when a catalogue entry does not set one."""
    return (datetime.now(UTC) + timedelta(hours=hours_ahead)).isoformat()
