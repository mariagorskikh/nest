# SPDX-License-Identifier: Apache-2.0
"""Exercise `live` mode against a real GMP/1 engine, over a real socket.

Everything else in this repository can run with no network at all: the
`simulated` transport is in-process and deterministic, and the test suite
injects fake transports. That leaves exactly one thing unproven — that
:class:`nanda_town_prava.client.GmpHttpClient` can actually talk to the
engine. This script is the thing that proves it.

    export GMP_API=https://engine-production-e6fa.up.railway.app
    export ENGINE_API_TOKEN=...            # never printed by this script
    python scripts/live_check.py

The script asks the engine which Prava adapter it is running and grades
itself accordingly, because the two cases have genuinely different correct
answers:

``prava_adapter: mock``
    The engine registers ``/mock/pay/{session}/approve``. Auto-approval can
    stand in for the passkey tap, so a group can reach ``committed`` inside
    one process and every charge assertion below is expected to hold.

``prava_adapter: sandbox`` (or any real key)
    Approval URLs point at Prava's own hosted ceremony. ``approve_member()``
    finds no ``/mock/pay/`` marker, returns ``False`` without sending
    anything, and the mandates stay pending until a human taps a passkey.
    The **correct** result is then ``PENDING`` with nothing captured — and
    that is what is asserted. There is no code path in this package that can
    approve a real mandate, and this run is where you watch it fail to.

Checks, in order:

1. ``GET /health`` — which adapter is the engine actually running?
2. single principal: ``pay()`` → ``verify_payment()``
3. four principals, four cards, four passkeys, one merchant, one purchase
4. ``quorum(3)`` of four plus a backstop, which forces a real GMP/1 requote
   cascade — the path that broke the first time this script was run
   (mock adapter only: a requote needs a second round of approvals)
5. unknown states — an unrecognised status string, and a group the engine
   has never heard of. Both must be ``PENDING``; neither may be
   ``CONFIRMED`` and neither may be ``FAILED``.
6. ``refund()`` pre-charge — cancels every mandate, charges nobody. Works on
   either adapter: cancelling needs no human.
7. ``refund()`` post-charge — refuses, because a settled card charge does not
   roll back (only reachable once something has actually been charged).

On a real adapter the script cancels every group it created before exiting,
so it never leaves a live mandate session dangling.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nanda_town_prava import (  # noqa: E402
    PravaMandates,
    Principal,
    RefundNotSupportedError,
)
from nanda_town_prava.client import EngineHTTPError, GmpHttpClient  # noqa: E402
from nanda_town_prava.plugin import reset_shared_state  # noqa: E402
from nest_sdk import AgentId, Money, PaymentRef, PaymentStatus  # noqa: E402

BASE = os.environ.get("GMP_API", "http://localhost:4100")
TOKEN = os.environ.get("ENGINE_API_TOKEN", "")
RUN = os.environ.get("LIVE_RUN_ID") or time.strftime("%H%M%S")
FAILURES: list[str] = []
ADAPTER = "unknown"
# Groups created against a real rail, cancelled on the way out.
OPEN_GROUPS: list[tuple[PravaMandates, PaymentRef]] = []


def mock() -> bool:
    """Is the engine running its own Prava simulator?"""
    return ADAPTER == "mock"


def head(n: int, title: str) -> None:
    print(f"\n=== {n}. {title} " + "=" * max(0, 60 - len(title)))


def check(label: str, ok: bool, detail: str = "") -> None:
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}{(' — ' + detail) if detail else ''}")
    if not ok:
        FAILURES.append(label)


def skip(label: str, why: str) -> None:
    print(f"  [SKIP] {label} — {why}")


def live(agent: str, **kw: Any) -> PravaMandates:
    return PravaMandates(
        AgentId(agent),
        initial_balance=100_000,
        mode="live",
        base_url=BASE,
        token=TOKEN,
        timeout=30.0,
        **kw,
    )


def show_members(view: dict[str, Any]) -> None:
    print("  per-member state from the engine:")
    for m in view.get("members", []):
        print(
            f"    {str(m.get('name')):<8} role={str(m.get('role')):<8} "
            f"status={str(m.get('status')):<18} share={m.get('share_amount')} "
            f"cap={m.get('cap_amount')} charged={m.get('charged_amount')} "
            f"requote_round={m.get('requote_round')}"
        )


async def cannot_self_approve(payments: PravaMandates, member_id: str) -> None:
    """On a real rail, ask the plugin to approve and watch it refuse."""
    approved = await payments._bundle.transport.approve_member(member_id)  # noqa: SLF001
    print(f"  approve_member({member_id}) -> {approved}")
    check("the plugin cannot approve a real mandate", approved is False, str(approved))


# ---------------------------------------------------------------------------
# 1. what is on the other end
# ---------------------------------------------------------------------------


def check_health() -> None:
    global ADAPTER
    head(1, "GET /health")
    with urllib.request.urlopen(f"{BASE}/health", timeout=30) as r:
        body = json.loads(r.read().decode())
    print(f"  {json.dumps(body, indent=2)}")
    check("engine reachable over HTTPS", bool(body.get("ok")))
    ADAPTER = str(body.get("prava_adapter", "unknown"))
    print(
        f"  adapter = {ADAPTER!r}: "
        + (
            "the engine's own Prava simulator. No real card is charged anywhere below, "
            "and auto-approval can stand in for the passkey tap."
            if mock()
            else "a REAL Prava key. Approval URLs are Prava's own hosted ceremony, "
            "nothing below can be approved without a human, and the correct answer "
            "to every charge question is PENDING."
        )
    )


# ---------------------------------------------------------------------------
# 2. single principal
# ---------------------------------------------------------------------------


async def check_single() -> tuple[PravaMandates, PaymentRef]:
    head(2, "single principal: pay() -> verify_payment()")
    payments = live("buyer-0", auto_approve=True, await_seconds=30.0 if mock() else 5.0)
    ref = PaymentRef(f"live-single-{RUN}")

    t0 = time.monotonic()
    receipt = await payments.pay(AgentId("velvet-tickets"), Money(amount=1200), ref)
    elapsed = time.monotonic() - t0

    auth = payments.authorization(ref)
    assert auth is not None
    print(
        f"  receipt: ref={receipt.ref} payer={receipt.payer} payee={receipt.payee} "
        f"amount={receipt.amount.amount} {receipt.amount.currency}"
    )
    print(f"  group_id     : {auth.group_id}")
    print(f"  board_url    : {auth.board_url}")
    print(f"  approval_urls: {json.dumps(auth.approval_urls, indent=2)}")
    print(
        f"  reserved={auth.reserved} captured={auth.captured} released={auth.released} "
        f"outstanding={auth.outstanding}"
    )
    print(f"  group_status={auth.group_status} rail={auth.rail} simulated={auth.simulated}")
    print(f"  mandate ids  : {json.dumps(auth.mandate_ids)}")
    print(f"  txn ids      : {json.dumps(auth.transaction_ids)}")
    print(f"  elapsed      : {elapsed:.2f}s")

    status = await payments.verify_payment(ref)
    print(f"  verify_payment -> {status}")
    check("simulated flag is False in live mode", auth.simulated is False)

    if mock():
        check("group committed", auth.group_status == "committed", auth.group_status)
        check("verify_payment is CONFIRMED", status is PaymentStatus.CONFIRMED)
        check("receipt rail is prava_mandates", auth.rail == "prava_mandates", str(auth.rail))
        check("captured covers the cart", auth.captured == 1200, str(auth.captured))
        check("a real charge txn id exists", bool(auth.transaction_ids))
    else:
        OPEN_GROUPS.append((payments, ref))
        url = next(iter(auth.approval_urls.values()), "")
        check(
            "the approval URL is Prava's own hosted ceremony",
            "/mock/pay/" not in url and url.startswith("https://"),
            url,
        )
        await cannot_self_approve(payments, auth.member_ids[0])
        check(
            "verify_payment is PENDING, waiting on a human",
            status is PaymentStatus.PENDING,
            str(status),
        )
        check("nothing was captured", auth.captured == 0, str(auth.captured))
        check("never CONFIRMED without a receipt", auth.rail is None, str(auth.rail))

    report = payments.conservation_report()
    print(f"  conservation_report: {json.dumps(report, indent=2)}")
    check("authorization_conserved", report["authorization_conserved"])
    check("no_pooled_funds", report["no_pooled_funds"])
    check("settlement_conserved", report["settlement_conserved"])
    check("headroom_consistent", report["headroom_consistent"])
    return payments, ref


# ---------------------------------------------------------------------------
# 3. the differentiator
# ---------------------------------------------------------------------------


async def check_group() -> None:
    head(3, "four principals, four cards, four passkeys, ONE purchase")
    payments = live("organizer", auto_approve=True, await_seconds=45.0 if mock() else 5.0)
    ref = PaymentRef(f"live-group-{RUN}")

    group = await payments.pay_group(
        AgentId("velvet-tickets"),
        Money(amount=18600),
        ref,
        principals=[
            Principal(name="Soham"),
            Principal(name="Arsh"),
            Principal(name="Dev"),
            Principal(name="Maya"),
        ],
        policy={"type": "all_of"},
    )

    print(f"  group_id : {group.group_id}")
    print(f"  board_url: {group.board_url}")
    print(f"  total    : {group.total} {group.currency}")
    print(f"  status   : {group.status}")
    print("  one approval URL per principal — each taps their own passkey on their own phone:")
    for name, url in group.approval_urls.items():
        print(f"    {name:<8} -> {url}")

    auth = payments.authorization(ref)
    assert auth is not None
    view = await payments._bundle.transport.get_group(auth.group_id)  # noqa: SLF001
    show_members(view)

    status = await payments.verify_payment(ref)
    print(f"  verify_payment -> {status}")
    print(f"  reserved={auth.reserved} captured={auth.captured} released={auth.released}")
    print(
        f"  organizer headroom={payments.balance(AgentId('organizer'))} "
        f"(it is not a principal, so it fronts nothing)"
    )

    check("four members were created", len(view.get("members", [])) == 4)
    check(
        "four distinct approval URLs",
        len(set(group.approval_urls.values())) == 4,
        f"{len(set(group.approval_urls.values()))} distinct",
    )
    check(
        "organizer's own headroom untouched",
        payments.balance(AgentId("organizer")) == 100_000,
        str(payments.balance(AgentId("organizer"))),
    )

    if mock():
        receipt = await payments._bundle.transport.get_receipt(auth.group_id)  # noqa: SLF001
        if receipt:
            print(f"  receipt.rail   : {receipt.get('rail')}")
            print(f"  receipt.totals : {json.dumps(receipt.get('totals'))}")
            print(f"  receipt.status : {receipt.get('status')}")
            print(f"  settlement_disclosure: {receipt.get('settlement_disclosure')}")
            print(f"  chain_head     : {receipt.get('chain_head')}")
            print(f"  signature len  : {len(str(receipt.get('signature') or ''))} hex chars")
            for e in receipt.get("entries", []):
                print(
                    f"    entry {str(e.get('name')):<8} cap={e.get('cap_amount')} "
                    f"quoted={e.get('quoted_share')} charged={e.get('charged_amount')} "
                    f"mandate={e.get('mandate_id')} txn={e.get('charge_txn_id')} "
                    f"outcome={e.get('outcome')}"
                )
        check("group committed", auth.group_status == "committed", auth.group_status)
        check("verify_payment is CONFIRMED", status is PaymentStatus.CONFIRMED)
        check("captured equals the cart total", auth.captured == 18600, str(auth.captured))
        check(
            "one distinct mandate per principal",
            len(set(auth.mandate_ids.values())) == 4,
            json.dumps(auth.mandate_ids),
        )
    else:
        OPEN_GROUPS.append((payments, ref))
        check(
            "every approval URL is Prava's own hosted ceremony",
            all("/mock/pay/" not in u for u in group.approval_urls.values()),
        )
        await cannot_self_approve(payments, auth.member_ids[0])
        check(
            "verify_payment is PENDING, waiting on four humans",
            status is PaymentStatus.PENDING,
            str(status),
        )
        check("nothing was captured", auth.captured == 0, str(auth.captured))

    report = payments.conservation_report()
    print(f"  conservation_report: {json.dumps(report, indent=2)}")
    check("no agent was credited by another", report["no_pooled_funds"])
    check("settlement_conserved across the boundary", report["settlement_conserved"])
    check("headroom_consistent", report["headroom_consistent"])


async def check_requote() -> None:
    """quorum(m<n) forces a requote cascade. This is where the plugin broke."""
    head(4, "quorum(3) of 4 + a backstop — the GMP/1 requote cascade")
    if not mock():
        skip(
            "requote cascade",
            "a requote needs a second round of passkey taps, and this engine "
            "holds a real Prava key. Covered on the mock adapter and by "
            "tests/test_group_payment.py::test_a_requote_cascade_is_followed_to_a_commit",
        )
        return

    payments = live("organizer-2", auto_approve=True, await_seconds=60.0)
    ref = PaymentRef(f"live-quorum-{RUN}")

    group = await payments.pay_group(
        AgentId("velvet-tickets"),
        Money(amount=18600),
        ref,
        principals=[
            Principal(name="Soham"),
            Principal(name="Arsh"),
            Principal(name="Dev"),
            Principal(name="Maya", role="backstop", backstop_cap=6000),
        ],
        policy={"type": "quorum", "m": 3},
    )
    auth = payments.authorization(ref)
    assert auth is not None
    view = await payments._bundle.transport.get_group(auth.group_id)  # noqa: SLF001
    print(f"  group_id : {group.group_id}   status: {group.status}")
    print(f"  decision : {view.get('decision_note')!r}")
    show_members(view)
    status = await payments.verify_payment(ref)
    print(f"  verify_payment -> {status}")
    print(f"  requote_rounds recorded by the plugin: {json.dumps(auth.requote_rounds)}")
    print(
        f"  reserved={auth.reserved} captured={auth.captured} released={auth.released} "
        f"outstanding={auth.outstanding}"
    )
    check(
        "the engine really did requote", bool(auth.requote_rounds), json.dumps(auth.requote_rounds)
    )
    check("group committed after the requote", auth.group_status == "committed", auth.group_status)
    check("verify_payment is CONFIRMED", status is PaymentStatus.CONFIRMED)
    check("the merchant got the whole cart", auth.captured == 18600, str(auth.captured))
    report = payments.conservation_report()
    check("authorization_conserved across a requote", report["authorization_conserved"])
    check("no_pooled_funds", report["no_pooled_funds"])
    check("settlement_conserved", report["settlement_conserved"])


# ---------------------------------------------------------------------------
# 5. unknown states
# ---------------------------------------------------------------------------


class _StubHandler(BaseHTTPRequestHandler):
    """The smallest thing that speaks GMP/1 badly, over a real socket.

    The deployed engine has eight group statuses and this plugin knows all
    eight, so the engine cannot produce an unrecognised one. To prove the
    unknown-state path over real HTTP rather than an injected transport, we
    stand up a stdlib server that returns a status no version of GMP/1 has
    ever defined and point `GmpHttpClient` at it.
    """

    status = "quantum_superposition"

    def log_message(self, *_: Any) -> None:  # keep the transcript clean
        return

    def _send(self, code: int, body: dict[str, Any]) -> None:
        raw = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self) -> None:  # noqa: N802
        if self.path == "/v1/groups":
            self._send(
                201,
                {
                    "group_id": "g_stub",
                    "board_url": "http://127.0.0.1/board",
                    "members": [{"member_id": "mem_stub", "name": "buyer-0", "role": "payer"}],
                },
            )
        elif self.path.endswith("/open"):
            self._send(
                200,
                {
                    "member_id": "mem_stub",
                    "name": "buyer-0",
                    "approval_url": "http://127.0.0.1/a/mem_stub",
                },
            )
        else:
            self._send(404, {"error": "not found"})

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/v1/groups/g_stub":
            self._send(
                200,
                {
                    "group_id": "g_stub",
                    "status": self.status,
                    "members": [
                        {
                            "member_id": "mem_stub",
                            "name": "buyer-0",
                            "status": "levitating",
                            "cap_amount": 53,
                            "charged_amount": 0,
                            "role": "payer",
                        }
                    ],
                },
            )
        else:
            self._send(404, {"error": "no receipt yet — group is not terminal"})


async def check_unknown() -> None:
    head(5, "unknown states over a real socket")

    server = ThreadingHTTPServer(("127.0.0.1", 0), _StubHandler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"  stub engine on http://127.0.0.1:{port} (real socket, deliberately wrong)")
    try:
        payments = PravaMandates(
            AgentId("buyer-0"),
            initial_balance=1000,
            mode="live",
            base_url=f"http://127.0.0.1:{port}",
            token="",
            auto_approve=False,
            await_seconds=0.0,
        )
        ref = PaymentRef(f"live-unknown-{RUN}")
        await payments.pay(AgentId("seller-0"), Money(amount=50), ref)
        status = await payments.verify_payment(ref)
        auth = payments.authorization(ref)
        assert auth is not None
        print(f"  engine said status={_StubHandler.status!r}, member status='levitating'")
        print(f"  verify_payment -> {status}")
        print(f"  unknown_states recorded: {auth.unknown_states}")
        check("unrecognised group status is PENDING, not FAILED", status is PaymentStatus.PENDING)
        check(
            "unrecognised group status is recorded", "quantum_superposition" in auth.unknown_states
        )
        check("unrecognised member status is recorded", "member:levitating" in auth.unknown_states)
    finally:
        server.shutdown()

    print()
    client = GmpHttpClient(BASE, token=TOKEN, timeout=30.0)
    try:
        await client.get_group("g_this_group_does_not_exist")
        check("a nonexistent group 404s", False, "no error raised")
    except EngineHTTPError as exc:
        print(f"  GET {BASE}/v1/groups/g_this_group_does_not_exist -> {exc}")
        check("a nonexistent group 404s cleanly", exc.status == 404, str(exc.status))
    print(
        f"  receipt for a nonexistent group -> "
        f"{await client.get_receipt('g_this_group_does_not_exist')} (404 is not an error here)"
    )

    # And the honest end of the same rule: an engine that is simply gone.
    dark = PravaMandates(
        AgentId("buyer-0"),
        initial_balance=1000,
        mode="live",
        base_url="http://127.0.0.1:1",
        token="",
        auto_approve=False,
        await_seconds=0.0,
    )
    dark._bundle.authorizations["gone"] = _orphan_auth()  # noqa: SLF001
    status = await dark.verify_payment(PaymentRef("gone"))
    print(f"  unreachable engine (127.0.0.1:1) -> verify_payment = {status}")
    check("unreachable engine is PENDING, never FAILED", status is PaymentStatus.PENDING)


def _orphan_auth() -> Any:
    from nanda_town_prava.plugin import Authorization

    return Authorization(
        ref="gone",
        payer="buyer-0",
        payee="seller-0",
        group_id="g_gone",
        board_url="",
        currency="USD",
        principals=("buyer-0",),
    )


# ---------------------------------------------------------------------------
# 6 + 7. refunds
# ---------------------------------------------------------------------------


async def check_refund_precharge() -> None:
    head(6, "refund() pre-charge — cancels every mandate, charges nobody")
    payments = live("buyer-1", auto_approve=False, await_seconds=0.0)
    ref = PaymentRef(f"live-void-{RUN}")

    await payments.pay(AgentId("velvet-tickets"), Money(amount=4200), ref)
    auth = payments.authorization(ref)
    assert auth is not None
    print(
        f"  group_id={auth.group_id} status={auth.group_status} "
        f"reserved={auth.reserved} captured={auth.captured}"
    )
    print("  nobody has tapped a passkey; approval URLs are still outstanding:")
    for name, url in auth.approval_urls.items():
        print(f"    {name} -> {url}")

    ok, why = payments.can_refund(ref)
    print(f"  can_refund -> {ok}: {why}")
    check("can_refund says yes before capture", ok)

    await payments.refund(ref)
    status = await payments.verify_payment(ref)
    view = await payments._bundle.transport.get_group(auth.group_id)  # noqa: SLF001
    print(
        f"  after refund(): group status={view.get('status')} "
        f"decision_note={view.get('decision_note')!r}"
    )
    for m in view.get("members", []):
        print(
            f"    {str(m.get('name')):<8} status={str(m.get('status')):<10} "
            f"charged={m.get('charged_amount')}"
        )
    print(f"  verify_payment -> {status}")
    print(f"  headroom back to {payments.balance(AgentId('buyer-1'))}")
    check("engine group is aborted", str(view.get("status")) == "aborted", str(view.get("status")))
    check("nothing was captured", auth.captured == 0, str(auth.captured))
    check("verify_payment is REFUNDED", status is PaymentStatus.REFUNDED)
    check(
        "headroom fully released",
        payments.balance(AgentId("buyer-1")) == 100_000,
        str(payments.balance(AgentId("buyer-1"))),
    )


async def check_refund_postcharge(payments: PravaMandates, ref: PaymentRef) -> None:
    head(7, "refund() post-charge — refuses, and says why")
    auth = payments.authorization(ref)
    assert auth is not None
    if auth.captured == 0:
        skip(
            "post-charge refund",
            "nothing was captured on this adapter, because no human tapped a "
            "passkey. Covered on the mock adapter and by "
            "tests/test_refund_honesty.py",
        )
        return
    ok, why = payments.can_refund(ref)
    print(f"  can_refund -> {ok}: {why}")
    check("can_refund says no after capture", not ok)
    try:
        await payments.refund(ref)
        check("refund() raises after capture", False, "it returned instead")
    except RefundNotSupportedError as exc:
        print(f"  RefundNotSupportedError: {exc}")
        print(f"    .ref={exc.ref} .captured={exc.captured} .currency={exc.currency}")
        print(f"    .remedy={exc.remedy}")
        print(f"    transaction ids to refund against: {json.dumps(auth.transaction_ids)}")
        check("refund() raises RefundNotSupportedError after capture", True)
        check("the exception carries the captured amount", exc.captured == 1200, str(exc.captured))
    status = await payments.verify_payment(ref)
    print(f"  verify_payment is still {status} — the charge stands")
    check("still CONFIRMED after a refused refund", status is PaymentStatus.CONFIRMED)


async def cleanup() -> None:
    """Never leave a live mandate session dangling on a real rail."""
    if not OPEN_GROUPS:
        return
    print("\n=== cleanup: cancelling the groups this run opened " + "=" * 15)
    for payments, ref in OPEN_GROUPS:
        auth = payments.authorization(ref)
        try:
            await payments.refund(ref)
            print(
                f"  cancelled {auth.group_id if auth else ref} "
                f"({await payments.verify_payment(ref)})"
            )
        except Exception as exc:  # noqa: BLE001 - cleanup must not mask results
            print(f"  could not cancel {ref}: {type(exc).__name__}: {exc}")


# ---------------------------------------------------------------------------


async def main() -> int:
    print(f"engine  : {BASE}")
    print(f"token   : {'present' if TOKEN else 'ABSENT — /v1/groups will 401'}")
    print(f"run id  : {RUN}")
    reset_shared_state()

    check_health()
    payments, ref = await check_single()
    await check_group()
    await check_requote()
    await check_unknown()
    await check_refund_precharge()
    await check_refund_postcharge(payments, ref)
    await cleanup()

    print("\n" + "=" * 66)
    print(f"adapter: {ADAPTER}")
    if FAILURES:
        print(f"{len(FAILURES)} FAILED:")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print("all checks passed against a live engine over HTTP")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
