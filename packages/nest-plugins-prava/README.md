# nest-plugins-prava

Reusable **Prava** payments adapter for [Nanda Town](https://nandatown.projectnanda.org).

Implements the NANDA Town `Payments` protocol (`quote` / `pay` / `verify_payment` / `refund`) and bridges it to Prava's Agentic Payments Sandbox:

`create session → payment-result → report-status`

## Why this exists

NANDA Town agents speak a synchronous ledger API. Prava speaks sessions, credentials, and report-status. This plugin is the production-minded adapter between them: local budget locks, idempotent `PaymentRef`s, typed failures, secret scrubbing, and a dual transport (`mock` / `live` / `hybrid`).

## Install

From the nandatown repo root:

```bash
uv sync
# or
pip install -e packages/nest-plugins-prava
```

Confirm discovery:

```bash
nest plugins list | grep -A2 payments
# should include: prava
```

## Environment

| Variable | Default | Meaning |
|---|---|---|
| `PRAVA_MODE` | `mock` | `mock` \| `live` \| `hybrid` |
| `PRAVA_API_KEY` | _(required for live/hybrid)_ | `sk_test_...` sandbox key |
| `PRAVA_BASE_URL` | `https://sandbox.api.prava.space` | API host |

- **mock** — fully deterministic, no network. Use for CI + scenarios.
- **live** — real HTTP to Prava (needs browser/passkey to finish checkout).
- **hybrid** — real `POST /v1/sessions` (sandbox evidence) + headless completion for agent sims.

## Quick start

```python
import asyncio
from nest_plugins_prava import PravaPayments
from nest_sdk import AgentId, Money, PaymentRef, PaymentStatus, ServiceRef

async def main() -> None:
    pay = PravaPayments(AgentId("alice"), initial_balance=1000)
    quote = await pay.quote(ServiceRef("compute-slot"))
    receipt = await pay.pay(AgentId("bob"), quote.price, PaymentRef("buy-1"))
    assert await pay.verify_payment(PaymentRef("buy-1")) is PaymentStatus.CONFIRMED
    print(receipt)

asyncio.run(main())
```

## Scenario

```bash
PRAVA_MODE=mock nest run scenarios/prava_marketplace.yaml -o traces/prava.jsonl
```

## Tests

```bash
pytest packages/nest-plugins-prava/tests -v
# optional live session create (needs PRAVA_API_KEY):
PRAVA_API_KEY=sk_test_... pytest packages/nest-plugins-prava/tests/test_sandbox_live.py -m live -v
```

## Protocol mapping

| NANDA | Prava |
|---|---|
| `quote(service)` | local priced quote + `prava_amount` metadata |
| `pay(to, amount, ref)` | budget lock → `POST /v1/sessions` → poll result → `report-status` |
| `verify_payment(ref)` | local state (+ optional poll) |
| `refund(ref)` | local ledger reverse (confirmed only) |

Currency mapping default: **1 credit = $0.01 USD**.

## Failure handling

Typed errors in `nest_plugins_prava.errors`:

- `InsufficientFundsError` — local budget gate; **never** calls Prava
- `DuplicatePaymentRefError` — conflicting reuse of `PaymentRef`
- `PravaAuthError` / `PravaSessionExpiredError` / `PravaTimeoutError`
- `PravaDeclinedError` — report-status `DECLINED` / failed result
- `QuoteExpiredError` / `PaymentNotFoundError`

Idempotency: retrying `pay` with the same `ref`, payee, and amount returns the original `Receipt` when status is `PENDING` or `CONFIRMED`.

## Security

- API keys only via env / constructor — never committed
- `session_token`, PAN, CVV are never stored on `Receipt` or `public_view()`
- `assert_no_secrets` runs on session/result projections

## Demo

```bash
python packages/nest-plugins-prava/scripts/demo_fail_then_retry.py
```
