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
# sandbox proof (prints redacted evidence JSON):
PRAVA_API_KEY=sk_test_... pytest packages/nest-plugins-prava/tests/test_sandbox_proof.py -m live -v -s
```

## Sandbox transaction evidence

These are **real** Prava Agentic Payments Sandbox sessions from
`https://sandbox.api.prava.space` (hybrid / live HTTP). Tokens and API keys are
redacted. Hybrid means: real `POST /v1/sessions` (the `ses_` / `ord_` IDs below),
then headless completion so agents can finish without a browser passkey.

### Batch A — README evidence capture (2026-08-02)

| # | Flow | `session_id` | `order_id` | Result |
|---|---|---|---|---|
| 1 | `create_session` (live HTTP) | `ses_01KZ1E1AXPZMT7Q0Y1QVWC4DV6` | `ord_01KZ1E1AXPZMT7Q0Y1QVWC4DV7` | session created (`expires_at` 2026-08-02T14:43:51.766Z, `response_id` `4cac332c-3990-4dbd-9e0b-e9098cc256b1`) |
| 2 | hybrid `quote → pay → verify` (`readme-evidence-1`, $0.50) | `ses_01KZ1E1BP5JGCQT9K353XSJYYE` | `ord_01KZ1E1BP5JGCQT9K353XSJYYF` | `verify=confirmed` |
| 3 | hybrid `pay` (`readme-evidence-2`, 25 credits) | `ses_01KZ1E1CF38T275M1RTVTM2AZH` | `ord_01KZ1E1CF41D893W3W1EXA4C6N` | `verify=confirmed` |

```json
{
  "host": "https://sandbox.api.prava.space",
  "mode": "hybrid/live",
  "transactions": [
    {
      "label": "create_session (live HTTP)",
      "session_id": "ses_01KZ1E1AXPZMT7Q0Y1QVWC4DV6",
      "order_id": "ord_01KZ1E1AXPZMT7Q0Y1QVWC4DV7",
      "expires_at": "2026-08-02T14:43:51.766Z",
      "response_id": "4cac332c-3990-4dbd-9e0b-e9098cc256b1",
      "session_token": "***REDACTED***"
    },
    {
      "label": "hybrid quote → pay → verify",
      "receipt_ref": "readme-evidence-1",
      "quote_amount_credits": 50,
      "prava_amount_usd": "0.50",
      "session_id": "ses_01KZ1E1BP5JGCQT9K353XSJYYE",
      "order_id": "ord_01KZ1E1BP5JGCQT9K353XSJYYF",
      "verify": "confirmed",
      "phase": "confirmed"
    },
    {
      "label": "hybrid pay (second PaymentRef)",
      "receipt_ref": "readme-evidence-2",
      "amount_credits": 25,
      "session_id": "ses_01KZ1E1CF38T275M1RTVTM2AZH",
      "order_id": "ord_01KZ1E1CF41D893W3W1EXA4C6N",
      "verify": "confirmed",
      "phase": "confirmed"
    }
  ]
}
```

### Batch B — live pytest suite (same day, earlier run)

`pytest …/test_sandbox_proof.py …/test_sandbox_live.py -m live -v -s` → **4 passed**.

| # | Flow | `session_id` | `order_id` | Result |
|---|---|---|---|---|
| 4 | `test_sandbox_create_session_real_response_shape` | `ses_01KZ1E0K6CZFDBWTFP41Z6T9SG` | `ord_01KZ1E0K6CZFDBWTFP41Z6T9SH` | session created |
| 5 | `test_sandbox_hybrid_quote_pay_verify_receipt` | `ses_01KZ1E0M1324J52V864HBHGMZQ` | `ord_01KZ1E0M1324J52V864HBHGMZR` | `status=confirmed` |

### Batch C — hostile / audit runs (earlier same day)

| # | Flow | `session_id` | `order_id` | Result |
|---|---|---|---|---|
| 6 | audit create_session | `ses_01KZ0Z1F5ES1ZT3TSGQ9RTH0MR` | `ord_01KZ0Z1F5ES1ZT3TSGQ9RTH0MS` | session created |
| 7 | audit hybrid pay (`sandbox-audit-1`) | `ses_01KZ0Z1FY1K42A0S51WPV822J5` | `ord_01KZ0Z1FY1K42A0S51WPV822J6` | `status=confirmed` |

**Total documented sandbox sessions above: 7** (all real `ses_` / `ord_` from Prava sandbox). Re-run the live tests with your own `sk_test_` key to mint fresh evidence; never commit API keys.

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
