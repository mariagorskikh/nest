# Payments layer

**What it does.** Price a service, pay, verify a payment, refund.

## Interface

```python
class Payments(Protocol):
    async def quote(self, service: ServiceRef) -> Quote: ...
    async def pay(self, to: AgentId, amount: Money, ref: PaymentRef) -> Receipt: ...
    async def verify_payment(self, ref: PaymentRef) -> PaymentStatus: ...
    async def refund(self, ref: PaymentRef) -> None: ...
```

Full definition: [`nest_core/layers/payments.py`](../../packages/nest-core/nest_core/layers/payments.py).

## Default plugin

`prepaid_credits` — in-memory debit/credit ledger. Constant-price
quotes, raises on insufficient balance, supports refund by `PaymentRef`.

Source: [`nest_plugins_reference/payments/prepaid_credits.py`](../../packages/nest-plugins-reference/nest_plugins_reference/payments/prepaid_credits.py).

## Additional reference plugins

`streaming` — bilateral per-tick streams with mid-stream cancellation
and **delivery-gated billing**: the payer records each delivered work
unit (`record_delivery`) and only then drains one tick (`tick_stream`),
so dropped or partitioned payees are never billed for work they could
not deliver — the per-request metering shape of x402-style HTTP
payments. `open_stream`/`close_stream` bound the flow by `max_total`;
closing settles exactly what was billed and the remainder is never
spent. One-shot `pay()` is a stream that drains everything in one tick.
The `streaming_payments` scenario (and its `_partition` variant)
exercises it under 5% message drop and a full buyer/seller partition;
three adversarial validators check conservation, drain-after-close, and
over-bill-on-partition, and all three fail loudly under a plugin that
quietly pre-pays instead of streaming.

Source: [`nest_plugins_reference/payments/streaming.py`](../../packages/nest-plugins-reference/nest_plugins_reference/payments/streaming.py).

`empic_escrow` — EMPIC-shaped escrow for service providers and
consumers. Pull mode locks one request payment until accepted data is
delivered; pubsub mode pre-funds a maximum stream amount, releases one
tick for each accepted delivery, and refunds unused escrow on close.
The bundled `empic_payments` scenario demonstrates provider service
registration, consumer acceptance policy, pull refunds, and pubsub
overbilling protection. Its adversarial validators also check consumer /
provider / service binding by payment reference and reject traces that leak
private keys, API keys, bearer tokens, wallet secrets, or other live rail
secrets.

## Writing your own

See [`writing-a-plugin.md`](../writing-a-plugin.md) — the full
walkthrough on that page builds a custom payments plugin end-to-end.
Register under entry point group `nest.plugins.payments`.

Good fits to test here: escrow, streaming payments, multi-party
settlement, on-chain stubs, x402-style HTTP payments.
