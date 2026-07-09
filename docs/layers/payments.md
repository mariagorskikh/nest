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

`streaming` — bilateral per-tick streams with mid-stream cancellation.

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

`split_settlement` — weighted multi-payee **fan-out settlement**. One atomic
debit from a payer is split across *N* payees by integer weights declared and
locked when the contract is opened. Allocation uses the largest-remainder
(Hamilton) method over integer credits, so every settlement conserves value
exactly (`sum(allocations) == amount`) and is deterministic — the indivisible
dust goes to the payees with the largest fractional parts, ties broken by payee
id. A plain `pay()` is the degenerate single-payee, weight-1 split, so one-shot
callers keep working. Where `escrow` conditions one payee's payout and
`streaming` meters one payee per tick, this splits one debit across many at
once — the missing shape for marketplace revenue splits, royalty payouts, and
contributor rev-share. The bundled `split_settlement` scenario (12 agents: a
content marketplace splitting buyer payments 80/20 across contributors and a
platform) runs under two adversarial validators the default `prepaid_credits`
plugin cannot satisfy: `split_conservation` catches **penny-shaving** (a splitter
that floors every share and pockets the dust) and `split_weight_fidelity`
recomputes the canonical allocation independently to catch **weight tampering**
(a mid-flight reweight or self-dealing that still sums to the amount). Source:
[`nest_plugins_reference/payments/split_settlement.py`](../../packages/nest-plugins-reference/nest_plugins_reference/payments/split_settlement.py).

## Writing your own

See [`writing-a-plugin.md`](../writing-a-plugin.md) — the full
walkthrough on that page builds a custom payments plugin end-to-end.
Register under entry point group `nest.plugins.payments`.

Good fits to test here: escrow, streaming payments, multi-party
settlement, on-chain stubs, x402-style HTTP payments.
