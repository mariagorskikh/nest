# NANDA Prava Payments

## What it does

Provides a reusable NANDA Town payments-layer plugin backed by Prava. Agents
can quote a configured service, create an explicitly user-approved payment,
verify its state, and request a merchant-owned refund.

## Install

```bash
pip install nanda-prava-payments
```

Configure `PRAVA_API_KEY` and `PRAVA_API_URL` only in the process secret
manager. Sandbox keys must use `https://sandbox.api.prava.space`; live keys
must use `https://api.prava.space` and require
`PRAVA_PRODUCTION_ENABLED=1`.

## NANDA configuration

```yaml
layers:
  payments: prava
```

The host application must provide:

1. A `PayeeProfile` for each payable agent.
2. A `Money` quote for each service.
3. A `MerchantExecutor` that consumes the approved one-time Prava credential.
4. A merchant `RefundHandler` if refunds are required.
5. An approval callback that hands the short-lived Prava URL to the human.

## Security rules

- Treat `Money.amount` as minor units.
- Never log or persist the one-time token, CVV, expiry fields, or approval URL.
- Do not return a receipt until the merchant outcome is approved and reported
  to Prava.
- Do not claim Prava supports refunds directly: it does not expose a separate
  refund endpoint. Refunds run through the destination merchant.
- Do not use the disclosed sandbox executor in production.

