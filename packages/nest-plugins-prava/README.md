# NANDA Town Prava payments adapter

This package implements NANDA Town's `Payments` protocol with Prava's current
Session REST API: `quote`, `pay`, `verify_payment`, and `refund`.

## Safety and trust boundary

- Every `pay` call creates a scoped Prava session and requires the human card
  and passkey step before merchant execution.
- Virtual card fields and CVV are passed directly to an injected merchant
  executor, then discarded. They are never logged, returned in a receipt, or
  stored in adapter state.
- Payment references are idempotent. Reuse with different terms is rejected;
  a completed duplicate returns the original receipt without another session.
- Merchant declines are reported to Prava as `DECLINED` and never produce a
  receipt.
- Prava's official Commerce FAQ states that it exposes no separate refund
  endpoint. `refund` therefore delegates to an injected merchant refund
  handler and fails closed when no merchant handler is configured.

## Install and test

```bash
uv sync --extra dev
uv run ruff check .
uv run ruff format --check .
uv run pyright
uv run pytest -v
```

The entry point is registered as `nest.plugins.payments: prava`.

## Interactive Prava sandbox scenario

Set `PRAVA_API_KEY` and `PRAVA_SANDBOX_URL` in your shell or secret manager.
Never put them in the scenario, source control, or chat. Then run:

```bash
export PRAVA_ALLOW_DISCLOSED_SANDBOX_EXECUTION=1
uv run python examples/one_payment.py
```

Open the short-lived approval URL, use Prava's team-issued sandbox test card,
and complete the passkey step. The example then reports an explicitly
disclosed sandbox merchant outcome to Prava and verifies the resulting
payment status. This proves the Prava sandbox transaction; it does **not**
claim a real merchant charge.

The YAML description is in `scenarios/prava_payment.yaml`. The interactive
runner is separate because a human passkey cannot be represented as a
deterministic Tier-1 state-machine step.

## Production reuse

Supply a `MerchantExecutor` that consumes the one-time credential at the real
merchant and a `RefundHandler` that calls that merchant's refund API. Never use
the disclosed sandbox executor in production.

Authoritative references:

- <https://nandatown.projectnanda.org/pravahack>
- <https://nandatown.projectnanda.org/docs>
- <https://docs.prava.space/api-reference/create-session>
- <https://docs.prava.space/api-reference/get-payment-result>
- <https://docs.prava.space/api-reference/report-status>
- <https://docs.prava.space/integration/faqs>

