# nest-payments-prava

[![Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](../../LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue)](https://www.python.org)

A **NANDA Town payments-layer plugin** that connects multi-agent simulations
to [Prava's Agentic Payments Sandbox](https://sandbox.api.prava.space) via
Visa Network Tokens.  Any agent in any scenario can route its `quote`, `pay`,
`verify`, and `refund` calls through this adapter by setting
`layers.payments: prava_adapter` in the scenario YAML — no code changes
required.

Built for the [Prava × NANDA Town Agentic Commerce Hackathon](https://nandatown.projectnanda.org/pravahack).

---

## What this plugin does

| Method | Behaviour |
|---|---|
| `quote(service)` | Returns a fixed-price USD quote (sandbox-compatible). |
| `pay(to, amount, ref, *, token?)` | POSTs to `https://sandbox.api.prava.space/v1/charge` with Prava Visa Network Token details. Returns a `Receipt` on success. |
| `verify_payment(ref)` | Returns `CONFIRMED` or `FAILED` from the internal ledger. |
| `refund(ref)` | Reverses the soft-balance bookkeeping (sandbox refund endpoint pending). |

### Mandatory failure handling

Two client-side guards raise `PaymentDeclined` **before** any network call:

- **CVV `000`** — Prava test-harness forced-decline marker.
- **Amount > `token.limit`** — Default sandbox token ceiling is $150.

---

## Package layout

```
packages/nest-payments-prava/
├── pyproject.toml                          # Package manifest + entry-point
├── README.md                               # This file
├── nest_payments_prava/
│   ├── __init__.py
│   └── prava_plugin.py                     # PravaPaymentLayer implementation
├── tests/
│   └── test_prava_adapter.py               # Offline pytest suite (uses respx)
└── scenarios/
    └── capspend_marketplace.yaml           # 4-agent multi-merchant scenario
```

---

## Installation

### Into the nandatown uv workspace (recommended)

The workspace `pyproject.toml` declares `nest-payments-prava` as a member,
so a single sync picks it up:

```bash
uv sync
```

### Standalone editable install

```bash
# From the repository root
uv pip install -e packages/nest-payments-prava

# Or with pip inside any active venv
pip install -e packages/nest-payments-prava
```

### Verify discovery

```bash
nest plugins list payments
# Expected output includes:
#   payments  prava_adapter  nest_payments_prava.prava_plugin:PravaPaymentLayer
```

---

## Running the tests

```bash
# From the repository root (respx is listed as a dev dependency)
pytest packages/nest-payments-prava/tests/

# Or install dev extras first if running standalone
pip install -e "packages/nest-payments-prava[dev]"
pytest packages/nest-payments-prava/tests/
```

All 7 tests run **fully offline** — HTTP calls are intercepted by
[`respx`](https://lundberg.github.io/respx/).

```
tests/test_prava_adapter.py::test_successful_transaction   PASSED
tests/test_prava_adapter.py::test_decline_over_limit       PASSED
tests/test_prava_adapter.py::test_decline_cvv_000          PASSED
tests/test_prava_adapter.py::test_duplicate_ref            PASSED
tests/test_prava_adapter.py::test_quote                    PASSED
tests/test_prava_adapter.py::test_refund                   PASSED
tests/test_prava_adapter.py::test_refund_unknown_ref       PASSED
```

---

## Running the CapSpend Marketplace scenario

```bash
nest run packages/nest-payments-prava/scenarios/capspend_marketplace.yaml
```

The scenario spins up four agents:

| Agent | Role | Catalog item | Price | Expected |
|---|---|---|---|---|
| `procurement_buyer` | Solo autonomous buyer | — | — | — |
| `software_seller` | Seller | Enterprise License | $99 | ✅ confirmed |
| `cloud_seller` | Seller | Cloud Compute 1mo | $120 | ✅ confirmed |
| `hardware_seller` | Seller | Server Rack Unit | $200 | ❌ declined |

All payments route exclusively through `prava_adapter`.
The trace is written to `./traces/capspend_marketplace.jsonl`.

---

## Using this adapter in your own scenario

Add one line to your scenario YAML:

```yaml
layers:
  payments: prava_adapter   # ← that's it
```

Pass Prava Visa Network Token credentials via the agent `config`:

```yaml
agents:
  roles:
    - name: buyer
      config:
        prava_token:
          pan: "4111111111111111"
          cvv: "123"
          expiry: "12/27"
          limit: 150        # optional; defaults to $150
```

Or inject a `PravaTokenDetails` object directly in Python:

```python
from nest_payments_prava import PravaPaymentLayer, PravaTokenDetails
from nest_core.types import AgentId

token = PravaTokenDetails(pan="4111111111111111", cvv="123", expiry="12/27")
plugin = PravaPaymentLayer(AgentId("my-buyer"), token=token, initial_balance=500)
```

---

## Error handling

```python
from nest_payments_prava import PaymentDeclined

try:
    receipt = await plugin.pay(seller_id, amount, ref)
except PaymentDeclined as exc:
    # exc.reason — human-readable decline message
    # exc.ref    — the PaymentRef that was declined
    print(f"Payment declined: {exc.reason}")
```

`PaymentDeclined` is raised for:

| Trigger | Notes |
|---|---|
| CVV `"000"` | Prava test-harness forced decline; no network call |
| Amount > token limit | Sandbox ceiling exceeded; no network call |
| HTTP 4xx from sandbox | Network decline mapped to `PaymentDeclined` |

Any HTTP 5xx or timeout propagates as `httpx.HTTPError`.

---

## Dependencies

| Package | Purpose |
|---|---|
| `nest-core` | NANDA Town layer types and plugin registry |
| `httpx>=0.27` | Async HTTP client for Prava sandbox calls |
| `pydantic>=2.0` | Token model validation |
| `respx>=0.21` *(dev)* | HTTP mocking in tests |
| `pytest-asyncio>=0.24` *(dev)* | Async test runner |

---

## License

Apache 2.0 — see [LICENSE](../../LICENSE).
