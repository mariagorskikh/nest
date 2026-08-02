# nest-plugins-prava

Prava Agentic Payments plugin for nest - mandate-backed payments with threshold enforcement.

## Overview

This plugin implements the nest `Payments` protocol using [Prava's Agentic Payments API](https://prava.space). It enables agents to make payments against pre-authorized mandates with built-in spending caps and idempotency.

### Key Features

- **Mandate-backed payments**: Charges are made against pre-authorized spending limits
- **Threshold enforcement**: Automatic rejection when charges exceed the approved cap
- **Idempotency**: Duplicate payment references return the same receipt without double-charging
- **Dual-mode operation**: Live API calls or deterministic mock mode for testing
- **Typed error handling**: Every Prava error code maps to a specific exception

## Installation

```bash
# Within the nandatown workspace
uv pip install -e packages/nest-plugins-prava

# Or add to dependencies
uv add nest-plugins-prava
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `PRAVA_SECRET_KEY` | For live mode | Prava API secret key (`sk_test_...` or `sk_live_...`) |
| `PRAVA_BASE_URL` | No | API base URL (default: `https://sandbox.api.prava.space`) |

**Important**: The secret key should ONLY be provided via environment variable, never hardcoded.

## Usage

### Basic Setup

```python
from nest_plugins_prava import PravaPayments
from nest_sdk import AgentId, Money, PaymentRef
import os

# Create plugin with mandate mapping
payments = PravaPayments(
    agent_id=AgentId("buyer-01"),
    mandate_map={
        AgentId("buyer-01"): "mdt_01ABCD...",  # Pre-provisioned mandate IDs
        AgentId("buyer-02"): "mdt_02EFGH...",
    },
    prava_secret_key=os.environ.get("PRAVA_SECRET_KEY"),  # None = mock mode
)

# Make a payment
receipt = await payments.pay(
    to=AgentId("seller-01"),
    amount=Money(amount=1250, currency="USD"),  # $12.50
    ref=PaymentRef("order-123"),
)

print(f"Payment confirmed: {receipt.ref}")
```

### Mock Mode (for testing)

```python
# Omit secret key for deterministic mock behavior
payments = PravaPayments(
    agent_id=AgentId("buyer-01"),
    mandate_map={AgentId("buyer-01"): "mdt_mock_001"},
    approved_amount=10000,  # $100.00 cap
)

# Works identically to live mode
receipt = await payments.pay(
    to=AgentId("seller"),
    amount=Money(amount=5000),
    ref=PaymentRef("test-001"),
)

# Test threshold enforcement
try:
    await payments.pay(
        to=AgentId("seller"),
        amount=Money(amount=6000),  # Would exceed $100 cap
        ref=PaymentRef("test-002"),
    )
except ThresholdExceededError:
    print("Cap enforced - defense held!")
```

### Shared State (multi-agent scenarios)

```python
# Share mandate state across multiple plugin instances
shared_mandates = {}
shared_receipts = {}

buyer1 = PravaPayments(
    agent_id=AgentId("buyer-01"),
    mandate_map={AgentId("buyer-01"): "mdt_shared"},
    mandates=shared_mandates,
    receipts=shared_receipts,
)

buyer2 = PravaPayments(
    agent_id=AgentId("buyer-02"),
    mandate_map={AgentId("buyer-02"): "mdt_shared"},  # Same mandate
    mandates=shared_mandates,
    receipts=shared_receipts,
)
```

## Design Notes

### Mandate Flow

1. **Pre-provisioning**: Mandates are created via Prava session + passkey approval BEFORE scenario runs
2. **Plugin config**: Maps each buyer `AgentId` to their pre-provisioned `mandate_id`
3. **Charging**: `pay()` calls `POST /v1/mandates/{mandate_id}/charge` with idempotent reference
4. **Settlement**: Charge outcomes are reported back to the network via `/report` endpoint

### Idempotency

The `reference` parameter on `pay()` provides idempotency:
- Same reference → same transaction ID returned (no double-charge)
- The plugin also caches receipts locally for fast lookups

### Refund Limitations

**Prava does not provide a direct refund API endpoint.**

The `refund()` method implements a best-effort approach:
- **Live mode**: Reports the charge as `DECLINED` to trigger network-level reversal
- **Mock mode**: Reverses the charge in the local ledger

This is documented as **game-only behavior**. Real refunds would require:
- Merchant-side chargeback processing
- Direct settlement with the acquiring bank

## Failure Matrix

| Error Code | Exception | Trigger | Resolution |
|------------|-----------|---------|------------|
| `THRESHOLD_EXCEEDED` | `ThresholdExceededError` | Charge exceeds `approvedAmount` | "Defense held" - cap working as intended |
| `MANDATE_NOT_ACTIVE` | `MandateNotActiveError` | Mandate cancelled/paused/expired | Re-provision mandate |
| `MANDATE_MERCHANT_NOT_ALLOWED` | `MandateMerchantNotAllowedError` | `listed` scope, wrong merchant | Use correct merchant or `any` scope |
| `MANDATE_NOT_FOUND` | `MandateNotFoundError` | Invalid mandate ID | Check mandate_map configuration |
| `AUTH_REQUIRED` | `AuthRequiredError` | Invalid/expired API key | Check `PRAVA_SECRET_KEY` |
| `NETWORK_TIMEOUT` | `NetworkTimeoutError` | Request timeout after retries | Retry later, check connectivity |
| `NO_TOKEN` (500) | `ServerError` | Prava internal error | Contact Prava support |
| `DUPLICATE_REFERENCE` | `DuplicateReferenceError` | Reference already used | Idempotent - original txn returned |
| `INVALID_AMOUNT` | `InvalidAmountError` | Zero or negative amount | Use positive amount |
| `CHARGE_FAILED` | `ChargeFailedError` | Card declined by network | Check card details |

### Error Handling Example

```python
from nest_plugins_prava import (
    PravaPayments,
    ThresholdExceededError,
    MandateNotActiveError,
    NetworkTimeoutError,
)

try:
    receipt = await payments.pay(to, amount, ref)
except ThresholdExceededError as e:
    # Cap enforced - this is success for the consumer!
    print(f"Spending limit protected: {e.message}")
    print(f"Remaining: {e.approved_amount - e.spent_amount}")
except MandateNotActiveError as e:
    # Mandate was cancelled
    print(f"Mandate {e.mandate_id} is {e.status}")
except NetworkTimeoutError as e:
    # Transient failure after retries
    print(f"Network error after {e.retries} retries")
```

## Security Notes

### Secret Key Management

- **NEVER** hardcode the secret key in source code
- **ALWAYS** provide via `PRAVA_SECRET_KEY` environment variable
- Use separate keys for sandbox (`sk_test_`) vs production (`sk_live_`)

### Card Data Handling

**Card credentials from charge responses are NEVER logged or written to traces.**

The client automatically redacts sensitive fields:
- `cardNumber`, `pan`
- `cvv`, `cvc`
- `expiry`, `expiryDate`
- `cardholderName`
- `token`, `cardToken`

### Idempotency & Replay Protection

- Each `PaymentRef` can only be charged once per mandate
- Duplicate references return the same transaction without double-charging
- This prevents both accidental retries and malicious replay attacks

### Token Scoping

Prava uses single-use, merchant/amount-scoped tokens:
- Tokens are bound to specific merchants (if `listed` scope)
- Tokens are bound to the approved amount cap
- This limits blast radius if a token is compromised

## Testing

### Run Mock Tests (no API keys required)

```bash
pytest packages/nest-plugins-prava/tests/test_payments_mock.py -v
```

### Run Live Sandbox Tests

```bash
# Set credentials
export PRAVA_SECRET_KEY=sk_test_...
export PRAVA_MANDATE_ID=mdt_01...  # Pre-provisioned test mandate

# Run live tests
pytest packages/nest-plugins-prava/tests/test_sandbox_live.py -v -m live
```

## Entry Point

This plugin registers as a nest payments provider:

```toml
[project.entry-points."nest.plugins.payments"]
prava = "nest_plugins_prava:PravaPayments"
```

Load via the plugin registry:

```python
from nest_core.plugins import PluginRegistry

registry = PluginRegistry()
PravaPayments = registry.load("payments", "prava")
```

## License

Apache-2.0
