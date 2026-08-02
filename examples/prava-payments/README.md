# Prava payments adapter for Nanda Town

A reusable **Prava** implementation of the Nanda Town **payments** layer --
`quote` / `pay` / `verify_payment` / `refund` -- with a Senso-backed **trust gate**
that refuses payments to unverified counterparties, an **adversarial validator**
for that property, a scenario, tests, and a runnable demo.

> Track: [NandaHack × Prava -- Best Prava Adapter for NANDA Town](https://nandatown.projectnanda.org/pravahack).
> Part of **Vendable** (https://github.com/karthikbalajikb/vendable), which turns any
> store URL into a discoverable, Senso-verified, Prava-payable agent. This example is
> only the Nanda Town payments layer.

## What's here

| File | Purpose |
| --- | --- |
| `prava_payments/plugin.py` | `PravaPayments` -- the `Payments` protocol over Prava, trust-gated. |
| `prava_payments/prava_client.py` | Prava rail client; deterministic offline mock, live sandbox with keys. |
| `prava_payments/trust.py` | `TrustGate` + `TrustRefused` -- Senso-backed verification gate. |
| `prava_payments/validator.py` | Adversarial validator: no value moves to an unverified payee. |
| `scenarios/prava_marketplace.yaml` | Marketplace scenario with `payments: prava`. |
| `tests/test_prava_payments.py` | Happy path + trust-gate failure + refund + validator. |
| `demo.py` | Console proof: settlement -> refusal -> refund. |
| `simulate_failure.py` | Writes a Nanda JSONL trace with a `trust_refused` event. |

## Install

```bash
pip install -e .            # registers the `prava` payments plugin
nest plugins list           # payments: ... prava
```

## Reuse -- one line in any scenario

```yaml
layers:
  payments: prava
```

## Prove it

```bash
python demo.py              # CONFIRMED -> BLOCKED -> REFUNDED
pytest -v                  # happy path + trust-gate failure + refund + validator
python simulate_failure.py                       # writes traces/prava_failure.jsonl
nest inspect traces/prava_failure.jsonl          # event breakdown incl. trust_refused: 1
python -m prava_payments.validator traces/prava_failure.jsonl did:printsmith:store
```

Expected `demo.py`:

```
[OK]      did:buyer:alice -> did:printsmith:store
          399 INR  status=CONFIRMED
[BLOCKED] Payee did:unknown:scammer failed Senso verification; Prava token refused
[REFUND]  status=REFUNDED
```

## The failure case (required)

`prepaid_credits`, the default payments plugin, has no notion of counterparty
trust -- it will settle to a scammer. `prava` runs every payee through a
Senso-backed gate first; an unverified payee raises `TrustRefusedError` and **no Prava
token is issued**. The adversarial validator encodes this as a property you can
check against any trace:

```bash
python -m prava_payments.validator <trace.jsonl> <verified_did> [<verified_did> ...]
# prepaid_credits -> FAIL: no_unverified_settlement - settled to unverified payees: ['did:unknown:scammer']
# prava           -> PASS: no_unverified_settlement - no value moved to an unverified payee
```

## Determinism

Tier-1 clean: no wall-clock, no unseeded RNG. The Prava client returns a
deterministic mock unless you opt into the live sandbox with `PRAVA_API_KEY` +
`PRAVA_LIVE=1`, so `nest run` and the tests are byte-reproducible.

## Live Prava sandbox

Set `PRAVA_API_KEY` (secret) and `PRAVA_LIVE=1` to settle against Prava's Agentic
Payments Sandbox instead of the mock. The full live integration (real Prava
mandates + charge, Touch-ID card approval) runs in the Vendable platform; a live
sandbox transaction reference from that flow is linked in the Devfolio submission.
