# NANDA Simulation Sandbox

Hosted sandbox service that runs and validates NANDA Town agent simulation configurations remotely.

https://renewed-truth-production-71f6.up.railway.app

## Endpoints

### GET /health
Checks if the sandbox service is online and active.
```bash
curl https://renewed-truth-production-71f6.up.railway.app/health
```
```json
{"status": "ok"}
```

### GET /scenarios
Lists all built-in simulation scenarios supported by the registry.
```bash
curl https://renewed-truth-production-71f6.up.railway.app/scenarios
```
```json
{
  "scenarios": [
    "marketplace",
    "auction",
    "voting",
    "consensus",
    "supply_chain",
    "reputation",
    "identity_rotation",
    "gossip_registry",
    "memory_concurrent_writers",
    "comms_versioning",
    "receipt_reputation",
    "empic_payments",
    "multi_attribute_market",
    "provenance_supply_chain",
    "bft_hotstuff",
    "escrow_marketplace",
    "failure_detection"
  ]
}
```

### POST /simulate
Executes a simulation scenario YAML string and returns metrics, adversarial validator reports, and trace logs. Requires the header `X-API-Key` to contain your deployed API key.
```bash
curl -X POST -H "Content-Type: text/yaml" -H "X-API-Key: <YOUR_SANDBOX_API_KEY>" --data-binary @scenarios/marketplace.yaml https://renewed-truth-production-71f6.up.railway.app/simulate
```
```json
{
  "success": true,
  "metrics": {
    "message_count": 82.0,
    "deal_rate": 0.8
  },
  "validation": [
    {
      "name": "double_spend_prevention",
      "passed": true,
      "detail": "Verified 10/10 transaction attempts"
    }
  ],
  "trace_summary": {
    "total_events": 100,
    "returned_events": [
      {
        "tick": 0.0,
        "event": "simulation_started",
        "seed": 42
      }
    ]
  }
}
```

## How the agent should use this

1. Retrieve the list of supported simulation task types by calling `GET /scenarios`.
2. Construct or modify a NANDA Town scenario configuration in YAML format (defining agent counts, plugin layers, and logical durations). Keep `agents.count` under 100 and duration ticks under 2000.
3. Submit the raw YAML string to `POST /simulate` including the `X-API-Key` header with your deployed API key.
4. Parse the output JSON to check if `"success"` is `true`.
5. Read the `"validation"` results to inspect which adversarial checks passed or failed.
6. Analyze the `"metrics"` and `"trace_summary.returned_events"` to optimize your custom layer configurations.
