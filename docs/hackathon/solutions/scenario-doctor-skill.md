# NANDA Scenario Doctor

A validation and linting service for NANDA Town scenario configuration files.

- **Hosted URL**: `https://nandatown-production.up.railway.app`
- **Purpose**: Helps OpenClaw agents quickly validate the structure of scenario YAML files and check for unregistered layers/plugins without running the full simulation.

## Endpoints

### 1. `GET /health`
- **Description**: Verifies that the service is running.
- **Response**:
  ```json
  {
    "status": "ok"
  }
  ```
- **Example Call**:
  ```bash
  curl https://nandatown-production.up.railway.app/health
  ```

### 2. `GET /layers`
- **Description**: Lists all 12 NANDA Town concept layers and their active plugin choices.
- **Response**:
  ```json
  {
    "layers": {
      "transport": ["in_memory"],
      "comms": ["nest_native", "versioned"],
      "identity": ["did_key", "ed25519_rotating"],
      "registry": ["in_memory", "gossip"],
      "auth": ["jwt", "delegatable"],
      "trust": ["score_average", "agent_receipts"],
      "payments": ["prepaid_credits", "streaming", "escrow", "empic_escrow"],
      "coordination": ["contract_net", "hotstuff"],
      "negotiation": ["alternating_offers", "pareto"],
      "memory": ["blackboard", "lww_register"],
      "privacy": ["noop", "hybrid_x25519"],
      "datafacts": ["datafacts_v1", "cid_facts"]
    }
  }
  ```
- **Example Call**:
  ```bash
  curl https://nandatown-production.up.railway.app/layers
  ```

### 3. `POST /validate-scenario`
- **Description**: Inspects a scenario YAML payload for structural correctness and completeness.
- **Content-Type**: `text/yaml`
- **Payload**: Raw scenario YAML string.
- **Response (Valid)**:
  ```json
  {
    "valid": true
  }
  ```
- **Response (Invalid)**:
  ```json
  {
    "valid": false,
    "errors": [
      "Missing mandatory root key: 'description'",
      "'duration' format must be 'ticks:<N>' or 'seconds:<N>'"
    ]
  }
  ```
- **Example Call**:
  ```bash
  curl -X POST -H "Content-Type: text/yaml" --data-binary @scenarios/delegated_auth.yaml https://nandatown-production.up.railway.app/validate-scenario
  ```

### 4. `POST /lint`
- **Description**: Lints the `layers` configuration in the posted YAML scenario to catch unknown layers or unregistered plugins.
- **Content-Type**: `text/yaml`
- **Payload**: Raw scenario YAML string.
- **Response (Clean)**:
  ```json
  {
    "clean": true,
    "warnings": []
  }
  ```
- **Response (Lints Detected)**:
  ```json
  {
    "clean": false,
    "warnings": [
      "Unknown plugin 'wrong_plugin' for layer 'auth'. Must be one of ['jwt', 'delegatable']."
    ]
  }
  ```
- **Example Call**:
  ```bash
  curl -X POST -H "Content-Type: text/yaml" --data-binary @scenarios/delegated_auth.yaml https://nandatown-production.up.railway.app/lint
  ```

---

## Agent Setup Guide

To use the Scenario Doctor in your automation or agent flow:
1. **Query known layers**: Call `GET /layers` to retrieve the current registry mapping of layers and plugins.
2. **Schema Verification**: Before running `nest run`, submit the scenario configuration to `POST /validate-scenario`. Check if `"valid": true` is returned. If not, inspect the returned `"errors"` list.
3. **Registry Linting**: Submit the configuration to `POST /lint` to check if any custom plugins or layers violate the current registry mapping, helping prevent runtime module import crashes.
