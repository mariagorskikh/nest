---
name: Agent Persistent Memory
description: Save and recall persistent key-value notes or coordinate state with other agents across session boundaries.
---

# Agent Persistent Memory

This service provides a persistent key-value memory scratchpad for AI agents. Use it to store state, configuration, and checkpoints between executions, or to share context and coordinate with other agents.

## Base URL
https://YOUR-APP.onrender.com

## Endpoints

### 1. Health Check
`GET /health`
Returns the status of the memory database.
- **Example Call**:
  ```bash
  curl "https://YOUR-APP.onrender.com/health"
  ```
- **Example Response**:
  ```json
  {
    "status": "ok",
    "entries_loaded": 4
  }
  ```

### 2. Store Memory
`POST /memory`
Stores a persistent string value under an `agent_id` namespace and a unique `key`.
- **Payload Format**: JSON
  - `agent_id` (string, required): A unique identifier for the agent (e.g. `agent-alice-42`).
  - `key` (string, required): The name of the property to store (e.g. `last_price_negotiated`).
  - `value` (string, required): The string value to store.
- **Example Call**:
  ```bash
  curl -X POST "https://YOUR-APP.onrender.com/memory" \
    -H "Content-Type: application/json" \
    -d '{
      "agent_id": "agent-alice-42",
      "key": "last_price_negotiated",
      "value": "12.50"
    }'
  ```
- **Example Response**:
  ```json
  {
    "message": "Memory stored successfully.",
    "agent_id": "agent-alice-42",
    "key": "last_price_negotiated"
  }
  ```

### 3. Retrieve Memory
`GET /memory?agent_id={agent_id}&key={key}`
Retrieves a previously stored value by agent namespace and key.
- **Example Call**:
  ```bash
  curl "https://YOUR-APP.onrender.com/memory?agent_id=agent-alice-42&key=last_price_negotiated"
  ```
- **Example Response**:
  ```json
  {
    "agent_id": "agent-alice-42",
    "key": "last_price_negotiated",
    "value": "12.50"
  }
  ```

### 4. Delete Memory
`DELETE /memory?agent_id={agent_id}&key={key}`
Deletes a stored key-value pair.
- **Example Call**:
  ```bash
  curl -X DELETE "https://YOUR-APP.onrender.com/memory?agent_id=agent-alice-42&key=last_price_negotiated"
  ```
- **Example Response**:
  ```json
  {
    "message": "Memory deleted successfully.",
    "agent_id": "agent-alice-42",
    "key": "last_price_negotiated"
  }
  ```

### 5. List Agent Keys
`GET /memories?agent_id={agent_id}`
Lists all keys and their corresponding values currently stored for a specific agent namespace.
- **Example Call**:
  ```bash
  curl "https://YOUR-APP.onrender.com/memories?agent_id=agent-alice-42"
  ```
- **Example Response**:
  ```json
  {
    "agent_id": "agent-alice-42",
    "keys": ["last_price_negotiated"],
    "memories": {
      "last_price_negotiated": "12.50"
    }
  }
  ```

## How the Agent Should Use This

1. **Initialize/Load State**: At the beginning of execution, request `GET /memories?agent_id={your_agent_id}` to retrieve any previously saved context or checklist progress.
2. **Read Specific Keys**: Use `GET /memory` to retrieve values for specific keys when navigating decision trees.
3. **Save Checkpoints**: When completing a task or updating state (e.g. recording negotiation details or transaction logs), send a `POST /memory` call to save your progress.
4. **Coordinate**: If cooperating with another agent, agree on a shared `agent_id` namespace to write and read message flags or lock statuses.
