# Typed CRDT Memory Plugin

## Problem

The default `blackboard` memory plugin uses last-writer-wins behavior.

That means if several agents write to the same key, the final value depends on message delivery order. Earlier writes can be silently overwritten.

Example:

```text
agent_1 writes fact_1
agent_2 writes fact_2
...
agent_8 writes fact_8
```

With `blackboard`, the final memory only contains whichever write arrived last.

This is unsafe for multi-agent coordination because NANDA Town scenarios can include concurrent writers, dropped messages, and reordered delivery.

## Solution

`typed_crdt` is a memory plugin that merges values according to the declared memory type.

Instead of treating every key as a normal value, each write includes a `type` field. The first write establishes the type for that key. Later writes to the same key must use the same type.

Supported types:

| Type | Merge behavior | Use case |
|---|---|---|
| `set` | Union tagged items | Shared facts, catalogue entries, presence |
| `counter` | Keep max count per writer and derive total | Vote totals, event counts, reports |
| `vote` | Preserve one ballot per writer and derive majority result | Agent decisions, reputation labels, approvals |

If two agents write different memory types to the same key, the plugin rejects the write instead of guessing.

## Example: set memory

First write:

```json
{"type":"set","writer":"agent_1","value":"fact_1"}
```

Second write:

```json
{"type":"set","writer":"agent_2","value":"fact_2"}
```

Final state:

```json
{
  "type": "set",
  "items": {
    "agent_1:fact_1": {
      "writer": "agent_1",
      "value": "fact_1"
    },
    "agent_2:fact_2": {
      "writer": "agent_2",
      "value": "fact_2"
    }
  },
  "values": ["fact_1", "fact_2"]
}
```

## Example: counter memory

First write:

```json
{"type":"counter","writer":"agent_1","count":1}
```

Second write:

```json
{"type":"counter","writer":"agent_2","count":1}
```

Final state:

```json
{
  "type": "counter",
  "counts": {
    "agent_1": 1,
    "agent_2": 1
  },
  "total": 2
}
```

Duplicate delivery from the same writer does not double count because merging keeps the maximum count per writer.

## Example: vote memory

First write:

```json
{"type":"vote","writer":"agent_1","value":"approve"}
```

Second write:

```json
{"type":"vote","writer":"agent_2","value":"approve"}
```

Third write:

```json
{"type":"vote","writer":"agent_3","value":"reject"}
```

Final state:

```json
{
  "type": "vote",
  "ballots": {
    "agent_1": "approve",
    "agent_2": "approve",
    "agent_3": "reject"
  },
  "result": {
    "winner": "approve",
    "confidence": 0.667,
    "counts": {
      "approve": 2,
      "reject": 1
    }
  }
}
```

The plugin shows a majority result, but it does not delete dissent.

## Determinism

`typed_crdt` encodes JSON with sorted keys. This makes the merged output deterministic.

The same writes produce the same final bytes even when delivered in different orders.

## How to run the validator

From the repo root:

```powershell
$env:PYTHONPATH="packages\nest-core;packages\nest-plugins-reference"
python3 validators\validate_typed_crdt_memory.py
```

Expected result:

```text
Blackboard expected failure:
  result: FAILS convergence, as expected
TypedCrdtMemory set: PASS
TypedCrdtMemory counter: PASS
TypedCrdtMemory vote: PASS
All typed CRDT memory validators passed.
```

## How to run the tests

From the repo root:

```powershell
$env:PYTHONPATH="packages\nest-core;packages\nest-plugins-reference"
python3 -m pytest packages\nest-plugins-reference\tests\test_typed_crdt_memory.py -v
```

Expected result:

```text
6 passed
```

## Limits

This plugin does not automatically infer the correct memory type. Agents or scenarios must write self-describing JSON values with a `type` field.

The first write to a key establishes that key's type. Later writes with a different type are rejected.

This is intentional: a schema conflict should be explicit instead of silently corrupting shared memory.
