"""Adapter for upstream projnanda/nandatown scenario files.

The upstream format declares agent populations as roles with counts,
uses different layer keys and plugin ids, tick durations, and rate
based failures. This adapter translates any of that into a runnable
local ScenarioSpec, mapping upstream roles onto the town's reference
roles per task type and substituting upstream layer plugins with the
local defaults. Adaptation notes disclose mapped roles, substituted
plugins, and unsupported failure declarations. The generic adapted
validator judges the local reference flow, not the original scenario's
agent configuration, protocol implementation, or validators.
"""

from __future__ import annotations

import re
from typing import Any

from .scenario import AgentSpec, FaultRule, ScenarioSpec

LAYER_KEY_MAP = {"comms": "communication", "datafacts": "data_facts"}

MAX_AGENTS = 30

# Per-task-type maps from upstream role names onto reference roles,
# plus the roles the local protocol flow cannot run without.
TASK_MAP: dict[str, dict[str, Any]] = {
    "voting": {"roles": {"proposer": "voter", "coordinator": "ballot_box",
                         "voter": "voter", "tally": "ballot_box"},
               "required": ["ballot_box", "voter"]},
    "marketplace": {"roles": {"buyer": "buyer", "seller": "seller",
                              "merchant": "seller", "client": "buyer",
                              "payer": "buyer", "payee": "seller",
                              "consumer": "buyer", "provider": "seller"},
                    "required": ["buyer", "seller"]},
    "auction": {"roles": {"auctioneer": "auctioneer", "bidder": "bidder",
                          "seller": "auctioneer", "buyer": "bidder"},
                "required": ["auctioneer", "bidder"]},
    "consensus": {"roles": {"proposer": "proposer",
                            "coordinator": "proposer",
                            "leader": "proposer", "acceptor": "acceptor",
                            "replica": "acceptor", "voter": "acceptor",
                            "byzantine": "acceptor",
                            "follower": "acceptor"},
                  "required": ["proposer", "acceptor"]},
    "supply_chain": {"roles": {"customer": "customer",
                               "manufacturer": "manufacturer",
                               "supplier": "supplier",
                               "distributor": "supplier",
                               "buyer": "customer"},
                     "required": ["customer", "manufacturer",
                                  "supplier"]},
    "capability_fulfillment": {"roles": {"requester": "buyer",
                                         "provider": "seller",
                                         "client": "buyer",
                                         "service": "seller"},
                               "required": ["buyer", "seller"]},
    "spoofing": {"roles": {"honest": "seller", "seller": "seller",
                           "buyer": "buyer", "client": "buyer",
                           "rogue": "spoofer", "sybil": "spoofer",
                           "attacker": "spoofer", "spoofer": "spoofer"},
                 "required": ["buyer", "seller"]},
}

TASK_ALIASES = {
    "escrow_marketplace": "marketplace",
    "shell_marketplace": "marketplace",
    "multi_attribute_market": "marketplace",
    "trust_gated_exchange": "marketplace",
    "receipt_reputation": "marketplace",
    "reputation": "marketplace",
    "streaming_payments": "marketplace",
    "empic_payments": "marketplace",
    "sealed_bid_with_privacy": "auction",
    "bft_consensus": "consensus",
    "sybil_bond": "spoofing",
    "rogue_trusted_agent": "spoofing",
    "provenance_supply_chain": "supply_chain",
}


def _default_config(role: str, index: int) -> dict[str, Any]:
    if role == "seller":
        return {"sku": "widget", "ask_cents": 1995 + 50 * index,
                "floor_cents": 1700, "stock": 100, "balance_cents": 0}
    if role == "buyer":
        return {"sku": "widget", "quantity": 2, "cap_cents": 2500,
                "balance_cents": 10000, "rounds": 1}
    if role == "voter":
        return {"choice": ["apricot", "plum"][index % 2]}
    if role == "ballot_box":
        return {"choices": ["apricot", "plum"], "close_after": 3.0}
    if role == "bidder":
        return {"valuation_cents": 500 + 100 * index,
                "bid_delay": 1.0 + 0.1 * index, "balance_cents": 5000}
    if role == "auctioneer":
        return {"item": "lot-1", "close_after": 3.0, "balance_cents": 0}
    if role == "proposer":
        return {"value": "v42", "retry_after": 1.5}
    if role == "customer":
        return {"product": "cart", "price_cents": 10000,
                "balance_cents": 12000}
    if role == "manufacturer":
        return {"product": "cart", "components": ["axle", "wheel"],
                "bid_wait": 1.0, "assembly_delay": 0.5,
                "balance_cents": 2000}
    if role == "supplier":
        return {"component": ["axle", "wheel"][index % 2],
                "price_cents": 400 + 50 * index, "balance_cents": 0}
    if role == "spoofer":
        return {"claimed_capability": "sell.widget",
                "forge_key_of": "shadow", "balance_cents": 0}
    return {}


def _resolve_task(task_type: str) -> tuple[str, dict[str, Any]]:
    key = TASK_ALIASES.get(task_type, task_type)
    for prefix, alias in TASK_ALIASES.items():
        if task_type.startswith(prefix):
            key = alias
    if key in TASK_MAP:
        return key, TASK_MAP[key]
    return "exchange", {"roles": {}, "required": ["buyer", "seller"]}


def _parse_ticks(duration: Any) -> float:
    if isinstance(duration, str):
        match = re.search(r"(\d+)", duration)
        if match:
            return min(float(match.group(1)), 300.0)
    if isinstance(duration, (int, float)):
        return min(float(duration), 300.0)
    return 60.0


def adapt_upstream(data: dict[str, Any]) -> ScenarioSpec:
    adaptations: list[str] = []
    name = data.get("name", "upstream")
    task = data.get("task", {}) or {}
    task_type = str(task.get("type", "exchange"))
    mapped_task, task_map = _resolve_task(task_type)
    if mapped_task != task_type:
        adaptations.append(f"task {task_type} adapted as {mapped_task}")

    # Roles with counts become named reference agents.
    role_map: dict[str, str] = task_map["roles"]
    upstream_roles = (data.get("agents", {}) or {}).get("roles", [])
    declared_total = sum(int(e.get("count", 1)) for e in upstream_roles)
    scale = 1.0
    if declared_total > MAX_AGENTS:
        scale = MAX_AGENTS / declared_total
        adaptations.append(
            f"population of {declared_total} scaled to about"
            f" {MAX_AGENTS} agents, ratios preserved")
    agents: list[AgentSpec] = []
    per_role_index: dict[str, int] = {}
    unmapped_next = ["buyer", "seller"]
    total = 0
    for entry in upstream_roles:
        upstream_role = entry.get("name", "agent")
        count = max(1, round(int(entry.get("count", 1)) * scale))
        local_role = role_map.get(upstream_role)
        if local_role is None:
            local_role = (unmapped_next.pop(0) if unmapped_next
                          else "seller")
            adaptations.append(f"role {upstream_role} adapted as"
                               f" {local_role}")
        elif local_role != upstream_role:
            adaptations.append(f"role {upstream_role} adapted as"
                               f" {local_role}")
        for i in range(count):
            if total >= MAX_AGENTS:
                adaptations.append(
                    f"population capped at {MAX_AGENTS} agents")
                break
            # Singleton roles never multiply.
            if local_role in ("ballot_box", "auctioneer", "proposer",
                              "manufacturer", "customer") \
                    and any(a.role == local_role for a in agents):
                adaptations.append(
                    f"extra {upstream_role} folded into one"
                    f" {local_role}")
                break
            idx = per_role_index.get(local_role, 0)
            per_role_index[local_role] = idx + 1
            suffix = f"-{idx + 1}" if count > 1 or idx else ""
            agents.append(AgentSpec(
                name=f"{upstream_role}{suffix}", role=local_role,
                config=_default_config(local_role, idx)))
            total += 1

    for required in task_map["required"]:
        if not any(a.role == required for a in agents):
            idx = per_role_index.get(required, 0)
            agents.append(AgentSpec(name=f"town-{required}",
                                    role=required,
                                    config=_default_config(required,
                                                           idx)))
            adaptations.append(f"added a reference {required}: the"
                               f" {mapped_task} flow cannot run without"
                               " one")

    # Layers: keys translated, upstream plugin ids substituted.
    upstream_layers = data.get("layers", {}) or {}
    substituted = []
    for key, plugin in upstream_layers.items():
        local_key = LAYER_KEY_MAP.get(key, key)
        substituted.append(f"{local_key} {plugin}")
    if substituted:
        adaptations.append("upstream layer plugins substituted by local"
                           " defaults: " + ", ".join(substituted))

    # Failures: rates become the seeded drop_rate fault.
    faults: list[FaultRule] = []
    failures = data.get("failures", {}) or {}
    drop = float(failures.get("message_drop", 0) or 0)
    if drop > 0:
        faults.append(FaultRule(action="drop_rate", rate=min(drop, 0.2)))
        if drop > 0.2:
            adaptations.append(f"message_drop {drop} capped at 0.2 so"
                               " the flow can still complete")
    for key in failures:
        if key != "message_drop":
            # Do not interpret unsupported values or copy their payloads
            # into public evidence. Even a zero/disabled declaration needs
            # disclosure: accepting it does not establish support for it.
            adaptations.append(f"failures.{key} not modeled by the"
                               " adapted reference flow")

    return ScenarioSpec(
        name=f"upstream-{name}",
        description=f"Adapted from upstream scenario {name!r}"
                    f" (task {task_type}). "
                    + (data.get("description", "") or ""),
        seed=int(data.get("seed", 42)),
        agents=agents,
        faults=faults,
        max_time=_parse_ticks(data.get("duration")),
        validator="adapted",
        adaptations=adaptations,
    )
