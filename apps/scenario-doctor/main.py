# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from typing import Any

import yaml
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

app = FastAPI(
    title="NANDA Scenario Doctor",
    description="Validation and linting service for NANDA Town scenario configurations.",
)

# Static listing of known layers and reference plugins
KNOWN_LAYERS: dict[str, list[str]] = {
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
    "datafacts": ["datafacts_v1", "cid_facts"],
}


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/layers")
async def get_layers() -> dict[str, dict[str, list[str]]]:
    return {"layers": KNOWN_LAYERS}


@app.post("/validate-scenario")
async def validate_scenario(request: Request) -> JSONResponse:
    body = await request.body()
    try:
        data = yaml.safe_load(body)
    except yaml.YAMLError as e:
        return JSONResponse(
            status_code=400,
            content={"valid": False, "errors": [f"Invalid YAML syntax: {e}"]},
        )

    if not isinstance(data, dict):
        return JSONResponse(
            status_code=400,
            content={"valid": False, "errors": ["Root of scenario must be a dictionary"]},
        )

    data_dict: dict[str, Any] = data
    errors: list[str] = []

    # Check mandatory root keys
    mandatory_keys = ["name", "description", "agents", "layers", "task", "duration", "output"]
    for key in mandatory_keys:
        if key not in data_dict:
            errors.append(f"Missing mandatory root key: '{key}'")

    # If keys exist, validate their types/sub-properties
    if "agents" in data_dict:
        agents = data_dict["agents"]
        if not isinstance(agents, dict):
            errors.append("'agents' must be a dictionary")
        else:
            agents_dict: dict[str, Any] = agents
            if "count" not in agents_dict:
                errors.append("Missing 'agents.count'")
            elif not isinstance(agents_dict["count"], int) or agents_dict["count"] <= 0:
                errors.append("'agents.count' must be a positive integer")

            if "brain" not in agents_dict:
                errors.append("Missing 'agents.brain'")
            elif not isinstance(agents_dict["brain"], str):
                errors.append("'agents.brain' must be a string")

    if "task" in data_dict:
        task = data_dict["task"]
        if not isinstance(task, dict):
            errors.append("'task' must be a dictionary")
        else:
            task_dict: dict[str, Any] = task
            if "type" not in task_dict:
                errors.append("Missing 'task.type'")
            elif not isinstance(task_dict["type"], str):
                errors.append("'task.type' must be a string")

    if "output" in data_dict:
        output = data_dict["output"]
        if not isinstance(output, dict):
            errors.append("'output' must be a dictionary")
        else:
            output_dict: dict[str, Any] = output
            if "trace" not in output_dict:
                errors.append("Missing 'output.trace'")
            elif not isinstance(output_dict["trace"], str):
                errors.append("'output.trace' must be a string")

    if "duration" in data_dict:
        duration = data_dict["duration"]
        if not isinstance(duration, str):
            errors.append("'duration' must be a string")
        elif not (duration.startswith("ticks:") or duration.startswith("seconds:")):
            errors.append("'duration' format must be 'ticks:<N>' or 'seconds:<N>'")

    if errors:
        return JSONResponse(status_code=400, content={"valid": False, "errors": errors})

    return JSONResponse(content={"valid": True})


@app.post("/lint")
async def lint(request: Request) -> JSONResponse:
    body = await request.body()
    try:
        data = yaml.safe_load(body)
    except yaml.YAMLError as e:
        raise HTTPException(status_code=400, detail=f"Invalid YAML syntax: {e}") from e

    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="Root of scenario must be a dictionary")

    data_dict: dict[str, Any] = data
    warnings: list[str] = []

    layers = data_dict.get("layers")
    if not layers:
        return JSONResponse(content={"clean": True, "warnings": []})

    if not isinstance(layers, dict):
        raise HTTPException(status_code=400, detail="'layers' key must be a dictionary")

    layers_dict: dict[str, Any] = layers
    for layer_name, plugin_name in layers_dict.items():
        if layer_name not in KNOWN_LAYERS:
            warnings.append(
                f"Unknown layer: '{layer_name}'. Must be one of {list(KNOWN_LAYERS.keys())}."
            )
            continue

        known_plugins = KNOWN_LAYERS[layer_name]
        if plugin_name not in known_plugins:
            warnings.append(
                f"Unknown plugin '{plugin_name}' for layer '{layer_name}'. "
                f"Must be one of {known_plugins}."
            )

    if warnings:
        return JSONResponse(content={"clean": False, "warnings": warnings})

    return JSONResponse(content={"clean": True, "warnings": []})
