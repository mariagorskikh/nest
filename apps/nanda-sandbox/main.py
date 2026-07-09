# SPDX-License-Identifier: Apache-2.0
# pyright: reportUnknownMemberType=false
# pyright: reportUnknownVariableType=false
# pyright: reportUnknownArgumentType=false
# pyright: reportUnusedImport=false
from __future__ import annotations

import asyncio
import contextlib
import json
import os
import tempfile
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

import yaml
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_core.validators import validate_trace
from pydantic import ValidationError

app = FastAPI(
    title="NANDA Simulation Sandbox",
    description="Simulation-as-a-Service (SaaS) for running and validating NANDA Town scenarios.",
    openapi_url=None,
    docs_url=None,
    redoc_url=None,
)

# API Authentication Configuration - Environment Variable Driven
API_KEY_NAME = "X-API-Key"
API_KEY = os.environ["SANDBOX_API_KEY"]


class SafeNoAnchorLoader(yaml.SafeLoader):
    """YAML Loader that forbids anchors and aliases to prevent CPU/memory amplification."""

    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(yaml.AliasEvent):
            raise yaml.YAMLError("YAML aliases are disabled")
        event = self.peek_event()
        if event is not None and getattr(event, "anchor", None) is not None:
            raise yaml.YAMLError("YAML anchors are disabled")
        return super().compose_node(parent, index)


BUILTIN_SCENARIOS = [
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
    "failure_detection",
]

# Strict Allow-lists for Configuration Validation
ALLOWED_BRAINS = {"state-machine", "llm", "shell"}
ALLOWED_PLUGINS = {
    "transport": {"in_memory"},
    "comms": {"nest_native", "versioned"},
    "identity": {"did_key", "ed25519_rotating"},
    "registry": {"in_memory", "gossip"},
    "auth": {"jwt", "delegatable"},
    "trust": {"score_average", "agent_receipts"},
    "payments": {"prepaid_credits", "streaming", "escrow", "empic_escrow"},
    "coordination": {"contract_net", "hotstuff"},
    "negotiation": {"alternating_offers", "pareto"},
    "memory": {"blackboard", "lww_register"},
    "privacy": {"noop", "hybrid_x25519"},
    "datafacts": {"datafacts_v1", "cid_facts"},
}


class InMemoryRateLimiter:
    """Rate limiter using Token Bucket algorithm in-memory per IP."""

    def __init__(self, requests_per_minute: int = 15) -> None:
        self.limit = requests_per_minute
        self.tokens: dict[str, float] = defaultdict(lambda: float(requests_per_minute))
        self.last_updated: dict[str, float] = defaultdict(time.time)

    def is_allowed(self, ip: str) -> bool:
        now = time.time()
        elapsed = now - self.last_updated[ip]
        self.last_updated[ip] = now

        refill = elapsed * (self.limit / 60.0)
        self.tokens[ip] = min(float(self.limit), self.tokens[ip] + refill)

        if self.tokens[ip] >= 1.0:
            self.tokens[ip] -= 1.0
            return True
        return False


rate_limiter = InMemoryRateLimiter()


@app.get("/")
async def root() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/scenarios")
async def get_scenarios() -> dict[str, list[str]]:
    return {"scenarios": BUILTIN_SCENARIOS}


@app.post("/simulate")
async def simulate(request: Request) -> JSONResponse:
    # 1. Enforce Rate Limiting (Handle reverse proxy X-Forwarded-For header safely)
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        client_ip = forwarded_for.split(",")[0].strip()
    else:
        client_ip = request.client.host if request.client else "unknown"

    if not rate_limiter.is_allowed(client_ip):
        return JSONResponse(
            status_code=429, content={"success": False, "errors": ["Rate limit exceeded"]}
        )

    # 2. Enforce Authentication
    api_key = request.headers.get(API_KEY_NAME)
    if api_key != API_KEY:
        return JSONResponse(
            status_code=401,
            content={"success": False, "errors": ["Unauthorized: Invalid API Key"]},
        )

    # 3. Enforce Request Body Size Limit (1 MB)
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > 1024 * 1024:
                return JSONResponse(
                    status_code=413, content={"success": False, "errors": ["Payload too large"]}
                )
        except ValueError:
            pass

    body_bytes = b""
    async for chunk in request.stream():
        body_bytes += chunk
        if len(body_bytes) > 1024 * 1024:
            return JSONResponse(
                status_code=413, content={"success": False, "errors": ["Payload too large"]}
            )

    # 4. Parse YAML Off the Event Loop (using a loader that forbids anchors/aliases)
    try:
        data = await asyncio.to_thread(yaml.load, body_bytes, Loader=SafeNoAnchorLoader)
    except yaml.YAMLError:
        return JSONResponse(
            status_code=400,
            content={
                "success": False,
                "errors": ["Invalid YAML syntax or contains disabled anchors/aliases"],
            },
        )

    if not isinstance(data, dict):
        return JSONResponse(
            status_code=400,
            content={"success": False, "errors": ["Root of scenario must be a dictionary"]},
        )

    data_dict: dict[str, Any] = data

    # 6. Sanitize and Validate Config Settings
    agents_section = data_dict.get("agents")
    if isinstance(agents_section, dict):
        agent_count = agents_section.get("count")
        if isinstance(agent_count, int) and agent_count > 100:
            return JSONResponse(
                status_code=400,
                content={
                    "success": False,
                    "errors": ["Simulation agent count exceeds maximum limit (100)"],
                },
            )

        brain_val = agents_section.get("brain")
        if brain_val and brain_val not in ALLOWED_BRAINS:
            return JSONResponse(
                status_code=400,
                content={"success": False, "errors": [f"Unsupported brain type: {brain_val}"]},
            )

    duration_val = data_dict.get("duration")
    if isinstance(duration_val, str) and duration_val.startswith("ticks:"):
        try:
            ticks = int(duration_val.split(":")[1].strip())
            if ticks > 2000:
                return JSONResponse(
                    status_code=400,
                    content={
                        "success": False,
                        "errors": ["Simulation duration ticks exceed maximum limit (2000)"],
                    },
                )
        except ValueError:
            pass

    # Validate layer plugin choices against allow-list
    layers_section = data_dict.get("layers")
    if isinstance(layers_section, dict):
        for layer_name, plugin_name in layers_section.items():
            if layer_name not in ALLOWED_PLUGINS:
                return JSONResponse(
                    status_code=400,
                    content={"success": False, "errors": [f"Unknown layer: {layer_name}"]},
                )
            if plugin_name not in ALLOWED_PLUGINS[layer_name]:
                return JSONResponse(
                    status_code=400,
                    content={
                        "success": False,
                        "errors": [f"Unknown plugin {plugin_name} for layer {layer_name}"],
                    },
                )

    # Set default values for mandatory keys
    if "name" not in data_dict:
        data_dict["name"] = "sandbox_sim"
    if "description" not in data_dict:
        data_dict["description"] = "Autogenerated sandbox simulation run"

    # 7. Execute Simulation with Timeouts
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            trace_file = Path(tmpdir) / "trace.jsonl"

            # Reconstruct output configuration server-side to prevent path traversal writes
            data_dict["output"] = {"trace": str(trace_file), "report": None}

            # Model validate parsed configuration off event loop
            config = await asyncio.to_thread(ScenarioConfig.model_validate, data_dict)

            # Initialize ScenarioRunner
            runner = ScenarioRunner(config)

            # Run with a strict timeout limit to prevent CPU lockups
            try:
                await asyncio.wait_for(runner.run(), timeout=30.0)
            except TimeoutError:
                return JSONResponse(
                    status_code=504,
                    content={"success": False, "errors": ["Simulation execution timed out"]},
                )

            # Read simulation metrics
            metrics = runner.metrics

            # Run adversarial validators off event loop
            val_results = await asyncio.to_thread(validate_trace, trace_file, config.task.type)
            validation = [
                {"name": r.name, "passed": r.passed, "detail": r.detail} for r in val_results
            ]

            # Read trace events with UTF-8 encoding
            returned_events = []
            total_events = 0
            if trace_file.exists():
                with trace_file.open(encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            total_events += 1
                            if len(returned_events) < 100:
                                with contextlib.suppress(json.JSONDecodeError):
                                    returned_events.append(json.loads(line))

            return JSONResponse(
                content={
                    "success": True,
                    "metrics": metrics,
                    "validation": validation,
                    "trace_summary": {
                        "total_events": total_events,
                        "returned_events": returned_events,
                    },
                }
            )

    except ValidationError:
        return JSONResponse(
            status_code=400,
            content={
                "success": False,
                "errors": ["Invalid scenario configuration parameters"],
            },
        )
    except Exception:
        # Return generic error and hide filesystem/version/library traces
        return JSONResponse(
            status_code=500,
            content={
                "success": False,
                "errors": ["Simulation failed due to an internal execution error"],
            },
        )


@app.get("/skill.md")
async def get_skill_md() -> Response:
    skill_file = (
        Path(__file__).parent.parent.parent / "docs/hackathon/solutions/nanda-sandbox-skill.md"
    )
    if skill_file.exists():
        content = skill_file.read_text(encoding="utf-8")
    else:
        content = "SKILL.md file not found"
    return Response(content=content, media_type="text/markdown")
