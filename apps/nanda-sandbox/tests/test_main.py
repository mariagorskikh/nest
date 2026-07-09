# SPDX-License-Identifier: Apache-2.0
# pyright: reportUnknownMemberType=false
# pyright: reportUnknownVariableType=false
# pyright: reportUnknownArgumentType=false
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

# Add app directory to sys.path so we can import main
sys.path.append(str(Path(__file__).parent.parent))

# Inject default dev key into environment before importing app to allow tests to run fail-closed
os.environ["SANDBOX_API_KEY"] = "nanda-sandbox-local-dev-fallback"

from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

TEST_API_KEY = os.environ["SANDBOX_API_KEY"]
HEADERS = {"X-API-Key": TEST_API_KEY}


def test_root() -> None:
    response: Any = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_health() -> None:
    response: Any = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_scenarios() -> None:
    response: Any = client.get("/scenarios")
    assert response.status_code == 200
    scenarios = response.json()["scenarios"]
    assert "marketplace" in scenarios
    assert "auction" in scenarios


def test_simulate_unauthorized() -> None:
    response: Any = client.post("/simulate", content="name: test")
    assert response.status_code == 401
    assert "Unauthorized" in response.json()["errors"][0]


def test_simulate_valid() -> None:
    yaml_content = """
name: test_sandbox_sim
description: "A minimal sandbox simulation run"
tier: 1
seed: 42
agents:
  count: 2
  brain: state-machine
  roles: []
layers:
  transport: in_memory
  comms: nest_native
task:
  type: marketplace
  config: {}
duration: "ticks: 10"
metrics:
  - message_count
output:
  trace: ./traces/sandbox_test.jsonl
"""
    response: Any = client.post("/simulate", content=yaml_content, headers=HEADERS)
    assert response.status_code == 200
    data: dict[str, Any] = response.json()
    assert data["success"] is True
    assert "metrics" in data
    assert "validation" in data
    assert "trace_summary" in data


def test_simulate_invalid_yaml() -> None:
    response: Any = client.post("/simulate", content="bad: [yaml: structure", headers=HEADERS)
    assert response.status_code == 400
    data: dict[str, Any] = response.json()
    assert data["success"] is False
    assert any("Invalid YAML syntax" in err for err in data["errors"])


def test_simulate_invalid_config() -> None:
    # A config with invalid fields (e.g. tier 99) will fail pydantic parsing
    yaml_content = """
name: invalid_config_sim
tier: 99
duration: "ticks: 10"
"""
    response: Any = client.post("/simulate", content=yaml_content, headers=HEADERS)
    assert response.status_code == 400
    data: dict[str, Any] = response.json()
    assert data["success"] is False
    assert any("Invalid scenario configuration parameters" in err for err in data["errors"])


def test_get_skill_md() -> None:
    response: Any = client.get("/skill.md")
    assert response.status_code == 200
    assert "NANDA Simulation Sandbox" in response.text


def test_simulate_yaml_anchors_rejected() -> None:
    # A config containing anchors or aliases will be rejected
    yaml_content = """
name: &anchor_name anchor_sim
tier: 1
duration: "ticks: 10"
"""
    response: Any = client.post("/simulate", content=yaml_content, headers=HEADERS)
    assert response.status_code == 400
    data: dict[str, Any] = response.json()
    assert data["success"] is False
    assert any("anchors/aliases" in err for err in data["errors"])
