# SPDX-License-Identifier: Apache-2.0
# pyright: ignore
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

# Add app directory to sys.path so we can import main
sys.path.append(str(Path(__file__).parent.parent))

from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


def test_health() -> None:
    response: Any = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_layers() -> None:
    response: Any = client.get("/layers")
    assert response.status_code == 200
    layers: dict[str, list[str]] = response.json()["layers"]
    assert "auth" in layers
    assert "jwt" in layers["auth"]
    assert "delegatable" in layers["auth"]
    assert len(layers) == 12


def test_validate_scenario_valid() -> None:
    yaml_content = """
name: test_scenario
description: "A valid test scenario"
tier: 1
agents:
  count: 4
  brain: state-machine
  roles: []
layers:
  auth: jwt
task:
  type: simple_task
  config: {}
duration: "ticks: 100"
output:
  trace: ./traces/test.jsonl
"""
    response: Any = client.post("/validate-scenario", content=yaml_content)
    assert response.status_code == 200
    assert response.json() == {"valid": True}


def test_validate_scenario_invalid() -> None:
    yaml_content = """
name: test_scenario
duration: 100
"""
    response: Any = client.post("/validate-scenario", content=yaml_content)
    assert response.status_code == 400
    data: dict[str, Any] = response.json()
    assert data["valid"] is False
    assert "Missing mandatory root key: 'description'" in data["errors"]


def test_lint_warnings() -> None:
    yaml_content = """
layers:
  auth: wrong_plugin
  wrong_layer: jwt
"""
    response: Any = client.post("/lint", content=yaml_content)
    assert response.status_code == 200
    data: dict[str, Any] = response.json()
    assert data["clean"] is False
    warnings: list[str] = data["warnings"]
    assert any("Unknown plugin" in w for w in warnings)
    assert any("Unknown layer" in w for w in warnings)


def test_lint_clean() -> None:
    yaml_content = """
layers:
  auth: jwt
"""
    response: Any = client.post("/lint", content=yaml_content)
    assert response.status_code == 200
    assert response.json() == {"clean": True, "warnings": []}
