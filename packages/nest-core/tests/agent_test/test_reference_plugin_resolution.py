# SPDX-License-Identifier: Apache-2.0
"""Tests for profile-pinned reference plugin resolution."""

from __future__ import annotations

import importlib.metadata
from pathlib import Path
from typing import Any, cast

import pytest
from nest_core.builtin_scenarios import builtin_path
from nest_core.plugins import PluginRegistry
from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_plugins_reference.registry.gossip import GossipRegistry
from nest_plugins_reference.registry.in_memory import InMemoryRegistry


class _CollidingRegistry:
    async def register(self, card: object) -> None:
        return None

    async def lookup(self, query: object) -> list[object]:
        return []


class _EntryPoint:
    name = "in_memory"

    def load(self) -> type[_CollidingRegistry]:
        return _CollidingRegistry


def test_reference_resolution_bypasses_colliding_entry_point(monkeypatch: Any) -> None:
    def entry_points(*, group: str) -> list[_EntryPoint]:
        if group == "nest.plugins.registry":
            return [_EntryPoint()]
        return []

    monkeypatch.setattr(importlib.metadata, "entry_points", entry_points)
    registry = PluginRegistry()

    assert registry.resolve("registry", "in_memory") is _CollidingRegistry
    assert registry.resolve_reference("registry", "in_memory") is InMemoryRegistry
    assert (
        f"{registry.resolve_reference('registry', 'in_memory').__module__}."
        f"{registry.resolve_reference('registry', 'in_memory').__name__}"
        == "nest_plugins_reference.registry.in_memory.InMemoryRegistry"
    )


@pytest.mark.asyncio
async def test_generic_scenario_runner_honors_entry_point_precedence(
    monkeypatch: Any, tmp_path: Path
) -> None:
    def entry_points(*, group: str) -> list[_EntryPoint]:
        if group == "nest.plugins.registry":
            return [_EntryPoint()]
        return []

    monkeypatch.setattr(importlib.metadata, "entry_points", entry_points)
    config = ScenarioConfig.from_yaml(builtin_path("capability_fulfillment"))
    config.output.trace = str(tmp_path / "collision.jsonl")
    runner = ScenarioRunner(config)

    await runner.run()

    assert type(runner.resolved_plugins["registry"]) is _CollidingRegistry


@pytest.mark.asyncio
async def test_generic_runner_resolves_configured_registry_without_profile_policy(
    tmp_path: Path,
) -> None:
    config = ScenarioConfig.from_yaml(builtin_path("capability_fulfillment"))
    config.layers.registry = "gossip"
    config.output.trace = str(tmp_path / "mutated-registry.jsonl")
    runner = ScenarioRunner(config)

    plugins = cast("Any", runner)._resolve_plugins()

    assert plugins["registry"] is GossipRegistry
    assert not Path(config.output.trace).exists()


def test_reference_resolution_rejects_unknown_reference() -> None:
    registry = PluginRegistry()

    try:
        registry.resolve_reference("registry", "third_party_only")
    except KeyError as exc:
        assert "No reference plugin found" in str(exc)
    else:
        raise AssertionError("unknown reference plugin unexpectedly resolved")
