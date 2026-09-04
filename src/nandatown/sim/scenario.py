"""Scenario definitions: a short YAML file describes a whole run.

A scenario specifies the participating agents, their roles, the
protocol plugin used at each layer, experimental conditions such as
dropped messages or adversarial agents, and the seed.
"""

from __future__ import annotations

import importlib.resources
import math
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..layers import DEFAULT_PLUGINS, LAYER_NAMES


class AgentSpec(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    role: str
    config: dict[str, Any] = {}


class FaultRule(BaseModel):
    model_config = ConfigDict(frozen=True)

    action: Literal["drop", "duplicate", "delay", "drop_rate"]
    kind: str = ""
    nth: int = Field(default=1, ge=1)
    delay: float = Field(default=0.0, ge=0)
    rate: float = Field(default=0.0, ge=0, le=1)

    @field_validator("nth", mode="before")
    @classmethod
    def _validate_nth(cls, value):
        if type(value) is not int:
            raise ValueError("nth must be an integer")
        return value

    @field_validator("delay", "rate", mode="before")
    @classmethod
    def _validate_real_number(cls, value):
        if type(value) not in (int, float) or not math.isfinite(value):
            raise ValueError("must be a finite real number")
        return value


class ScenarioSpec(BaseModel):
    name: str
    description: str = ""
    seed: int = 42
    layers: dict[str, str] = {}
    agents: list[AgentSpec]
    faults: list[FaultRule] = []
    redact_fields: list[str] = []
    max_time: float = 1000.0
    validator: str = ""
    plugin_files: list[str] = []
    adaptations: list[str] = []

    @model_validator(mode="after")
    def _fill_defaults(self):
        merged = dict(DEFAULT_PLUGINS)
        for layer, plugin in self.layers.items():
            if layer not in LAYER_NAMES:
                raise ValueError(f"unknown layer {layer!r}")
            merged[layer] = plugin
        self.layers = merged
        if not self.validator:
            self.validator = self.name
        return self


def load_scenario_text(text: str) -> ScenarioSpec:
    data = yaml.safe_load(text)
    if isinstance(data, dict) and isinstance(data.get("agents"), dict):
        from .upstream import adapt_upstream

        return adapt_upstream(data)
    return ScenarioSpec.model_validate(data)


def load_scenario_file(path: str) -> ScenarioSpec:
    import os

    with open(path) as f:
        spec = load_scenario_text(f.read())
    base = os.path.dirname(os.path.abspath(path))
    spec.plugin_files = [
        p if os.path.isabs(p) else os.path.join(base, p)
        for p in spec.plugin_files
    ]
    return spec


def _bundled_dir():
    return importlib.resources.files("nandatown.sim") / "scenarios"


def bundled_scenarios() -> dict[str, str]:
    """Name to one-line description for every bundled scenario."""
    out = {}
    for entry in sorted(_bundled_dir().iterdir(),
                        key=lambda e: e.name):
        if entry.name.endswith(".yaml"):
            spec = load_scenario_text(entry.read_text())
            out[spec.name] = spec.description
    return out


def load_bundled(name: str) -> ScenarioSpec:
    path = _bundled_dir() / f"{name}.yaml"
    try:
        return load_scenario_text(path.read_text())
    except FileNotFoundError:
        raise KeyError(f"no bundled scenario {name!r};"
                       f" available: {sorted(bundled_scenarios())}")
