# SPDX-License-Identifier: Apache-2.0
"""Deterministic generation and drift checks for the seven packaged 1 schemas."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .contracts import DriverError, DriverReady
from .evidence import TestResult
from .profile_codecs import DEFAULT_PROFILE_CODECS

_DIALECT = "https://json-schema.org/draft/2020-12/schema"
_SCHEMA_DIRECTORY = Path(__file__).parent / "resources" / "schemas"


def _schema(document: dict[str, Any], *semantic_validation: str) -> dict[str, Any]:
    result = {"$schema": _DIALECT, **document}
    existing = result.get("x-town-semantic-validation", [])
    if semantic_validation:
        result["x-town-semantic-validation"] = [*existing, *semantic_validation]
    return result


def generated_schemas() -> dict[str, dict[str, Any]]:
    """Return all seven schemas from runtime models and the explicit codec registry."""
    return {
        "driver-error-1.schema.json": _schema(DriverError.model_json_schema()),
        "driver-ready-1.schema.json": _schema(DriverReady.model_json_schema()),
        "driver-request-1.schema.json": _schema(DEFAULT_PROFILE_CODECS.driver_request_schema()),
        "driver-response-1.schema.json": _schema(DEFAULT_PROFILE_CODECS.driver_response_schema()),
        "test-observation-1.schema.json": _schema(
            DEFAULT_PROFILE_CODECS.test_observation_schema(),
            "calendar-valid UTC RFC3339 timestamps",
            "payload_digest matches exact UTF-8 text",
            "routed response text is at most the profile UTF-8 byte limit",
        ),
        "test-profile-1.schema.json": _schema(DEFAULT_PROFILE_CODECS.test_profile_schema()),
        "test-result-1.schema.json": _schema(
            TestResult.model_json_schema(),
            "calendar-valid UTC RFC3339 timestamps",
            "literal loopback HTTP origin",
            "profile, scenario, checks, and coverage require codec-bound result validation",
        ),
    }


def generated_schema_bytes() -> dict[str, bytes]:
    """Render stable reviewable UTF-8 JSON with sorted keys and one final LF."""
    return {
        name: (json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode(
            "utf-8"
        )
        for name, schema in generated_schemas().items()
    }


def check_packaged_schemas() -> None:
    """Raise without writing when checked-in schema filenames or bytes drift."""
    generated = generated_schema_bytes()
    packaged_names = {path.name for path in _SCHEMA_DIRECTORY.glob("*.schema.json")}
    if packaged_names != set(generated):
        raise AssertionError(
            "packaged agent-test schema set drifted: "
            f"expected {sorted(generated)}, found {sorted(packaged_names)}"
        )
    drifted = [
        name
        for name, content in generated.items()
        if (_SCHEMA_DIRECTORY / name).read_bytes() != content
    ]
    if drifted:
        raise AssertionError(f"packaged agent-test schemas are stale: {', '.join(sorted(drifted))}")


def write_packaged_schemas() -> None:
    """Replace only the seven known packaged schema resources deterministically."""
    for name, content in generated_schema_bytes().items():
        (_SCHEMA_DIRECTORY / name).write_bytes(content)
