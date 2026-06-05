# SPDX-License-Identifier: Apache-2.0
"""Tests for the comms schema-versioning validators.

The validators must PASS on a versioned-style trace (schema + unknown fields
preserved, unsupported-major rejected) and FAIL on a nest_native-style trace
(version/unknown fields dropped, v3 blindly forwarded).
"""

from __future__ import annotations

import base64
import json
from typing import Any

from nest_core.validators import (
    VALIDATORS,
    validate_comms_schema_version,
    validate_comms_unknown_field_preserved,
    validate_comms_unsupported_major_rejected,
    validate_events,
)

type Event = dict[str, Any]


def _forwarded(
    payload: str, schema: str | None = None, extra: dict[str, Any] | None = None
) -> Event:
    env: dict[str, Any] = {
        "id": "m",
        "sender": "forwarder-0",
        "receiver": "sink-0",
        "payload": base64.b64encode(payload.encode()).decode("ascii"),
        "kind": "x",
        "metadata": {},
    }
    if schema is not None:
        env["schema_version"] = schema
    if extra:
        env.update(extra)
    return {
        "ts": 0.0,
        "agent": "forwarder-0",
        "kind": "send",
        "to": "sink-0",
        "msg": json.dumps(env),
    }


# A compliant (versioned) trace: schema present, priority preserved, no v3 forwarded.
def _versioned_trace() -> list[Event]:
    return [
        _forwarded("greeting-v1", schema="2.0"),
        _forwarded("greeting-v2", schema="2.0", extra={"priority": "high"}),
    ]


class TestPassesOnVersioned:
    def test_all_validators_pass(self) -> None:
        results = validate_events(_versioned_trace(), "comms_versioning")
        assert results
        assert all(r.passed for r in results)

    def test_registered(self) -> None:
        assert "comms_versioning" in VALIDATORS
        assert len(VALIDATORS["comms_versioning"]) == 3


class TestFailsOnNestNative:
    def test_missing_schema_version_fails(self) -> None:
        [result] = validate_comms_schema_version([_forwarded("greeting-v1")])
        assert result.passed is False

    def test_dropped_unknown_field_fails(self) -> None:
        # v2 envelope forwarded WITHOUT the priority field
        [result] = validate_comms_unknown_field_preserved([_forwarded("greeting-v2", schema="2.0")])
        assert result.passed is False

    def test_v3_forwarded_fails(self) -> None:
        # an unsupported-major message reached the sink
        [result] = validate_comms_unsupported_major_rejected([_forwarded("probe-v3")])
        assert result.passed is False


class TestUnsupportedMajorRejected:
    def test_no_v3_forwarded_passes(self) -> None:
        [result] = validate_comms_unsupported_major_rejected(_versioned_trace())
        assert result.passed is True
