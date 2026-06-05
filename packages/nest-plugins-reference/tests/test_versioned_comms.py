# SPDX-License-Identifier: Apache-2.0
"""Tests for the versioned comms plugin."""

from __future__ import annotations

import base64
import json
from typing import Any

import pytest
from nest_core.types import AgentId, Message, MessageId
from nest_plugins_reference.comms.versioned import (
    SCHEMA_VERSION,
    UnsupportedSchemaError,
    VersionedComms,
)


def _msg(payload: bytes = b"hi", metadata: dict[str, Any] | None = None) -> Message:
    return Message(
        id=MessageId("m1"),
        sender=AgentId("a1"),
        receiver=AgentId("a2"),
        payload=payload,
        metadata=metadata or {},
    )


def _raw(**fields: Any) -> bytes:
    base: dict[str, Any] = {
        "id": "m1",
        "sender": "a1",
        "receiver": "a2",
        "payload": base64.b64encode(b"x").decode("ascii"),
        "correlation_id": None,
        "timestamp": 0,
        "metadata": {},
    }
    base.update(fields)
    return json.dumps(base).encode("utf-8")


class TestRoundTrip:
    def test_serialize_stamps_schema_version_and_kind(self) -> None:
        comms = VersionedComms(AgentId("a1"))
        data = json.loads(comms.serialize(_msg()))
        assert data["schema_version"] == SCHEMA_VERSION
        assert "kind" in data

    def test_roundtrip_preserves_payload_and_parties(self) -> None:
        comms = VersionedComms(AgentId("a1"))
        msg = comms.deserialize(comms.serialize(_msg(b"hello")))
        assert msg.payload == b"hello"
        assert msg.sender == AgentId("a1")
        assert msg.receiver == AgentId("a2")

    def test_serialize_is_deterministic(self) -> None:
        comms = VersionedComms(AgentId("a1"))
        assert comms.serialize(_msg(b"x")) == comms.serialize(_msg(b"x"))


class TestForwardCompat:
    def test_unknown_field_preserved_through_roundtrip(self) -> None:
        comms = VersionedComms(AgentId("a1"))
        msg = comms.deserialize(_raw(schema_version="2.5", kind="greeting", priority="high"))
        out = json.loads(comms.serialize(msg))
        assert out["priority"] == "high"
        assert out["kind"] == "greeting"

    def test_higher_minor_version_accepted(self) -> None:
        comms = VersionedComms(AgentId("a1"))
        msg = comms.deserialize(_raw(schema_version="2.9"))
        assert msg.sender == AgentId("a1")


class TestMajorSafety:
    def test_unsupported_major_raises(self) -> None:
        comms = VersionedComms(AgentId("a1"))
        with pytest.raises(UnsupportedSchemaError):
            comms.deserialize(_raw(schema_version="3.0"))

    def test_malformed_version_raises(self) -> None:
        comms = VersionedComms(AgentId("a1"))
        with pytest.raises(UnsupportedSchemaError):
            comms.deserialize(_raw(schema_version="not-a-version"))


class TestBackwardCompat:
    def test_legacy_envelope_without_version_accepted(self) -> None:
        comms = VersionedComms(AgentId("a1"))
        msg = comms.deserialize(_raw())  # no schema_version (nest_native style)
        assert msg.payload == b"x"

    def test_v1_major_accepted(self) -> None:
        comms = VersionedComms(AgentId("a1"))
        msg = comms.deserialize(_raw(schema_version="1.4"))
        assert msg.sender == AgentId("a1")
