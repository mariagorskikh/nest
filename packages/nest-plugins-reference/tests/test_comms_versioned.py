# SPDX-License-Identifier: Apache-2.0
"""Tests for the versioned comms plugin: round-trip, compat, and rejection.

Persona note (wire-compat engineer): the invariants under test are the ones a
rolling upgrade lives or dies on -- lossless round-trip, MUST-preserve unknown
fields from newer minors, and a hard refusal of breaking majors.
"""

from __future__ import annotations

import base64
import json
import string
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from nest_core.layers.comms import CommsProtocol
from nest_core.plugins import PluginRegistry
from nest_core.types import AgentId, Message, MessageId
from nest_plugins_reference.comms.versioned import (
    KNOWN_FIELDS,
    RESERVED_METADATA_KEYS,
    SCHEMA_MAJOR,
    SCHEMA_VERSION,
    UnsupportedSchemaError,
    VersionedComms,
)

_AGENT = AgentId("auditor-0")


def _comms() -> VersionedComms:
    return VersionedComms(_AGENT)


# ---------------------------------------------------------------------------
# Hypothesis strategies for canonical envelopes
# ---------------------------------------------------------------------------

_NAME = st.text(alphabet=string.ascii_letters + string.digits + "-", min_size=1, max_size=10)
_JSON_SCALAR = st.none() | st.booleans() | st.integers() | st.text(max_size=12)
_META_KEY = st.text(alphabet=string.ascii_letters, min_size=1, max_size=8).filter(
    lambda k: k not in RESERVED_METADATA_KEYS
)
_UNKNOWN_KEY = st.text(alphabet=string.ascii_letters + "-", min_size=1, max_size=8).filter(
    lambda k: k not in KNOWN_FIELDS
)


@st.composite
def _envelopes(draw: st.DrawFn) -> dict[str, Any]:
    """Draw a canonical same-major (1.x) envelope, possibly with unknown fields."""
    minor = draw(st.integers(min_value=0, max_value=99))
    payload = draw(st.binary(max_size=24))
    env: dict[str, Any] = {
        "schema_version": f"1.{minor}",
        "kind": draw(st.text(alphabet=string.ascii_letters, min_size=1, max_size=8)),
        "id": draw(_NAME),
        "sender": draw(_NAME),
        "receiver": draw(_NAME),
        "payload": base64.b64encode(payload).decode("ascii"),
        "correlation_id": draw(st.none() | _NAME),
        "timestamp": draw(
            st.none()
            | st.floats(min_value=0.0, max_value=1e9, allow_nan=False, allow_infinity=False)
        ),
        "metadata": draw(st.dictionaries(_META_KEY, _JSON_SCALAR, max_size=3)),
    }
    for key, value in draw(st.dictionaries(_UNKNOWN_KEY, _JSON_SCALAR, max_size=3)).items():
        env[key] = value
    return env


# ---------------------------------------------------------------------------
# Round-trip properties
# ---------------------------------------------------------------------------


class TestRoundTrip:
    @settings(max_examples=200, deadline=None)
    @given(env=_envelopes())
    def test_wire_round_trip_is_canonical_and_stable(self, env: dict[str, Any]) -> None:
        """serialize(deserialize(raw)) reproduces the canonical bytes exactly."""
        comms = _comms()
        raw = json.dumps(env, sort_keys=True).encode("utf-8")
        msg = comms.deserialize(raw)
        assert comms.serialize(msg) == raw
        assert comms.deserialize(comms.serialize(msg)) == msg

    @settings(max_examples=200, deadline=None)
    @given(env=_envelopes())
    def test_unknown_fields_are_preserved(self, env: dict[str, Any]) -> None:
        """Every top-level field this build doesn't own survives the round-trip."""
        comms = _comms()
        expected_unknown = {k: v for k, v in env.items() if k not in KNOWN_FIELDS}
        msg = comms.deserialize(json.dumps(env).encode("utf-8"))
        assert msg.metadata.get("_unknown", {}) == expected_unknown
        # ...and they reappear at the top level when re-serialized.
        reemitted = json.loads(comms.serialize(msg))
        for key, value in expected_unknown.items():
            assert reemitted[key] == value


# ---------------------------------------------------------------------------
# Compatibility contract
# ---------------------------------------------------------------------------


class TestCompatibility:
    def test_basic_payload_round_trip(self) -> None:
        comms = _comms()
        msg = Message(
            id=MessageId("m1"),
            sender=AgentId("a1"),
            receiver=AgentId("a2"),
            payload=b"hello world",
            metadata={"kind": "offer"},
        )
        back = comms.deserialize(comms.serialize(msg))
        assert back.payload == b"hello world"
        assert back.metadata["kind"] == "offer"
        assert back.metadata["schema_version"] == SCHEMA_VERSION

    def test_higher_minor_is_accepted(self) -> None:
        comms = _comms()
        env = _wire(version="1.99", extra={"future_flag": True})
        msg = comms.deserialize(env)
        assert msg.metadata["_unknown"] == {"future_flag": True}

    def test_missing_version_treated_as_oldest(self) -> None:
        """A pre-versioning envelope (no schema_version) is read as 1.0."""
        comms = _comms()
        raw = json.dumps(
            {
                "id": "m1",
                "sender": "a1",
                "receiver": "a2",
                "payload": base64.b64encode(b"x").decode("ascii"),
                "correlation_id": None,
                "timestamp": None,
                "metadata": {},
            }
        ).encode("utf-8")
        msg = comms.deserialize(raw)
        assert msg.metadata["schema_version"] == "1.0"


class TestRejection:
    def test_higher_major_is_rejected(self) -> None:
        comms = _comms()
        with pytest.raises(UnsupportedSchemaError) as exc:
            comms.deserialize(_wire(version="2.0"))
        assert exc.value.version == "2.0"

    @settings(max_examples=50, deadline=None)
    @given(major=st.integers(min_value=SCHEMA_MAJOR + 1, max_value=99))
    def test_any_future_major_is_rejected(self, major: int) -> None:
        comms = _comms()
        with pytest.raises(UnsupportedSchemaError):
            comms.deserialize(_wire(version=f"{major}.0"))

    def test_malformed_version_is_rejected(self) -> None:
        comms = _comms()
        with pytest.raises(UnsupportedSchemaError):
            comms.deserialize(_wire(version="not-a-version"))

    def test_unparseable_envelope_is_rejected(self) -> None:
        comms = _comms()
        with pytest.raises(UnsupportedSchemaError):
            comms.deserialize(b"{not json")

    def test_non_object_envelope_is_rejected(self) -> None:
        comms = _comms()
        with pytest.raises(UnsupportedSchemaError):
            comms.deserialize(b"[1, 2, 3]")

    def test_error_is_a_value_error(self) -> None:
        """Existing ``except ValueError`` guards keep catching us."""
        assert issubclass(UnsupportedSchemaError, ValueError)


# ---------------------------------------------------------------------------
# API fit
# ---------------------------------------------------------------------------


class TestApiFit:
    def test_satisfies_comms_protocol(self) -> None:
        assert isinstance(_comms(), CommsProtocol)

    def test_resolvable_from_registry(self) -> None:
        cls = PluginRegistry().resolve("comms", "versioned")
        assert cls is VersionedComms


def _wire(*, version: str, extra: dict[str, Any] | None = None) -> bytes:
    """Build envelope bytes at a given version for rejection/compat tests."""
    env: dict[str, Any] = {
        "schema_version": version,
        "kind": "offer",
        "id": "m1",
        "sender": "a1",
        "receiver": "a2",
        "payload": base64.b64encode(b"x").decode("ascii"),
        "correlation_id": None,
        "timestamp": None,
        "metadata": {},
    }
    if extra:
        env.update(extra)
    return json.dumps(env).encode("utf-8")
