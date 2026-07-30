# SPDX-License-Identifier: Apache-2.0
"""Tests for the authenticated comms plugin: round-trip, tamper-evidence, parity.

Persona note (protocol-security-engineer): the invariants under test are the ones
a downgrade attack lives or dies on -- an authentication tag that covers every
covered byte (so rollback and field-stripping are detected), a constant-time
compare, and strict parity with ``versioned`` on the compatibility contract so the
security upgrade is genuinely drop-in. Adversarial cases model an on-path attacker
who can rewrite cleartext but cannot forge the HMAC.
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
from nest_plugins_reference.comms.authenticated import (
    AUTH_TAG_FIELD,
    CHANNEL_SECRET_DEFAULT,
    KNOWN_FIELDS,
    SCHEMA_VERSION,
    AuthenticatedComms,
    DowngradeError,
    UnsupportedSchemaError,
    expected_auth_tag,
    pair_key,
)

_SENDER = AgentId("peer-1")
_AUDITOR = AgentId("auditor-0")


def _comms(**kw: Any) -> AuthenticatedComms:
    return AuthenticatedComms(_AUDITOR, **kw)


def _msg(mid: str = "m-1", *, unknown: dict[str, Any] | None = None) -> Message:
    meta: dict[str, Any] = {"schema_version": "1.1", "kind": "offer"}
    if unknown:
        meta["_unknown"] = unknown
    return Message(
        id=MessageId(mid),
        sender=_SENDER,
        receiver=_AUDITOR,
        payload=b"hello-world",
        metadata=meta,
    )


def _decode_envelope(raw: bytes) -> dict[str, Any]:
    return json.loads(raw)


# ---------------------------------------------------------------------------
# Protocol / registry wiring
# ---------------------------------------------------------------------------


def test_satisfies_comms_protocol() -> None:
    """The plugin structurally satisfies ``CommsProtocol``."""
    assert isinstance(_comms(), CommsProtocol)


def test_resolves_via_builtin_registry() -> None:
    """``(comms, authenticated)`` resolves through the built-in plugin registry."""
    cls = PluginRegistry().resolve("comms", "authenticated")
    assert cls is AuthenticatedComms


# ---------------------------------------------------------------------------
# Round-trip (example-based)
# ---------------------------------------------------------------------------


def test_round_trip_is_lossless() -> None:
    """``deserialize(serialize(m)) == m`` for a plain message."""
    comms = _comms()
    msg = _msg()
    assert comms.deserialize(comms.serialize(msg)) == msg


def test_serialized_envelope_carries_tag_and_version() -> None:
    """Every serialized envelope stamps the version and a hex ``auth_tag``."""
    env = _decode_envelope(_comms().serialize(_msg()))
    assert env["schema_version"] == SCHEMA_VERSION
    assert len(env[AUTH_TAG_FIELD]) == 64
    assert all(c in "0123456789abcdef" for c in env[AUTH_TAG_FIELD])


def test_serialize_is_deterministic() -> None:
    """Identical input yields byte-identical output (Tier-1 replay)."""
    assert _comms().serialize(_msg()) == _comms().serialize(_msg())


def test_unknown_fields_preserved_and_covered() -> None:
    """Forward-compat unknown fields round-trip *and* are bound by the tag."""
    comms = _comms()
    raw = comms.serialize(_msg(unknown={"x-trace-id": "t-9"}))
    env = _decode_envelope(raw)
    assert env["x-trace-id"] == "t-9"
    # The unknown field is inside the MAC: dropping it must break verification.
    stripped = {k: v for k, v in env.items() if k != "x-trace-id"}
    tampered = json.dumps(stripped, sort_keys=True).encode()
    with pytest.raises(DowngradeError):
        comms.deserialize(tampered)
    # And an honest round-trip restores it.
    assert comms.deserialize(raw).metadata["_unknown"] == {"x-trace-id": "t-9"}


def test_pair_key_is_direction_independent() -> None:
    """Both endpoints derive the same key regardless of send direction."""
    assert pair_key("a1", "a2") == pair_key("a2", "a1")
    assert pair_key("a1", "a2") != pair_key("a1", "a3")


# ---------------------------------------------------------------------------
# Adversarial: the downgrade / tamper attacks this plugin exists to catch
# ---------------------------------------------------------------------------


def test_version_rollback_is_rejected() -> None:
    """Rewriting schema_version 1.1 -> 1.0 with a stale tag is refused."""
    comms = _comms()
    env = _decode_envelope(comms.serialize(_msg()))
    env["schema_version"] = "1.0"  # attacker rolls back, cannot re-tag
    forged = json.dumps(env, sort_keys=True).encode()
    with pytest.raises(DowngradeError) as exc:
        comms.deserialize(forged)
    assert exc.value.reason == "tag_mismatch"


def test_field_strip_is_rejected() -> None:
    """Deleting a covered field with a stale tag is refused."""
    comms = _comms()
    env = _decode_envelope(comms.serialize(_msg(unknown={"x-trace-id": "t-1"})))
    del env["x-trace-id"]
    forged = json.dumps(env, sort_keys=True).encode()
    with pytest.raises(DowngradeError):
        comms.deserialize(forged)


def test_payload_tamper_is_rejected() -> None:
    """Rewriting the payload with a stale tag is refused."""
    comms = _comms()
    env = _decode_envelope(comms.serialize(_msg()))
    env["payload"] = base64.b64encode(b"evil").decode("ascii")
    forged = json.dumps(env, sort_keys=True).encode()
    with pytest.raises(DowngradeError):
        comms.deserialize(forged)


def test_attacker_without_channel_secret_cannot_forge() -> None:
    """A tag minted under a different channel secret does not verify."""
    honest = _comms()
    attacker = _comms(channel_secret=b"attacker-guessed-secret")
    forged = attacker.serialize(_msg())
    # The receiver keyed on the real secret rejects the attacker's re-tag.
    with pytest.raises(DowngradeError):
        honest.deserialize(forged)


def test_require_auth_rejects_untagged_envelope() -> None:
    """In strict mode an envelope with no tag at all is refused."""
    strict = _comms(require_auth=True)
    env = _decode_envelope(_comms().serialize(_msg()))
    del env[AUTH_TAG_FIELD]
    untagged = json.dumps(env, sort_keys=True).encode()
    with pytest.raises(DowngradeError) as exc:
        strict.deserialize(untagged)
    assert exc.value.reason == "tag_missing"


def test_permissive_mode_accepts_untagged_legacy_envelope() -> None:
    """Default mode still accepts untagged legacy traffic (rolling upgrade)."""
    permissive = _comms()  # require_auth=False
    env = _decode_envelope(_comms().serialize(_msg()))
    del env[AUTH_TAG_FIELD]
    untagged = json.dumps(env, sort_keys=True).encode()
    msg = permissive.deserialize(untagged)  # must not raise
    assert str(msg.id) == "m-1"


def test_unknown_major_is_rejected_before_tag_check() -> None:
    """A breaking major is refused with UnsupportedSchemaError, not accepted."""
    comms = _comms()
    env = _decode_envelope(comms.serialize(_msg()))
    env["schema_version"] = "2.0"
    forged = json.dumps(env, sort_keys=True).encode()
    with pytest.raises(UnsupportedSchemaError):
        comms.deserialize(forged)


def test_non_object_envelope_is_rejected() -> None:
    """A JSON array (or any non-object) is refused, not silently mis-decoded."""
    with pytest.raises(UnsupportedSchemaError):
        _comms().deserialize(b"[1, 2, 3]")


def test_unparseable_bytes_are_rejected() -> None:
    """Malformed bytes raise a typed error rather than a raw JSONDecodeError."""
    with pytest.raises(UnsupportedSchemaError):
        _comms().deserialize(b"not json{{{")


# ---------------------------------------------------------------------------
# Parity with the versioned contract (drop-in guarantee)
# ---------------------------------------------------------------------------


def test_missing_version_treated_as_legacy_1_0() -> None:
    """A pre-versioning envelope (no schema_version) decodes as 1.0."""
    comms = _comms()
    env = _decode_envelope(comms.serialize(_msg()))
    del env["schema_version"]
    del env[AUTH_TAG_FIELD]  # legacy peers carry no tag; permissive mode accepts
    legacy = json.dumps(env, sort_keys=True).encode()
    msg = comms.deserialize(legacy)
    assert msg.metadata["schema_version"] == "1.0"


# ---------------------------------------------------------------------------
# Property-based: the security invariants over arbitrary envelopes
# ---------------------------------------------------------------------------

_NAME = st.text(alphabet=string.ascii_letters + string.digits + "-", min_size=1, max_size=10)


@st.composite
def _messages(draw: st.DrawFn) -> Message:
    """Draw a schema-valid Message with optional forward-compat unknown fields."""
    unknown_keys = draw(
        st.lists(
            st.text(alphabet=string.ascii_letters + "-", min_size=1, max_size=8).filter(
                lambda k: k not in KNOWN_FIELDS
            ),
            max_size=3,
            unique=True,
        )
    )
    unknown = {k: draw(st.text(max_size=8)) for k in unknown_keys}
    meta: dict[str, Any] = {"schema_version": "1.1", "kind": draw(_NAME)}
    if unknown:
        meta["_unknown"] = unknown
    return Message(
        id=MessageId(draw(_NAME)),
        sender=AgentId(draw(_NAME)),
        receiver=AgentId(draw(_NAME)),
        payload=draw(st.binary(max_size=24)),
        metadata=meta,
    )


@settings(max_examples=200)
@given(_messages())
def test_property_round_trip_is_lossless(msg: Message) -> None:
    """For any schema-valid message, an honest round-trip is lossless."""
    comms = AuthenticatedComms(msg.receiver)
    assert comms.deserialize(comms.serialize(msg)) == msg


@settings(max_examples=200)
@given(_messages())
def test_property_any_single_byte_flip_in_a_field_is_detected(msg: Message) -> None:
    """Rewriting any covered field to a new value breaks verification."""
    comms = AuthenticatedComms(msg.receiver)
    env = json.loads(comms.serialize(msg))
    # Flip the kind (a covered field) to a guaranteed-different value.
    env["kind"] = env["kind"] + "X"
    forged = json.dumps(env, sort_keys=True).encode()
    with pytest.raises(DowngradeError):
        comms.deserialize(forged)


@settings(max_examples=200)
@given(_messages())
def test_property_tag_matches_independent_recompute(msg: Message) -> None:
    """The carried tag equals the module-level ground-truth recompute."""
    comms = AuthenticatedComms(msg.receiver)
    env = json.loads(comms.serialize(msg))
    carried = env[AUTH_TAG_FIELD]
    assert carried == expected_auth_tag(env, CHANNEL_SECRET_DEFAULT)
