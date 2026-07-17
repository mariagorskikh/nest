# SPDX-License-Identifier: Apache-2.0
"""Tests for the replay-safe comms plugin: replay rejection, tamper/version parity.

Persona note (protocol-security-engineer): ``AuthenticatedComms`` proves an
envelope was not rewritten; it says nothing about whether it was *replayed*.
The invariant under test here is narrow and specific: the first delivery of a
given id from a given sender is accepted, and every delivery after that is
refused with a typed :class:`ReplayError` -- even though the replayed bytes
are byte-for-byte identical to an honest, correctly-tagged envelope and would
sail through ``AuthenticatedComms`` unmodified.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from nest_core.layers.comms import CommsProtocol
from nest_core.plugins import PluginRegistry
from nest_core.types import AgentId, Message, MessageId
from nest_plugins_reference.comms.authenticated import DowngradeError
from nest_plugins_reference.comms.replay_safe import (
    DEFAULT_REPLAY_WINDOW,
    ReplayError,
    ReplaySafeComms,
)

_SENDER = AgentId("peer-1")
_OTHER_SENDER = AgentId("peer-2")
_AUDITOR = AgentId("auditor-0")


def _comms(**kw: Any) -> ReplaySafeComms:
    return ReplaySafeComms(_AUDITOR, **kw)


def _msg(mid: str = "m-1", sender: AgentId = _SENDER) -> Message:
    return Message(
        id=MessageId(mid),
        sender=sender,
        receiver=_AUDITOR,
        payload=b"hello-world",
        metadata={"schema_version": "1.1", "kind": "offer"},
    )


# ---------------------------------------------------------------------------
# Protocol / registry wiring
# ---------------------------------------------------------------------------


def test_satisfies_comms_protocol() -> None:
    """The plugin structurally satisfies ``CommsProtocol``."""
    assert isinstance(_comms(), CommsProtocol)


def test_resolves_via_builtin_registry() -> None:
    """``(comms, replay_safe)`` resolves through the built-in plugin registry."""
    cls = PluginRegistry().resolve("comms", "replay_safe")
    assert cls is ReplaySafeComms


def test_is_a_strict_authenticated_comms_subclass() -> None:
    """Drop-in claim: ``ReplaySafeComms`` inherits ``AuthenticatedComms`` wire behaviour."""
    from nest_plugins_reference.comms.authenticated import AuthenticatedComms

    assert issubclass(ReplaySafeComms, AuthenticatedComms)


# ---------------------------------------------------------------------------
# Round-trip parity with AuthenticatedComms (unaffected by the new behaviour)
# ---------------------------------------------------------------------------


def test_round_trip_is_lossless() -> None:
    """``deserialize(serialize(m)) == m`` for a plain message, first delivery."""
    comms = _comms()
    msg = _msg()
    assert comms.deserialize(comms.serialize(msg)) == msg


def test_serialize_is_deterministic() -> None:
    """Identical input yields byte-identical output (Tier-1 replay of the *simulation*)."""
    assert _comms().serialize(_msg()) == _comms().serialize(_msg())


# ---------------------------------------------------------------------------
# The bug this plugin exists to fix: AuthenticatedComms accepts a verbatim replay
# ---------------------------------------------------------------------------


def test_authenticated_comms_accepts_a_verbatim_replay() -> None:
    """Baseline failure: without replay memory, a captured envelope re-verifies.

    This is the exact gap flagged in ``authenticated.py``'s own docstring
    ("a verbatim re-send of a genuine envelope still verifies"). Demonstrating
    it here pins down *why* ``ReplaySafeComms`` needs to exist.
    """
    from nest_plugins_reference.comms.authenticated import AuthenticatedComms

    comms = AuthenticatedComms(_AUDITOR)
    raw = comms.serialize(_msg())
    first = comms.deserialize(raw)
    second = comms.deserialize(raw)  # captured & replayed verbatim
    assert first == second  # accepted twice -- no error, no distinction


# ---------------------------------------------------------------------------
# Adversarial: the replay attack this plugin exists to catch
# ---------------------------------------------------------------------------


def test_second_delivery_of_same_envelope_is_rejected() -> None:
    """A verbatim replay of an already-accepted envelope is refused."""
    comms = _comms()
    raw = comms.serialize(_msg())
    comms.deserialize(raw)  # first delivery: accepted
    with pytest.raises(ReplayError) as exc:
        comms.deserialize(raw)  # replay: rejected
    assert exc.value.message_id == "m-1"
    assert exc.value.sender == str(_SENDER)
    assert exc.value.reason == "replay"


def test_replay_error_is_a_downgrade_error() -> None:
    """``ReplayError`` still satisfies any ``except DowngradeError`` guard."""
    comms = _comms()
    raw = comms.serialize(_msg())
    comms.deserialize(raw)
    with pytest.raises(DowngradeError):
        comms.deserialize(raw)


def test_third_delivery_is_also_rejected() -> None:
    """Replay rejection is not a one-shot toggle -- every repeat after the first fails."""
    comms = _comms()
    raw = comms.serialize(_msg())
    comms.deserialize(raw)
    for _ in range(5):
        with pytest.raises(ReplayError):
            comms.deserialize(raw)


def test_tampered_replay_is_rejected_as_tamper_not_replay() -> None:
    """A rewritten copy of a delivered id fails on the tag, not the replay check.

    Tamper detection runs before replay bookkeeping: a forged envelope with a
    stale tag must be caught as a forgery regardless of whether its id has
    been seen before.
    """
    comms = _comms()
    raw = comms.serialize(_msg())
    comms.deserialize(raw)
    env = json.loads(raw)
    env["kind"] = "evil"  # covered field, stale tag no longer matches
    forged = json.dumps(env, sort_keys=True).encode()
    with pytest.raises(DowngradeError) as exc:
        comms.deserialize(forged)
    assert not isinstance(exc.value, ReplayError)


def test_different_senders_have_independent_replay_windows() -> None:
    """The same id from two different senders is not conflated as a replay."""
    comms = _comms()
    raw_a = comms.serialize(_msg(mid="m-shared", sender=_SENDER))
    raw_b = comms.serialize(_msg(mid="m-shared", sender=_OTHER_SENDER))
    comms.deserialize(raw_a)  # accepted: first time from peer-1
    comms.deserialize(raw_b)  # accepted: first time from peer-2, different sender
    with pytest.raises(ReplayError):
        comms.deserialize(raw_a)  # now a replay from peer-1


def test_two_distinct_ids_from_same_sender_both_accepted() -> None:
    """Replay tracking is keyed on id, not just sender -- distinct ids don't collide."""
    comms = _comms()
    raw_1 = comms.serialize(_msg(mid="m-1"))
    raw_2 = comms.serialize(_msg(mid="m-2"))
    comms.deserialize(raw_1)
    comms.deserialize(raw_2)  # different id, must not be treated as a replay


def test_replay_window_evicts_oldest_id() -> None:
    """A bounded window forgets the oldest id once it overflows."""
    comms = _comms(replay_window=2)
    raws = [comms.serialize(_msg(mid=f"m-{i}")) for i in range(3)]
    comms.deserialize(raws[0])
    comms.deserialize(raws[1])
    comms.deserialize(raws[2])  # window: {m-1, m-2}, m-0 evicted
    comms.deserialize(raws[0])  # m-0 no longer remembered -> treated as new, accepted
    with pytest.raises(ReplayError):
        comms.deserialize(raws[2])  # m-2 is still in the window


def test_replay_window_must_be_positive() -> None:
    """A non-positive window is a configuration error, not silently disabled tracking."""
    with pytest.raises(ValueError, match="replay_window"):
        ReplaySafeComms(_AUDITOR, replay_window=0)


def test_default_replay_window_is_generous() -> None:
    """Sanity: the shipped default comfortably covers a single scenario's traffic."""
    assert DEFAULT_REPLAY_WINDOW >= 1000
