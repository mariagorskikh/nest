# SPDX-License-Identifier: Apache-2.0

import pytest
from nest_core.types import AgentId, Message, MessageId
from nest_plugins_reference.comms.replay_safe import ReplayError, ReplaySafeComms


def _msg(i: int, sender: str = "alice", receiver: str = "bob") -> Message:
    return Message(
        id=MessageId(f"msg-{i}"),
        sender=AgentId(sender),
        receiver=AgentId(receiver),
        payload=f"payload-{i}".encode(),
        correlation_id=None,
        timestamp=i,
        metadata={},
    )


def test_serialize_deserialize_roundtrip() -> None:
    alice = ReplaySafeComms(AgentId("alice"))
    msg = _msg(0)
    raw = alice.serialize(msg)
    recovered = alice.deserialize(raw)
    assert recovered.id == msg.id
    assert recovered.payload == msg.payload
    assert recovered.metadata["sequence"] == 0


def test_sequence_increments() -> None:
    alice = ReplaySafeComms(AgentId("alice"))
    for i in range(5):
        raw = alice.serialize(_msg(i))
        recovered = alice.deserialize(raw)
        assert recovered.metadata["sequence"] == i


def test_replay_rejected() -> None:
    alice = ReplaySafeComms(AgentId("alice"))
    bob = ReplaySafeComms(AgentId("bob"))
    raw = alice.serialize(_msg(0))
    bob.deserialize(raw)
    with pytest.raises(ReplayError) as exc_info:
        bob.deserialize(raw)
    assert exc_info.value.reason == "stale_sequence"


def test_different_peers_independent_sequences() -> None:
    alice = ReplaySafeComms(AgentId("alice"))
    bob = ReplaySafeComms(AgentId("bob"))
    carol = ReplaySafeComms(AgentId("carol"))

    raw_bob = alice.serialize(_msg(0, receiver="bob"))
    raw_carol = alice.serialize(_msg(0, receiver="carol"))

    bob.deserialize(raw_bob)
    carol.deserialize(raw_carol)

    # Independent counters — both start at 0.
    assert bob._incoming_sequences[("alice", "bob")] == 0  # type: ignore[reportPrivateUsage]
    assert carol._incoming_sequences[("alice", "carol")] == 0  # type: ignore[reportPrivateUsage]


def test_concurrent_sending_no_duplicates() -> None:
    """Test that sequence numbers are unique even under rapid successive sends."""
    alice = ReplaySafeComms(AgentId("alice"))

    # Send 10 messages in rapid succession
    sequences: list[int] = []
    for i in range(10):
        raw = alice.serialize(_msg(i))
        msg = alice.deserialize(raw)
        sequences.append(msg.metadata["sequence"])

    # All sequences should be unique and monotonically increasing
    assert len(set(sequences)) == 10
    assert sequences == list(range(10))


def test_out_of_order_delivery_buffering() -> None:
    alice = ReplaySafeComms(AgentId("alice"))
    bob = ReplaySafeComms(AgentId("bob"))
    msgs = [alice.serialize(_msg(i)) for i in range(3)]

    # Deliver 0, then 2 (out of order), then 1 (fills the gap).
    m0 = bob.deserialize(msgs[0])
    assert m0.metadata["sequence"] == 0

    with pytest.raises(ReplayError) as exc_info:
        bob.deserialize(msgs[2])
    assert exc_info.value.reason == "out_of_order_buffered"

    m1 = bob.deserialize(msgs[1])
    assert m1.metadata["sequence"] == 1
    # Flushing should have advanced the state to include msg 2.
    assert bob._incoming_sequences[("alice", "bob")] == 2  # type: ignore[reportPrivateUsage]
