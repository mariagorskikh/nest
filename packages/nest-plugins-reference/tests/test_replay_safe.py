# SPDX-License-Identifier: Apache-2.0

from nest_core.types import AgentId, Message, MessageId
from nest_plugins_reference.comms.replay_safe import ReplayError, ReplaySafeComms
from nest_plugins_reference.validators.replay_validators import (
    check_comms_replay_rejected,
    check_comms_sequence_rollback_rejected,
)


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


def test_serialize_deserialize_roundtrip():
    alice = ReplaySafeComms(AgentId("alice"))
    msg = _msg(0)
    raw = alice.serialize(msg)
    recovered = alice.deserialize(raw)
    assert recovered.id == msg.id
    assert recovered.payload == msg.payload
    assert recovered.metadata["sequence"] == 0


def test_sequence_increments():
    alice = ReplaySafeComms(AgentId("alice"))
    for i in range(5):
        raw = alice.serialize(_msg(i))
        recovered = alice.deserialize(raw)
        assert recovered.metadata["sequence"] == i


def test_replay_rejected():
    alice = ReplaySafeComms(AgentId("alice"))
    bob = ReplaySafeComms(AgentId("bob"))
    raw = alice.serialize(_msg(0))
    bob.deserialize(raw)
    try:
        bob.deserialize(raw)
        assert False, "Replay should have been rejected"
    except ReplayError as exc:
        assert exc.reason == "stale_sequence"


def test_adversarial_validator_replay():
    alice = ReplaySafeComms(AgentId("alice"))
    bob = ReplaySafeComms(AgentId("bob"))
    msg = _msg(0)
    raw = alice.serialize(msg)
    assert check_comms_replay_rejected(bob, raw, "alice", "bob")


def test_adversarial_validator_rollback():
    alice = ReplaySafeComms(AgentId("alice"))
    bob = ReplaySafeComms(AgentId("bob"))
    msg = _msg(0)
    raw = alice.serialize(msg)
    bob.deserialize(raw)
    assert check_comms_sequence_rollback_rejected(bob, raw, "alice", "bob")


def test_different_peers_independent_sequences():
    alice = ReplaySafeComms(AgentId("alice"))
    bob = ReplaySafeComms(AgentId("bob"))
    carol = ReplaySafeComms(AgentId("carol"))

    raw_bob = alice.serialize(_msg(0, receiver="bob"))
    raw_carol = alice.serialize(_msg(0, receiver="carol"))
    
    bob.deserialize(raw_bob)
    carol.deserialize(raw_carol)

    # Independent counters — both start at 0.
    assert bob._incoming_sequences[("alice", "bob")] == 0
    assert carol._incoming_sequences[("alice", "carol")] == 0


def test_concurrent_sending_no_duplicates():
    """Test that sequence numbers are unique even under rapid successive sends."""
    alice = ReplaySafeComms(AgentId("alice"))
    
    # Send 10 messages in rapid succession
    sequences = []
    for i in range(10):
        raw = alice.serialize(_msg(i))
        msg = alice.deserialize(raw)
        sequences.append(msg.metadata["sequence"])
    
    # All sequences should be unique and monotonically increasing
    assert len(set(sequences)) == 10
    assert sequences == list(range(10))


def test_out_of_order_delivery_buffering():
    alice = ReplaySafeComms(AgentId("alice"))
    bob = ReplaySafeComms(AgentId("bob"))
    msgs = [alice.serialize(_msg(i)) for i in range(3)]

    # Deliver 0, then 2 (out of order), then 1 (fills the gap).
    m0 = bob.deserialize(msgs[0])
    assert m0.metadata["sequence"] == 0

    try:
        bob.deserialize(msgs[2])
        assert False, "Out-of-order message should raise ReplayError"
    except ReplayError as exc:
        assert exc.reason == "out_of_order_buffered"

    m1 = bob.deserialize(msgs[1])
    assert m1.metadata["sequence"] == 1
    # Flushing should have advanced the state to include msg 2.
    assert bob._incoming_sequences[("alice", "bob")] == 2