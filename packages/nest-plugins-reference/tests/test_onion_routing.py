# SPDX-License-Identifier: Apache-2.0

from unittest.mock import AsyncMock

import pytest

from nest_core.types import AgentCard, AgentId, Message, MessageId
from nest_plugins_reference.comms.onion import OnionRoutingComms

@pytest.fixture
def msg():
    return Message(
        id=MessageId("m1"),
        sender=AgentId("origin"),
        receiver=AgentId("dest"),
        payload=b"secret_payload",
    )

@pytest.fixture
def mock_registry():
    registry = AsyncMock()
    registry.lookup.return_value = [
        AgentCard(agent_id=AgentId("relay1"), name="Relay 1", capabilities=[]),
        AgentCard(agent_id=AgentId("relay2"), name="Relay 2", capabilities=[]),
        AgentCard(agent_id=AgentId("relay3"), name="Relay 3", capabilities=[]),
    ]
    return registry

@pytest.fixture
def mock_transport():
    transport = AsyncMock()
    transport.send = AsyncMock()
    return transport


@pytest.mark.asyncio
async def test_onion_encryption_and_decryption(msg, mock_registry, mock_transport):
    """Test that a message is wrapped and can be correctly unwrapped by relays."""
    comms_origin = OnionRoutingComms(
        AgentId("origin"),
        mock_transport,
        mock_registry,
        circuit_length=3
    )

    # 1. Send the message. This will encrypt it 3 times (relay1 -> relay2 -> dest)
    await comms_origin.send(AgentId("dest"), msg)

    # Verify the transport was called to send to relay1
    mock_transport.send.assert_called_once()
    args, _ = mock_transport.send.call_args
    assert args[0] == AgentId("relay1")
    raw_wrapped_payload = args[1]

    # 2. Relay 1 receives it. It decrypts it and discovers it needs to relay to relay2.
    comms_r1 = OnionRoutingComms(AgentId("relay1"))
    relay1_msg = comms_r1.deserialize(raw_wrapped_payload)

    assert relay1_msg.metadata["onion_action"] == "relay"
    assert relay1_msg.metadata["onion_next_hop"] == "relay2"

    # 3. Relay 1 forwards the payload to relay 2
    mock_transport.send.reset_mock()
    comms_r1._transport = mock_transport
    await comms_r1.send(AgentId(relay1_msg.metadata["onion_next_hop"]), relay1_msg)

    mock_transport.send.assert_called_once()
    args, _ = mock_transport.send.call_args
    assert args[0] == AgentId("relay2")
    r2_raw_payload = args[1]

    # 4. Relay 2 receives it. It decrypts it and discovers it needs to relay to dest.
    comms_r2 = OnionRoutingComms(AgentId("relay2"))
    relay2_msg = comms_r2.deserialize(r2_raw_payload)

    assert relay2_msg.metadata["onion_action"] == "relay"
    assert relay2_msg.metadata["onion_next_hop"] == "dest"

    # 5. Relay 2 forwards the payload to dest
    mock_transport.send.reset_mock()
    comms_r2._transport = mock_transport
    await comms_r2.send(AgentId(relay2_msg.metadata["onion_next_hop"]), relay2_msg)

    mock_transport.send.assert_called_once()
    args, _ = mock_transport.send.call_args
    assert args[0] == AgentId("dest")
    dest_raw_payload = args[1]

    # 6. Dest receives it. It decrypts it and gets the final message.
    comms_dest = OnionRoutingComms(AgentId("dest"))
    final_msg = comms_dest.deserialize(dest_raw_payload)

    assert final_msg.id == msg.id
    assert final_msg.sender == msg.sender
    assert final_msg.receiver == msg.receiver
    assert final_msg.payload == msg.payload


@pytest.mark.asyncio
async def test_send_without_transport_is_noop(msg):
    comms = OnionRoutingComms(AgentId("a1"))
    resp = await comms.send(AgentId("dest"), msg)
    assert resp.success is True


def test_malformed_onion_packet():
    """Test that an improperly encrypted onion packet raises an error."""
    comms = OnionRoutingComms(AgentId("a1"))
    with pytest.raises(ValueError, match="Failed to decrypt"):
        comms.deserialize(b"invalid_bytes_that_are_not_encrypted_properly")


def _encrypt_malformed_for_test(dest: AgentId, plaintext: bytes) -> bytes:
    import os
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from nest_plugins_reference.comms.onion import _get_key_for_agent
    aesgcm = AESGCM(_get_key_for_agent(dest))
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext


def test_malformed_onion_packet_not_json_dict():
    """Test that a decrypted packet that isn't a JSON dict raises an error."""
    comms = OnionRoutingComms(AgentId("a1"))
    raw = _encrypt_malformed_for_test(AgentId("a1"), b'"just_a_string"')
    with pytest.raises(ValueError, match="Failed to decrypt") as exc_info:
        comms.deserialize(raw)
    assert "Onion packet must decode to a JSON object" in str(exc_info.value.__cause__)


def test_malformed_onion_packet_missing_next_hop():
    """Test that a decrypted packet missing next_hop raises an error."""
    import json
    comms = OnionRoutingComms(AgentId("a1"))
    raw = _encrypt_malformed_for_test(AgentId("a1"), json.dumps({"payload": "YmFzZTY0"}).encode())
    with pytest.raises(ValueError, match="Failed to decrypt") as exc_info:
        comms.deserialize(raw)
    assert "Onion packet missing next_hop" in str(exc_info.value.__cause__)


def test_malformed_onion_packet_missing_payload():
    """Test that a decrypted packet missing payload raises an error."""
    import json
    comms = OnionRoutingComms(AgentId("a1"))
    raw = _encrypt_malformed_for_test(AgentId("a1"), json.dumps({"next_hop": "a2"}).encode())
    with pytest.raises(ValueError, match="Failed to decrypt") as exc_info:
        comms.deserialize(raw)
    assert "Onion packet payload must be a base64 string" in str(exc_info.value.__cause__)


@pytest.mark.asyncio
async def test_send_malformed_relay_metadata(mock_transport):
    """Test that sending with malformed relay metadata fails gracefully."""
    comms = OnionRoutingComms(AgentId("origin"), mock_transport)
    
    # Missing payload
    msg = Message(
        id=MessageId("m1"),
        sender=AgentId("origin"),
        receiver=AgentId("dest"),
        payload=b"",
        metadata={"onion_action": "relay", "onion_next_hop": "relay1"}
    )
    resp = await comms.send(AgentId("dest"), msg)
    assert resp.success is False

    # Invalid base64
    msg.metadata["onion_raw_payload"] = "not_valid_base64!!"
    resp = await comms.send(AgentId("dest"), msg)
    assert resp.success is False
