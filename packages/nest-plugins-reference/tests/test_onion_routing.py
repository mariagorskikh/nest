# SPDX-License-Identifier: Apache-2.0

import pytest
import base64
import json
from unittest.mock import AsyncMock

from nest_core.types import AgentId, Message, MessageId, Query, AgentCard
from nest_plugins_reference.comms.onion import OnionRoutingComms, _get_key_for_agent

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
