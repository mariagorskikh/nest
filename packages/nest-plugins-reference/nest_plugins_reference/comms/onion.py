# SPDX-License-Identifier: Apache-2.0
"""Onion Routing communication plugin.

Implements a Tor-style multi-hop encryption demo to reduce linkability between hops.
Messages are wrapped in layers of AES-GCM encryption; each hop removes one layer to
learn only the next hop, not the sender, final destination, or payload.

NOTE: Hackathon stub; keys are derived from public AgentIds and are not secret.

Example::

    comms = OnionRoutingComms(AgentId("a1"), transport, registry)
    await comms.send(AgentId("a4"), msg)
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from nest_core.types import (
    AgentCard,
    AgentId,
    Message,
    MessageId,
    Query,
    Response,
)

# Number of intermediary hops to use for a circuit (e.g. 2 relays + 1 destination = 3)
DEFAULT_CIRCUIT_LENGTH = 3

def _get_key_for_agent(agent_id: AgentId) -> bytes:
    """Derive a deterministic 256-bit AES key for an agent's identity.
    
    In a real production environment, this would use a public-key infrastructure (PKI)
    where agents publish their RSA/Curve25519 public keys in the Registry, and we would 
    perform ECDH to derive a shared symmetric key. For this hackathon, we use a 
    deterministic hash of the AgentId to simulate knowing their public key.
    
    NOTE: This makes the current implementation intentionally insecure for demo purposes,
    as any agent can derive any other agent's key.
    """
    return hashlib.sha256(str(agent_id).encode("utf-8")).digest()


class OnionRoutingComms:
    """Tor-style Onion Routing communication protocol.
    
    Provides anonymity and privacy by wrapping messages in layers of encryption.
    """

    def __init__(
        self,
        agent_id: AgentId,
        transport: Any = None,
        registry: Any = None,
        circuit_length: int = DEFAULT_CIRCUIT_LENGTH,
    ) -> None:
        self._agent_id = agent_id
        self._transport = transport
        self._registry = registry
        self.circuit_length = circuit_length
        self._key = _get_key_for_agent(agent_id)

    def serialize(self, msg: Message) -> bytes:
        """Serialize the inner message to a standard JSON envelope."""
        meta = dict(msg.metadata)
        data = {
            "id": str(msg.id),
            "sender": str(msg.sender),
            "receiver": str(msg.receiver),
            "payload": base64.b64encode(msg.payload).decode("ascii"),
            "correlation_id": str(msg.correlation_id) if msg.correlation_id else None,
            "timestamp": msg.timestamp,
            "metadata": meta,
        }
        return json.dumps(data, sort_keys=True).encode("utf-8")

    def _wrap_layer(self, dest_agent: AgentId, next_hop: str, payload_bytes: bytes) -> bytes:
        """Encrypts a payload for a specific destination agent using AES-GCM."""
        aesgcm = AESGCM(_get_key_for_agent(dest_agent))
        nonce = os.urandom(12)

        inner_data = {
            "next_hop": next_hop,
            "payload": base64.b64encode(payload_bytes).decode("ascii")
        }
        plaintext = json.dumps(inner_data).encode("utf-8")
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        return nonce + ciphertext

    def deserialize(self, raw: bytes) -> Message:
        """Deserialize an Onion packet, peeling off one layer of encryption.

        If this agent is the final destination, returns the unwrapped Message.
        If this agent is a relay, returns a special control Message instructing
        the agent to forward the payload to the next hop.
        """
        try:
            aesgcm = AESGCM(self._key)
            nonce = raw[:12]
            ciphertext = raw[12:]
            decrypted = aesgcm.decrypt(nonce, ciphertext, None)
            parsed = json.loads(decrypted)

            if not isinstance(parsed, dict):
                raise TypeError("Onion packet must decode to a JSON object")

            next_hop = parsed.get("next_hop")
            payload_b64 = parsed.get("payload")

            if not isinstance(next_hop, str) or not next_hop:
                raise TypeError("Onion packet missing next_hop")
            if not isinstance(payload_b64, str):
                raise TypeError("Onion packet payload must be a base64 string")

            inner_payload = base64.b64decode(payload_b64, validate=True)

            if next_hop == "FINAL":
                # We are the final destination! Decode the actual inner message.
                msg_data = json.loads(inner_payload)
                return Message(
                    id=MessageId(msg_data["id"]),
                    sender=AgentId(msg_data["sender"]),
                    receiver=AgentId(msg_data["receiver"]),
                    payload=base64.b64decode(msg_data["payload"]),
                    correlation_id=msg_data.get("correlation_id"),
                    timestamp=msg_data.get("timestamp"),
                    metadata=msg_data.get("metadata", {}),
                )
            else:
                # We are an intermediary relay. Return a control message.
                return Message(
                    id=MessageId(f"relay-{os.urandom(4).hex()}"),
                    sender=AgentId("onion-network"),
                    receiver=self._agent_id,
                    payload=b"relay_instruction",
                    metadata={
                        "onion_action": "relay",
                        "onion_next_hop": next_hop,
                        "onion_raw_payload": payload_b64,  # keep as base64 string
                    }
                )
        except Exception as exc:
            raise ValueError("Failed to decrypt or parse Onion packet") from exc

    async def send(self, to: AgentId, msg: Message) -> Response:
        """Send a message using Onion Routing.
        
        If the message contains relay instructions in its metadata, it simply
        forwards the raw wrapped payload to the next hop.
        Otherwise, it constructs a full multi-hop circuit, wraps the message in 
        layers of encryption, and sends it to the first relay.
        """
        if self._transport is None:
            return Response(success=True)
            
        # 1. Check if we are just relaying an existing onion packet
        if msg.metadata.get("onion_action") == "relay":
            next_hop = AgentId(msg.metadata["onion_next_hop"])
            try:
                raw_payload = base64.b64decode(msg.metadata["onion_raw_payload"])
            except Exception:
                return Response(success=False)
            await self._transport.send(next_hop, raw_payload)
            return Response(success=True)
            
        # 2. We are the origin. Construct the circuit!
        circuit: list[AgentId] = []

        # In a real network, we would query the registry for random relays.
        # For this implementation, if a registry is provided, we fetch peers.
        if self._registry is not None:
            cards = await self._registry.lookup(Query())
            # Exclude self and final destination from relays
            available_relays = [
                c.agent_id for c in cards if c.agent_id not in (self._agent_id, to)
            ]

            # Pick up to (circuit_length - 1) relays
            needed = max(0, self.circuit_length - 1)
            # Simplistic random selection (taking first N for simplicity of mock)
            circuit = available_relays[:needed]

        # The final node in the circuit is always the destination
        circuit.append(to)

        # 3. Serialize the inner message
        inner_bytes = self.serialize(msg)
        current_payload = inner_bytes

        # 4. Wrap layers in reverse order (from destination back to first relay)
        # For the destination, next_hop is "FINAL"
        current_payload = self._wrap_layer(circuit[-1], "FINAL", current_payload)

        # For intermediate relays, next_hop is the node AFTER them in the circuit
        for i in range(len(circuit) - 2, -1, -1):
            relay = circuit[i]
            next_relay = str(circuit[i + 1])
            current_payload = self._wrap_layer(relay, next_relay, current_payload)

        # 5. Send to the first node in the circuit
        first_hop = circuit[0]
        await self._transport.send(first_hop, current_payload)
        
        return Response(success=True)

    async def advertise(self, card: AgentCard) -> None:
        """Advertise this agent to the registry so others can use it as a relay."""
        if self._registry is not None:
            await self._registry.register(card)

    async def discover(self, query: Query) -> list[AgentCard]:
        if self._registry is not None:
            return await self._registry.lookup(query)
        return []
