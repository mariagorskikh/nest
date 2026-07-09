# SPDX-License-Identifier: Apache-2.0
"""Adversarial validators for the replay_safe comms plugin.

These validators test that the replay_safe comms layer properly rejects:
1. Replayed envelopes (same envelope sent twice)
2. Sequence rollback attacks (manipulated sequence numbers)
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from nest_plugins_reference.comms.replay_safe import ReplaySafeComms


def check_comms_replay_rejected(
    comms: ReplaySafeComms,
    envelope: bytes,
    sender_id: str,
    receiver_id: str,
) -> bool:
    """Verify that replaying an envelope is rejected.
    
    Args:
        comms: The ReplaySafeComms instance
        envelope: The original envelope bytes
        sender_id: Sender agent ID
        receiver_id: Receiver agent ID
    
    Returns:
        True if replay is properly rejected, False otherwise
    """
    # First delivery should succeed
    try:
        comms.deserialize(envelope)
    except Exception:
        # First delivery failed - can't test replay
        return False
    
    # Second delivery (replay) should fail
    try:
        comms.deserialize(envelope)
        return False  # Replay was accepted - BAD
    except Exception:
        return True  # Replay was rejected - GOOD


def check_comms_sequence_rollback_rejected(
    comms: ReplaySafeComms,
    envelope: bytes,
    sender_id: str,
    receiver_id: str,
) -> bool:
    """Verify that sequence rollback attacks are rejected.
    
    Args:
        comms: The ReplaySafeComms instance
        envelope: The original envelope bytes
        sender_id: Sender agent ID
        receiver_id: Receiver agent ID
    
    Returns:
        True if rollback is properly rejected, False otherwise
    """
    try:
        # Parse the envelope
        data = json.loads(envelope.decode('utf-8'))
        
        # Get current sequence
        current_seq = data.get('sequence', 0)
        
        # Try to rollback to a lower sequence
        data['sequence'] = max(0, current_seq - 1)
        rolled_back_envelope = json.dumps(data).encode('utf-8')
        
        # This should be rejected
        try:
            comms.deserialize(rolled_back_envelope)
            return False  # Rollback was accepted - BAD
        except Exception:
            return True  # Rollback was rejected - GOOD
            
    except Exception:
        # Couldn't create rollback envelope
        return False