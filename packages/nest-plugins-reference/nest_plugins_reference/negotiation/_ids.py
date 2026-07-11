# SPDX-License-Identifier: Apache-2.0
"""Deterministic negotiation session identifiers.

Nanda Town's core guarantee is a *byte-deterministic* JSONL trace: the same
seed must replay to an identical trace so operators can ``diff`` two runs and
``replay`` a failure. ADR-004 (seeded-determinism) makes that a hard rule and
calls out unseeded RNG as a violation of it.

The alternating-offers plugin previously minted a session id with
:func:`uuid.uuid4`, which draws from ``os.urandom`` and is therefore
**unseedable**: every run produced a fresh ``NegotiationSession`` id, so two
runs of the *same* seed diverged on every opened negotiation and their traces
could neither be diffed nor replayed. This is the negotiation-layer sibling of
the coordination-layer fix (``coordination/_ids.py``).

:func:`derive_session_id` replaces that with a pure function of the initiating
agent, the partner, and a monotonic per-initiator sequence number. It is:

- **deterministic** -- identical inputs always yield the identical id, so a
  seeded run replays byte-for-byte;
- **injective on its inputs** -- distinct ``(initiator, partner, seq)`` triples
  map to distinct ids, because the pre-image is a length-prefixed encoding that
  no two distinct triples can share (this rules out concatenation ambiguity
  such as ``("ab", "c")`` vs ``("a", "bc")``);
- **free of ambient state** -- no reliance on object identity, dict insertion
  order, wall-clock time, or a global RNG.

Example::

    from nest_core.types import AgentId

    sid = derive_session_id(AgentId("a1"), AgentId("a2"), 1)
    assert sid == derive_session_id(AgentId("a1"), AgentId("a2"), 1)
"""

from __future__ import annotations

import hashlib

from nest_core.types import AgentId


def derive_session_id(initiator: AgentId, partner: AgentId, seq: int) -> str:
    """Return a deterministic, collision-resistant negotiation session id.

    The id is ``"session-" + sha256(preimage)[:16]`` where ``preimage`` is a
    length-prefixed (netstring-style) encoding of ``(initiator, partner, seq)``.
    Length-prefixing makes the encoding injective, so distinct inputs cannot
    alias onto the same digest through boundary ambiguity.

    Args:
        initiator: The agent opening the negotiation.
        partner: The counterparty. Distinguishes sessions the same initiator
            opens with different partners.
        seq: A monotonic per-initiator counter. Distinguishes successive
            sessions opened by the same initiator; the caller owns incrementing
            it.

    Example::

        sid = derive_session_id(AgentId("a1"), AgentId("a2"), 1)
    """
    parts = (str(initiator), str(partner), str(seq))
    preimage = "|".join(f"{len(p)}:{p}" for p in parts).encode("utf-8")
    return "session-" + hashlib.sha256(preimage).hexdigest()[:16]
