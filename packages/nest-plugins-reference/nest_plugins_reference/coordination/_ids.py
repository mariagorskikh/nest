# SPDX-License-Identifier: Apache-2.0
"""Deterministic coordination round identifiers.

Nanda Town's core guarantee is a *byte-deterministic* JSONL trace: the same
seed must replay to an identical trace so operators can ``diff`` two runs and
``replay`` a failure. ADR-004 (seeded-determinism) makes that a hard rule and
calls out unseeded RNG as a violation of it.

The reference coordination plugins previously minted round identifiers with
:func:`uuid.uuid4`, which draws from ``os.urandom`` and is therefore
**unseedable**: every run produced fresh ``Round`` / ``Bid`` / ``Outcome`` ids,
so two runs of the *same* seed diverged on every coordination event and their
traces could neither be diffed nor replayed.

:func:`derive_round_id` replaces that with a pure function of the proposing
agent, the task, and a monotonic per-proposer sequence number. It is:

- **deterministic** -- identical inputs always yield the identical id, so a
  seeded run replays byte-for-byte;
- **injective on its inputs** -- distinct ``(agent, task, seq)`` triples map to
  distinct ids, because the pre-image is a length-prefixed encoding that no two
  distinct triples can share (this rules out concatenation ambiguity such as
  ``("ab", "c")`` vs ``("a", "bc")``);
- **free of ambient state** -- no reliance on object identity, dict insertion
  order, wall-clock time, or a global RNG.

Example::

    from nest_core.types import AgentId

    rid = derive_round_id(AgentId("manager"), "task-7", 1)
    assert rid == derive_round_id(AgentId("manager"), "task-7", 1)
"""

from __future__ import annotations

import hashlib

from nest_core.types import AgentId


def derive_round_id(agent_id: AgentId, task_id: str, seq: int) -> str:
    """Return a deterministic, collision-resistant coordination round id.

    The id is ``"round-" + sha256(preimage)[:16]`` where ``preimage`` is a
    length-prefixed (netstring-style) encoding of ``(agent_id, task_id, seq)``.
    Length-prefixing makes the encoding injective, so distinct inputs cannot
    alias onto the same digest through boundary ambiguity.

    Args:
        agent_id: The proposing agent. Distinguishes rounds proposed by
            different agents for the same task.
        task_id: The task being coordinated.
        seq: A monotonic per-proposer counter. Distinguishes successive rounds
            proposed by the same agent; the caller owns incrementing it.

    Example::

        rid = derive_round_id(AgentId("r0"), "t1", 1)
    """
    parts = (str(agent_id), task_id, str(seq))
    preimage = "|".join(f"{len(p)}:{p}" for p in parts).encode("utf-8")
    return "round-" + hashlib.sha256(preimage).hexdigest()[:16]
