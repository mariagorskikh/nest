# SPDX-License-Identifier: Apache-2.0
"""Replay-safe comms — rejects verbatim re-delivery of an already-seen envelope.

:mod:`~nest_plugins_reference.comms.authenticated` closes the downgrade/tamper
gap: an on-path adversary who *rewrites* an envelope gets caught because the
rewrite invalidates the HMAC tag. But its own docstring flags what is still
open: "a *verbatim* re-send of a genuine envelope still verifies." A captured,
byte-identical copy of an honest envelope carries a perfectly valid tag — there
is nothing to recompute-and-compare against, because nothing was tampered with.
Replaying it a second (or third, or Nth) time is indistinguishable from an
honest resend at the ``AuthenticatedComms`` layer, so it is silently accepted
again. For a non-idempotent message (a payment instruction, a vote, a state
transition) that is a live attack: capture one authentic envelope off the
wire and replay it to double-spend, double-vote, or double-apply.

This plugin closes that gap the way the docstring suggests — "bind a
nonce/sequence into ``metadata``" — but does it with zero new wire fields: the
envelope's own ``id`` is already inside the HMAC tag's coverage (see
``canonical_untagged`` in ``authenticated.py``), so an attacker cannot forge a
*new* id for a captured payload without invalidating the tag. That makes ``id``
a free, tamper-evident nonce. All this plugin adds is receiver-side memory: a
bounded, per-sender window of the ids it has already accepted. A second
delivery of an id already in that window is rejected with a typed
:class:`ReplayError` instead of being decoded again.

Threat model (delta over ``authenticated``)::

    in scope    replay: a verbatim re-send (or re-broadcast by a relay) of a
                previously accepted, genuinely-tagged envelope is detected and
                refused on the second and later deliveries.
    out scope   everything already in scope for authenticated (rollback,
                field-stripping, forgery without the channel secret).
    out scope   replay across process restarts: the seen-id window is
                in-memory only, exactly like the simulator's other per-agent
                state. A real deployment would persist or derive the window
                from a monotonic counter.

Example::

    comms = ReplaySafeComms(AgentId("a1"))
    raw = comms.serialize(msg)
    comms.deserialize(raw)                 # first delivery: accepted
    comms.deserialize(raw)                 # replay: raises ReplayError
"""

from __future__ import annotations

from collections import OrderedDict

from nest_core.types import AgentId, Message, MessageId

from nest_plugins_reference.comms.authenticated import (
    AUTH_TAG_FIELD,
    CHANNEL_SECRET_DEFAULT,
    KNOWN_FIELDS,
    SCHEMA_MAJOR,
    SCHEMA_MINOR,
    SCHEMA_VERSION,
    AuthenticatedComms,
    DowngradeError,
)

__all__ = [
    "AUTH_TAG_FIELD",
    "CHANNEL_SECRET_DEFAULT",
    "DEFAULT_REPLAY_WINDOW",
    "KNOWN_FIELDS",
    "SCHEMA_MAJOR",
    "SCHEMA_MINOR",
    "SCHEMA_VERSION",
    "ReplayError",
    "ReplaySafeComms",
]

#: Number of distinct message ids remembered per sender before the oldest is
#: evicted. Bounds memory on a long-running agent; sized generously above any
#: single scenario's per-sender message count so it never evicts a live id.
DEFAULT_REPLAY_WINDOW = 4096


class ReplayError(DowngradeError):
    """Raised when an envelope's ``id`` has already been accepted from this sender.

    A subclass of :class:`~nest_plugins_reference.comms.authenticated.DowngradeError`
    (hence :class:`UnsupportedSchemaError`, hence :class:`ValueError`): the
    envelope is authentic and well-formed, but delivering it *again* is itself
    the attack, so it is refused the same way a tampered envelope is.

    Example::

        try:
            comms.deserialize(captured_raw)
        except ReplayError as exc:
            assert exc.reason == "replay"
    """

    def __init__(self, version: str, message_id: str, sender: str) -> None:
        self.message_id = message_id
        self.sender = sender
        super().__init__(version, "replay", f"duplicate id {message_id!r} from {sender!r}")


class ReplaySafeComms(AuthenticatedComms):
    """``AuthenticatedComms`` plus rejection of verbatim envelope replay.

    Strict superset: version negotiation, unknown-field preservation,
    unknown-major rejection and tamper-evidence are all inherited unchanged
    from :class:`AuthenticatedComms`. The only new behaviour is a per-sender
    memory of accepted ids, consulted after the tag verifies.

    Example::

        comms = ReplaySafeComms(AgentId("a1"), require_auth=True)
        resp = await comms.send(AgentId("a2"), msg)
    """

    def __init__(
        self,
        agent_id: AgentId,
        transport: object | None = None,
        registry: object | None = None,
        *,
        channel_secret: bytes = CHANNEL_SECRET_DEFAULT,
        require_auth: bool = False,
        replay_window: int = DEFAULT_REPLAY_WINDOW,
    ) -> None:
        super().__init__(
            agent_id,
            transport,
            registry,
            channel_secret=channel_secret,
            require_auth=require_auth,
        )
        if replay_window < 1:
            msg = f"replay_window must be >= 1, got {replay_window}"
            raise ValueError(msg)
        self._replay_window = replay_window
        # sender -> ordered set (dict-as-set) of accepted ids, oldest first.
        self._seen: dict[AgentId, OrderedDict[MessageId, None]] = {}

    def deserialize(self, raw: bytes) -> Message:
        """Deserialize, then enforce that ``(sender, id)`` has not been seen before.

        Delegates version/tamper checks to :class:`AuthenticatedComms` first —
        a forged or downgraded envelope is rejected on those grounds before
        replay bookkeeping ever runs, so an attacker cannot use a mangled
        duplicate to probe the replay window. Only a genuinely-verified
        envelope reaches the id check.

        Example::

            msg = comms.deserialize(raw)   # raises ReplayError on 2nd call
        """
        msg = super().deserialize(raw)
        seen = self._seen.setdefault(msg.sender, OrderedDict())
        if msg.id in seen:
            version = str(msg.metadata.get("schema_version", SCHEMA_VERSION))
            raise ReplayError(version, str(msg.id), str(msg.sender))
        seen[msg.id] = None
        if len(seen) > self._replay_window:
            seen.popitem(last=False)
        return msg
