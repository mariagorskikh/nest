# SPDX-License-Identifier: Apache-2.0
"""Mesh-revocable capability tokens: delegatable auth whose revocations gossip.

The merged ``delegatable`` plugin gives every verifier real macaroon-style
capability chains -- offline attenuation, cascading revocation, audience
binding. But its revocation knowledge lives in one in-process ``set``: run
one honest replica per agent and a revocation performed at the issuer is
invisible to every other verifier, forever. The only deployment in which
its cascade reaches the whole mesh is the one where all agents share a
single Python object -- which no real network can do.

``MeshRevocableAuth`` fixes exactly that, by composition: it subclasses
:class:`~nest_plugins_reference.auth.delegatable.DelegatableAuth` -- token
format, HMAC chain, attenuation rules, and all exception types unchanged --
and treats the inherited revocation set as a replica of a **grow-only set
CRDT** (G-Set). Two additive methods, :meth:`export_revocations` and
:meth:`merge_revocations`, are the replication channel; gossip them over
any transport and every replica converges on the union of all revocations,
in any delivery order, because set union is commutative, associative, and
idempotent.

The CAP trade is stated, not hidden: a replica partitioned away from the
revoker keeps honoring not-yet-propagated revocations (availability), and
becomes consistent within one gossip round of the partition healing. The
``delegated_auth_partition`` scenario demonstrates -- and its validators
enforce -- both halves of that sentence.

All replicas must be constructed with the same ``secret``: tokens minted
by any replica verify at every replica; only *revocation knowledge* is
replica-local until gossiped.

Example::

    issuer = MeshRevocableAuth(secret=b"s", clock=0.0)
    gateway = MeshRevocableAuth(secret=b"s", clock=0.0)
    root = await issuer.issue(AgentId("coord"), ["read", "write"])
    child = await issuer.delegate(root, AgentId("worker"), ["read"], ttl=60.0)
    await gateway.verify(child)              # any replica can verify
    await issuer.revoke(root)
    await gateway.verify(child)              # still passes: not yet gossiped
    gateway.merge_revocations(issuer.export_revocations())
    await gateway.verify(child)              # raises RevokedAncestorError
"""

from __future__ import annotations

import json
from typing import cast

from .delegatable import DelegatableAuth

CRDT_KIND = "revocation_gset"
"""Schema tag stamped into every serialized revocation set, used to detect
and validate G-Set state when it is read back from a trace or the wire."""


class RevocationStateError(ValueError):
    """Raised when a byte string is not a valid serialized revocation G-Set.

    Subclasses :class:`ValueError` so existing ``except ValueError`` handlers
    keep working while callers that care can catch the specific type.

    Example::

        try:
            auth.merge_revocations(b"not json")
        except RevocationStateError:
            ...
    """


class MeshRevocableAuth(DelegatableAuth):
    """Delegatable capability tokens with gossip-propagated revocation.

    Each instance is an independent **replica**. ``issue`` / ``delegate`` /
    ``verify`` / ``verify_presented`` / ``revoke`` are inherited verbatim
    from :class:`DelegatableAuth`; the inherited ``_revoked`` set doubles as
    this replica's G-Set state, so a revocation recorded anywhere reaches
    every replica once :meth:`export_revocations` output has been merged --
    directly or through any chain of intermediate replicas.

    The replication channel is additive: a caller that only speaks the base
    ``Auth`` protocol never has to know revocations are replicated.

    Example::

        a = MeshRevocableAuth(secret=b"s", clock=0.0)
        b = MeshRevocableAuth(secret=b"s", clock=0.0)
        root = await a.issue(AgentId("a1"), ["read"])
        await a.revoke(root)
        b.merge_revocations(a.export_revocations())
    """

    # -- G-Set replication channel --------------------------------------

    def export_revocations(self) -> bytes:
        """Serialize this replica's revocation set for gossip.

        The member list is sorted, so identical states export identical
        bytes -- keeping traces replay-deterministic and making state
        comparison in tests a byte comparison.

        Example::

            state = auth.export_revocations()
            peer.merge_revocations(state)
        """
        data = {"crdt": CRDT_KIND, "revoked": sorted(self._revoked)}
        return json.dumps(data, sort_keys=True).encode("utf-8")

    def merge_revocations(self, state: bytes) -> bool:
        """Union a peer's serialized revocation set into this replica.

        Returns ``True`` if the merge added at least one new revocation
        (useful for gossip loops that only re-broadcast on change).
        Malformed or foreign state raises :class:`RevocationStateError`
        and leaves this replica untouched -- gossip input is
        attacker-adjacent and must never corrupt local state.

        Union is commutative, associative, and idempotent, so replicas
        converge under any delivery order and duplicated gossip is a no-op.

        Example::

            changed = auth.merge_revocations(peer.export_revocations())
        """
        try:
            decoded: object = json.loads(state.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as err:
            msg = "revocation state is not valid JSON"
            raise RevocationStateError(msg) from err
        if not isinstance(decoded, dict):
            msg = "revocation state must be a JSON object"
            raise RevocationStateError(msg)
        data = cast("dict[str, object]", decoded)
        if data.get("crdt") != CRDT_KIND:
            msg = f"revocation state kind must be {CRDT_KIND!r}"
            raise RevocationStateError(msg)
        revoked = data.get("revoked")
        if not isinstance(revoked, list):
            msg = "revocation state 'revoked' must be a list of strings"
            raise RevocationStateError(msg)
        members = cast("list[object]", revoked)
        if not all(isinstance(tid, str) for tid in members):
            msg = "revocation state 'revoked' must be a list of strings"
            raise RevocationStateError(msg)
        incoming = set(cast("list[str]", members))
        new = incoming - self._revoked
        self._revoked |= new
        return bool(new)
