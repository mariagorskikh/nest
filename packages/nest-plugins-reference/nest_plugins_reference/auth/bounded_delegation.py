# SPDX-License-Identifier: Apache-2.0
"""Delegatable auth with a bounded chain and a revocation set that forgets.

The merged ``delegatable`` and ``mesh_revocable`` plugins get the crypto
right: macaroon-style HMAC chaining, offline attenuation, cascading
revocation, and a G-Set CRDT that converges under partition. Both grow
without limit, in two independent directions, and neither growth is a
crypto bug -- which is why the existing validators pass straight through
them.

**Chain depth is unbounded.** ``delegate`` appends a segment and re-signs;
nothing caps how many times. Because attenuation is offline by design, a
token holder needs no issuer contact to do it. Measured against the merged
plugin: 2000 delegations produce a 215 KB token whose ``verify`` walks
every segment and runs ~400x slower than a root token's. The cost is paid
by the *verifier*, so a single holder degrades the agents it talks to.

**The revocation set never forgets.** ``_revoked`` is a G-Set, so it only
grows -- correct for the CRDT, wrong for the workload. A revoked segment
whose ``exp`` has passed is already unforgeable: ``_check_chain`` rejects
it on expiry alone, without consulting ``_revoked``. Retaining it changes
no verification outcome and costs memory on every replica plus bytes in
every gossip round, forever.

``BoundedDelegationAuth`` subclasses ``MeshRevocableAuth``, so the token
format, HMAC chain, attenuation rules, exception types, and G-Set
replication are inherited unchanged. It adds two bounds:

1. ``max_depth`` -- ``delegate`` refuses to extend a chain past the limit,
   and ``verify`` re-checks it, so a chain assembled by some other means
   is rejected on presentation rather than merely at mint.
2. Expiry-based pruning -- ``prune_revocations`` drops entries whose
   segments have expired, using an expiry the replica recorded at revoke
   time. Entries with unknown expiry are always retained.

Pruning a G-Set is not free: unioning with a stale peer resurrects pruned
entries. The guard is that resurrection is harmless *only* for entries
past expiry, which fail on expiry regardless. To keep that true under
gossip, pruning is time-gated by ``prune_grace``: an entry is eligible
only once ``now > exp + prune_grace``. Set the grace above the worst-case
gossip propagation delay and a pruned entry can never return to a replica
that would have honored it.

Example::

    auth = BoundedDelegationAuth(secret=b"s", clock=0.0, max_depth=3)
    root = await auth.issue(AgentId("coordinator"), ["read", "write"])
    child = await auth.delegate(root, AgentId("worker"), ["read"], ttl=60.0)
    await auth.revoke(child)
    auth.advance_to(10_000.0)
    auth.prune_revocations()          # child expired: entry dropped
"""

from __future__ import annotations

import json
from typing import Any, cast

from nest_core.types import AgentId, AuthContext, Token

from .delegatable import DelegationError
from .mesh_revocable import MeshRevocableAuth

DEFAULT_MAX_DEPTH = 8
"""Chain segments allowed by default, counting the root.

Eight covers the delegation trees in the shipped scenarios (a coordinator,
three intermediaries, and leaf agents is depth three) with room to spare,
while keeping worst-case ``verify`` cost bounded by a small constant.
"""

DEFAULT_PRUNE_GRACE = 3600.0
"""Seconds past a segment's expiry before its revocation entry may be pruned.

Must exceed the worst-case time for a revocation to reach every replica.
An hour is generous for the in-process gossip in these scenarios; a real
deployment should set it from its own propagation bound.
"""


class DelegationDepthExceededError(DelegationError):
    """A chain reached or would exceed ``max_depth`` segments.

    Subclasses :class:`~nest_plugins_reference.auth.delegatable.DelegationError`
    so callers catching delegation failures generically keep working.

    Example::

        raise DelegationDepthExceededError("chain depth 9 exceeds max_depth 8")
    """


class BoundedDelegationAuth(MeshRevocableAuth):
    """Mesh-revocable auth with a depth-bounded chain and prunable revocations.

    Every inherited method keeps its semantics. ``delegate`` and ``verify``
    add a depth check; ``revoke`` additionally records the revoked
    segment's expiry so pruning can later tell which entries are dead.

    Replicas must share a ``secret``, as with
    :class:`~nest_plugins_reference.auth.mesh_revocable.MeshRevocableAuth`.
    They need not share ``max_depth``: the bound is enforced by whichever
    replica performs the mint or the verify, so a stricter verifier
    rejects chains a laxer minter allowed.

    Example::

        auth = BoundedDelegationAuth(secret=b"s", clock=0.0, max_depth=2)
        root = await auth.issue(AgentId("a1"), ["read"])
        child = await auth.delegate(root, AgentId("a2"), ["read"], ttl=60.0)
        # a third link exceeds max_depth=2 and raises
    """

    def __init__(
        self,
        secret: bytes = b"nest-default-secret",
        clock: float | None = None,
        max_depth: int = DEFAULT_MAX_DEPTH,
        prune_grace: float = DEFAULT_PRUNE_GRACE,
    ) -> None:
        if max_depth < 1:
            msg = f"max_depth must be at least 1, got {max_depth}"
            raise ValueError(msg)
        if prune_grace < 0:
            msg = f"prune_grace must be non-negative, got {prune_grace}"
            raise ValueError(msg)
        super().__init__(secret=secret, clock=clock)
        self._max_depth = max_depth
        self._prune_grace = prune_grace
        self._revoked_exp: dict[str, float] = {}

    @property
    def max_depth(self) -> int:
        """Maximum chain segments this replica will mint or accept.

        Example::

            assert BoundedDelegationAuth(max_depth=4).max_depth == 4
        """
        return self._max_depth

    def advance_to(self, when: float) -> None:
        """Pin this replica's clock, for deterministic tests and scenarios.

        Calling this on a replica constructed without an explicit
        ``clock`` switches it from wall-clock to fixed time, so only call
        it on replicas you intend to drive by hand.

        Example::

            auth = BoundedDelegationAuth(clock=0.0)
            auth.advance_to(120.0)
        """
        self._clock = when

    def _depth_of(self, token: Token) -> int:
        """Count segments in a token's chain.

        Example::

            assert auth._depth_of(root) == 1
        """
        return len(self._decode(token))

    async def delegate(
        self,
        parent_token: Token,
        audience: AgentId,
        scopes_subset: list[str],
        ttl: float,
    ) -> Token:
        """Mint a child token, refusing to extend past ``max_depth``.

        The depth check runs before any attenuation work, so an
        over-deep request is rejected without doing the HMAC.

        Example::

            child = await auth.delegate(root, AgentId("a2"), ["read"], ttl=60.0)
        """
        depth = self._depth_of(parent_token)
        if depth + 1 > self._max_depth:
            msg = (
                f"delegating would make chain depth {depth + 1}, "
                f"exceeding max_depth {self._max_depth}"
            )
            raise DelegationDepthExceededError(msg)
        return await super().delegate(parent_token, audience, scopes_subset, ttl)

    async def verify(self, token: Token) -> AuthContext:
        """Verify a token, rejecting over-deep chains before walking them.

        Re-checking at verify matters because ``delegate`` is not the
        only way a chain can be assembled: a holder who reconstructs one
        out of band, or a laxer replica, can produce a chain this
        replica should still refuse.

        Example::

            ctx = await auth.verify(child)
        """
        depth = self._depth_of(token)
        if depth > self._max_depth:
            msg = f"chain depth {depth} exceeds max_depth {self._max_depth}"
            raise DelegationDepthExceededError(msg)
        return await super().verify(token)

    async def revoke(self, token: Token) -> None:
        """Revoke a token and record its expiry for later pruning.

        The expiry is stored locally, not gossiped: it is a pruning hint,
        and a replica that lacks it simply retains the entry.

        Example::

            await auth.revoke(child)
        """
        chain = self._decode(token)
        leaf = chain[-1]
        tid = str(leaf.get("tid", ""))
        self._revoked_exp[tid] = float(cast("float", leaf.get("exp", 0.0)))
        await super().revoke(token)

    def prune_revocations(self) -> set[str]:
        """Drop revocation entries whose segments expired long enough ago.

        An entry is eligible only when its expiry is known *and*
        ``now > exp + prune_grace``. Returns the pruned ids.

        Safety: a pruned entry's segment is already past ``exp``, so
        ``_check_chain`` rejects any token containing it on expiry
        grounds, whether or not the revocation is still recorded. The
        grace period ensures a stale peer cannot re-introduce an entry
        while it could still have mattered.

        Example::

            auth.advance_to(10_000.0)
            dropped = auth.prune_revocations()
        """
        now = self._now()
        cutoff = now - self._prune_grace
        prunable = {
            tid
            for tid in self._revoked
            if tid in self._revoked_exp and self._revoked_exp[tid] < cutoff
        }
        self._revoked -= prunable
        for tid in prunable:
            del self._revoked_exp[tid]
        return prunable

    def export_revocations(self) -> bytes:
        """Serialize this replica's revocation set, pruning dead entries first.

        Pruning before export keeps gossip payloads from carrying entries
        that can no longer change a verification outcome.

        Example::

            state = auth.export_revocations()
        """
        self.prune_revocations()
        return super().export_revocations()

    def revocation_stats(self) -> dict[str, int]:
        """Report retained and prunable entry counts, for scenario telemetry.

        Example::

            stats = auth.revocation_stats()
            assert stats["retained"] >= 0
        """
        now = self._now()
        cutoff = now - self._prune_grace
        prunable = sum(
            1
            for tid in self._revoked
            if tid in self._revoked_exp and self._revoked_exp[tid] < cutoff
        )
        return {
            "retained": len(self._revoked),
            "prunable": prunable,
            "unknown_expiry": sum(1 for tid in self._revoked if tid not in self._revoked_exp),
        }

    def chain_summary(self, token: Token) -> dict[str, Any]:
        """Describe a token's chain, for validators and audit events.

        Example::

            summary = auth.chain_summary(child)
            assert summary["depth"] >= 1
        """
        chain = self._decode(token)
        leaf = chain[-1]
        return {
            "depth": len(chain),
            "max_depth": self._max_depth,
            "bytes": len(json.dumps(chain, sort_keys=True, separators=(",", ":"))),
            "leaf_tid": str(leaf.get("tid", "")),
            "leaf_aud": str(leaf.get("aud", "")),
            "scopes": [str(s) for s in cast("list[Any]", leaf.get("scopes", []))],
        }
