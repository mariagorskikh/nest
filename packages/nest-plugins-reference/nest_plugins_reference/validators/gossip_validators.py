# SPDX-License-Identifier: Apache-2.0
"""Adversarial validators for the gossip registry plugin.

Two attacks the default ``in_memory`` registry silently allows:

1. **Cross-partition knowledge leak.**  ``in_memory`` is a single shared
   ``dict`` — every agent's ``lookup`` returns every other agent's card,
   even when the simulator's ``failures.network_partition`` is supposed
   to prevent cross-group discovery.  ``check_no_partition_view_leak``
   catches this by asserting that no agent in partition group ``G_i``
   has a card whose publisher belongs to ``G_j`` (where ``j != i``).
   Bridge agents — listed neither in a partition group nor in
   ``bridge_agents`` — are excluded because they legitimately mediate
   cross-group traffic.
2. **Non-convergence after heal / via bridge.**  Once gossip is
   unblocked, every live agent's view must reach a single byte-identical
   state inside ``K`` rounds.  ``check_converged`` runs the equality
   check; ``K`` is the caller's choice and the PR justifies the value.

Both validators are pure functions on per-agent view snapshots, so they
compose with three call sites: unit tests (build views by hand),
integration tests (snapshot the real ``GossipRegistry`` instances after
running the scenario), and trace replays (rebuild snapshots from a
trace's ``register`` events when the registries are no longer in memory).

By construction:

* against the **gossip** plugin in a partitioned topology, the leak
  check passes and convergence holds via the bridge;
* against the **in_memory** plugin in the same topology, the leak check
  fails immediately (every agent sees every card) — the validator
  literally cannot be satisfied by the reference plugin, which is the
  charter's bar for "adversarial".

Example::

    snaps = {aid: reg.view_snapshot() for aid, reg in regs.items()}
    assert check_no_partition_view_leak(snaps, partition_groups).passed
    assert check_converged(regs, ignore_agents={AgentId("bridge-0")}).passed
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from nest_core.types import AgentId

    from nest_plugins_reference.registry.gossip import GossipRegistry

ViewSnapshot = dict["AgentId", tuple[int, "AgentId", bool]]
"""Per-agent view: ``{published_agent_id: (version, publisher_id, tombstone)}``.

Matches the return type of ``GossipRegistry.view_snapshot()`` exactly so
the validator composes cleanly without an adapter step.
"""


@dataclass
class ValidatorReport:
    """Pass/fail report with a short human-readable explanation.

    Example::

        report = ValidatorReport(passed=True, detail="converged in 4 rounds")
        assert report.passed, report.detail
    """

    passed: bool
    detail: str
    evidence: dict[str, object] = field(default_factory=dict[str, object])


class PartitionLeakError(AssertionError):
    """Raised when an agent's view contains a card from across a partition.

    Example::

        raise PartitionLeakError("peer_a-0 sees peer_b-3 mid-partition")
    """


class ConvergenceFailureError(AssertionError):
    """Raised when agents fail to converge within the bound ``K``.

    Example::

        raise ConvergenceFailureError("3 agents diverged after 10 rounds")
    """


def check_no_partition_view_leak(
    views: dict[AgentId, ViewSnapshot],
    partition_groups: list[list[AgentId]],
    *,
    bridge_agents: set[AgentId] | None = None,
) -> ValidatorReport:
    """Assert no agent in group ``G_i`` knows about a card published in ``G_j``.

    ``views`` is per-agent — each value is what that agent would return
    from ``view_snapshot()``.  ``partition_groups`` is the same shape the
    simulator accepts in ``failures.network_partition.groups``.  Bridge
    agents (those not listed in any group, plus any explicit additions
    in ``bridge_agents``) are skipped — they are *meant* to see both
    sides.

    Returns ``passed=True`` iff every non-bridge agent's view contains
    only cards whose ``publisher_id`` is in the same group as the
    viewing agent.  Otherwise ``passed=False`` with ``evidence["leaks"]``
    listing ``(viewer, leaked_publisher)`` pairs.

    Example::

        report = check_no_partition_view_leak(snaps, partition_groups)
        assert report.passed, report.detail
    """
    group_of: dict[AgentId, int] = {}
    for idx, group in enumerate(partition_groups):
        for aid in group:
            group_of[aid] = idx
    bridges = set(bridge_agents or set())
    leaks: list[tuple[str, str]] = []
    for viewer, snapshot in views.items():
        if viewer in bridges or viewer not in group_of:
            continue
        viewer_group = group_of[viewer]
        for _, (_version, publisher_id, _tombstone) in snapshot.items():
            pub_group = group_of.get(publisher_id)
            if pub_group is None:
                continue  # bridge publishers are allowed everywhere
            if pub_group != viewer_group:
                leaks.append((str(viewer), str(publisher_id)))
    if leaks:
        return ValidatorReport(
            passed=False,
            detail=f"{len(leaks)} cross-partition leaks (viewer sees publisher in other group)",
            evidence={"leaks": leaks[:20]},
        )
    return ValidatorReport(passed=True, detail="no cross-partition view leaks")


def check_converged(
    regs: dict[AgentId, GossipRegistry],
    *,
    ignore_agents: set[AgentId] | None = None,
) -> ValidatorReport:
    """Assert every live agent's view snapshot is byte-identical.

    ``ignore_agents`` excludes a subset (e.g. a bridge that intentionally
    holds a superset view).  Returns ``passed=True`` iff all remaining
    snapshots match one another; otherwise ``evidence["divergent"]``
    lists the diverging agents.

    Example::

        report = check_converged(regs, ignore_agents={AgentId("bridge-0")})
        assert report.passed, report.detail
    """
    ignored = ignore_agents or set()
    live = {aid: reg for aid, reg in regs.items() if aid not in ignored}
    if not live:
        return ValidatorReport(passed=True, detail="no agents to check")
    snapshots = {aid: reg.view_snapshot() for aid, reg in live.items()}
    reference = next(iter(snapshots.values()))
    divergent = [str(aid) for aid, snap in snapshots.items() if snap != reference]
    if divergent:
        return ValidatorReport(
            passed=False,
            detail=f"{len(divergent)} of {len(live)} agents diverged",
            evidence={
                "divergent": divergent,
                "snapshots_seen": len({repr(s) for s in snapshots.values()}),
            },
        )
    return ValidatorReport(passed=True, detail=f"all {len(live)} agents converged")
