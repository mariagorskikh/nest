# SPDX-License-Identifier: Apache-2.0
"""Adversarial validators for the caching resolver registry.

They run concrete liveness attacks against a registry and report whether it kept
discovery honest. They FAIL against the default `in_memory` registry, which has no
notion of time and serves a crashed agent forever, and PASS against the
`resolver`, which expires records by TTL and keeps heartbeating agents alive.

Example::

    from nest_plugins_reference.registry.caching_resolver import CachingResolverRegistry
    report = await run_all_resolver_checks(CachingResolverRegistry(clock=0.0))
    assert report.passed
"""

from __future__ import annotations

from typing import Any

from nest_core.types import AgentCard, AgentId, Query

from nest_plugins_reference.validators.gossip_validators import ValidatorReport

_CAP = "resolve-me"


def _card(agent_id: str, ttl: float) -> AgentCard:
    return AgentCard(
        agent_id=AgentId(agent_id), name=agent_id, capabilities=[_CAP], metadata={"ttl": ttl}
    )


async def check_stale_records_expire(registry: Any) -> ValidatorReport:
    """A crashed agent must stop being resolvable once its TTL lapses.

    Example::

        report = await check_stale_records_expire(registry)
    """
    await registry.register(_card("ghost", ttl=10.0))
    set_clock = getattr(registry, "set_clock", None)
    if set_clock is None:
        return ValidatorReport(
            passed=False,
            detail="registry has no clock or TTL, so dead records never expire",
            evidence={"registry": type(registry).__name__},
        )
    set_clock(1000.0)  # far past the 10s TTL
    remaining = await registry.lookup(Query(capabilities=[_CAP]))
    if remaining:
        return ValidatorReport(
            passed=False,
            detail="a stale record was still resolvable long after its TTL",
            evidence={"still_live": [str(c.agent_id) for c in remaining]},
        )
    return ValidatorReport(passed=True, detail="stale record expired after its TTL", evidence={})


async def check_heartbeat_keeps_alive(registry: Any) -> ValidatorReport:
    """Re-registering before the TTL (a heartbeat) keeps an agent resolvable.

    Example::

        report = await check_heartbeat_keeps_alive(registry)
    """
    set_clock = getattr(registry, "set_clock", None)
    if set_clock is None:
        return ValidatorReport(
            passed=False,
            detail="registry has no clock, so it cannot model liveness at all",
            evidence={"registry": type(registry).__name__},
        )
    set_clock(0.0)
    await registry.register(_card("beat", ttl=10.0))  # expires at 10
    set_clock(5.0)
    await registry.register(_card("beat", ttl=10.0))  # heartbeat: now expires at 15
    set_clock(12.0)  # past the original 10, before the refreshed 15
    live = await registry.lookup(Query(capabilities=[_CAP]))
    if any(str(c.agent_id) == "beat" for c in live):
        return ValidatorReport(
            passed=True,
            detail="heartbeating agent stayed resolvable past its first TTL",
            evidence={},
        )
    return ValidatorReport(
        passed=False,
        detail="a heartbeating agent was wrongly evicted",
        evidence={"registry": type(registry).__name__},
    )


async def check_negative_cache_is_consistent(registry: Any) -> ValidatorReport:
    """A miss stays a miss until a matching agent registers, then it resolves.

    Example::

        report = await check_negative_cache_is_consistent(registry)
    """
    miss = await registry.lookup(Query(capabilities=["nothing-here"]))
    if miss:
        return ValidatorReport(
            passed=False, detail="a lookup for a missing capability returned results", evidence={}
        )
    await registry.register(_card("late", ttl=100.0))
    found = await registry.lookup(Query(capabilities=[_CAP]))
    if not any(str(c.agent_id) == "late" for c in found):
        return ValidatorReport(
            passed=False,
            detail="a freshly registered agent was hidden by a stale negative cache",
            evidence={},
        )
    return ValidatorReport(
        passed=True, detail="negative cache stayed consistent with registrations", evidence={}
    )


async def run_all_resolver_checks(registry: Any) -> ValidatorReport:
    """Run every liveness check; pass only if discovery stayed honest throughout.

    Example::

        report = await run_all_resolver_checks(registry)
        assert report.passed
    """
    reports = [
        await check_stale_records_expire(registry),
        await check_heartbeat_keeps_alive(registry),
        await check_negative_cache_is_consistent(registry),
    ]
    failed = [r for r in reports if not r.passed]
    if failed:
        return ValidatorReport(
            passed=False,
            detail=f"{len(failed)} of {len(reports)} resolver checks failed",
            evidence={"failures": [r.detail for r in failed]},
        )
    return ValidatorReport(
        passed=True, detail=f"all {len(reports)} resolver checks passed", evidence={}
    )
