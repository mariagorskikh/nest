# SPDX-License-Identifier: Apache-2.0
"""Adversarial validator for the capability-conformance registry gate.

The attack this catches: an agent registers a capability claim
(``capabilities=["sell"]``) with a perfectly valid registration and never
honors it. Every existing defense in this repo verifies the *publisher* of
a claim (signatures, identity) or an agent's *overall* reputation
(``agent_receipts``, ``score_average``); none of them checks a claim
against the specific behavior it names. ``check_capability_conformance``
asserts the one property that actually distinguishes a real skill from an
advertised one: after enough observed defections, the registry must stop
returning the claimant for that capability.

Registry ``lookup`` calls are not recorded in the trace (see
``nest_core.sim.simulator``, which traces send/broadcast/deliver/receive
events only), so this validator is not a trace parser. It is a pure
function over a live registry instance -- the same pattern
``registry_byzantine_validators`` and ``gossip_validators`` use for
properties that live in plugin state rather than message content. Callers
obtain the instance from ``ScenarioRunner.resolved_plugins["registry"]``
after running ``scenarios/capability_spoofing.yaml``.

By construction:

* against ``registry: in_memory`` (no concept of a defection), the
  spoofers and the bait-and-switch seller are still returned by
  ``lookup`` at the end of the run -- the check fails;
* against ``registry: verified_capabilities``, they are excluded once
  their defection count crosses the threshold, while every honest seller
  remains discoverable throughout -- the check passes.

Example::

    report = await check_capability_conformance(
        registry, spoofer_ids={AgentId("spoofer-0")}, honest_ids={AgentId("honest-0")},
    )
    assert report.passed, report.detail
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from nest_core.types import Query

if TYPE_CHECKING:
    from nest_core.types import AgentId


@dataclass
class ValidatorReport:
    """Pass/fail report with a short human-readable explanation.

    Example::

        report = ValidatorReport(passed=True, detail="2 spoofers excluded")
        assert report.passed, report.detail
    """

    passed: bool
    detail: str
    evidence: dict[str, object] = field(default_factory=dict[str, object])


async def check_capability_conformance(
    registry: Any,
    *,
    spoofer_ids: set[AgentId],
    honest_ids: set[AgentId],
    capability: str = "sell",
) -> ValidatorReport:
    """Assert defecting claimants are excluded and honest claimants are not.

    Runs a single ``lookup(Query(capabilities=[capability]))`` against
    *registry* and checks two properties together, so a gate that blocks
    everyone cannot pass by accident:

    1. No id in *spoofer_ids* appears in the result (the adversarial
       property this validator exists for).
    2. Every id in *honest_ids* still appears in the result (no
       over-blocking -- a gate that excludes indiscriminately is not a
       fix).

    Example::

        report = await check_capability_conformance(
            registry, spoofer_ids={AgentId("spoofer-0")}, honest_ids={AgentId("honest-0")},
        )
    """
    results = await registry.lookup(Query(capabilities=[capability]))
    visible_ids = {card.agent_id for card in results}

    leaked = sorted(spoofer_ids & visible_ids)
    over_blocked = sorted(honest_ids - visible_ids)

    if leaked or over_blocked:
        problems: list[str] = []
        if leaked:
            problems.append(f"still discoverable for {capability!r}: {leaked}")
        if over_blocked:
            problems.append(f"honest agents wrongly excluded from {capability!r}: {over_blocked}")
        return ValidatorReport(
            passed=False,
            detail="; ".join(problems),
            evidence={
                "visible": sorted(visible_ids),
                "spoofers": sorted(spoofer_ids),
                "honest": sorted(honest_ids),
            },
        )
    return ValidatorReport(
        passed=True,
        detail=(
            f"{len(spoofer_ids)} spoofer(s) excluded from {capability!r}, "
            f"{len(honest_ids)} honest agent(s) still discoverable"
        ),
    )
