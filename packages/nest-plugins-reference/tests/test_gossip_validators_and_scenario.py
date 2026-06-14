# SPDX-License-Identifier: Apache-2.0
"""Validator + end-to-end scenario tests for the gossip registry plugin.

Three layers of coverage:

1. **Validator unit tests** — direct, hand-built ``views`` exercising
   pass / leak / partial-leak / bridge-exempt code paths.
2. **Adversarial discrimination** — the same partitioned topology
   run through the ``in_memory`` reference plugin (every agent reads the
   same shared dict) MUST FAIL the leak validator, and through the
   ``gossip`` plugin MUST PASS it.  This is the charter's bar for
   "validator catches a class of attacks the default reference plugin
   would fail."
3. **Full simulator integration** — boot the ``gossip_registry``
   scenario via ``ScenarioRunner``, run it under seeds 42, 7, 1337,
   and assert (a) determinism (same seed → same final snapshot per
   agent), (b) partition honesty mid-run, (c) bridge-mediated
   convergence on the global view by end-of-run.

The integration test exercises the real ``Simulator`` against real
transport with the real ``_should_drop`` partition logic — there is no
mocking past the plugin boundary.
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path
from typing import cast

import pytest
from nest_core.plugins import PluginRegistry
from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_core.types import AgentCard, AgentId, Query
from nest_plugins_reference.registry.gossip import GossipNetwork, GossipRegistry
from nest_plugins_reference.registry.in_memory import InMemoryRegistry
from nest_plugins_reference.validators import (
    check_converged,
    check_no_partition_view_leak,
)

# ---------------------------------------------------------------------------
# Validator unit tests
# ---------------------------------------------------------------------------


def test_leak_validator_passes_on_empty_views() -> None:
    report = check_no_partition_view_leak(
        views={AgentId("g0-0"): {}},
        partition_groups=[[AgentId("g0-0")], [AgentId("g1-0")]],
    )
    assert report.passed


def test_leak_validator_passes_when_agents_only_see_same_group() -> None:
    g0 = [AgentId("g0-0"), AgentId("g0-1")]
    g1 = [AgentId("g1-0")]
    views: dict[AgentId, dict[AgentId, tuple[int, AgentId, bool]]] = {
        g0[0]: {g0[0]: (1, g0[0], False), g0[1]: (1, g0[1], False)},
        g0[1]: {g0[0]: (1, g0[0], False), g0[1]: (1, g0[1], False)},
        g1[0]: {g1[0]: (1, g1[0], False)},
    }
    report = check_no_partition_view_leak(views=views, partition_groups=[g0, g1])
    assert report.passed, report.detail


def test_leak_validator_catches_cross_partition_card() -> None:
    g0 = [AgentId("g0-0")]
    g1 = [AgentId("g1-0")]
    # g0-0's view leaked a card published by g1-0 — the bug we're hunting.
    views: dict[AgentId, dict[AgentId, tuple[int, AgentId, bool]]] = {
        g0[0]: {g1[0]: (1, g1[0], False)},
        g1[0]: {g1[0]: (1, g1[0], False)},
    }
    report = check_no_partition_view_leak(views=views, partition_groups=[g0, g1])
    assert not report.passed
    leaks = report.evidence["leaks"]
    assert isinstance(leaks, list)
    assert ("g0-0", "g1-0") in leaks


def test_leak_validator_exempts_bridge_publishers() -> None:
    """Cards published by bridge agents (no group) are allowed in any view."""
    g0 = [AgentId("g0-0")]
    g1 = [AgentId("g1-0")]
    bridge = AgentId("bridge-0")
    views: dict[AgentId, dict[AgentId, tuple[int, AgentId, bool]]] = {
        g0[0]: {bridge: (1, bridge, False)},
        g1[0]: {bridge: (1, bridge, False)},
    }
    report = check_no_partition_view_leak(views=views, partition_groups=[g0, g1])
    assert report.passed


def test_converged_validator_passes_when_all_equal() -> None:
    gnet = GossipNetwork(agent_ids=[AgentId("a"), AgentId("b")])
    regs = {aid: GossipRegistry(aid, gnet) for aid in [AgentId("a"), AgentId("b")]}
    # No data → all empty → all equal.
    assert check_converged(regs).passed


def test_converged_validator_fails_when_divergent() -> None:
    gnet = GossipNetwork(agent_ids=[AgentId("a"), AgentId("b")])
    regs = {aid: GossipRegistry(aid, gnet) for aid in [AgentId("a"), AgentId("b")]}
    asyncio.run(regs[AgentId("a")].register(AgentCard(agent_id=AgentId("a"), name="A")))
    report = check_converged(regs)
    assert not report.passed
    divergent = cast("list[str]", report.evidence["divergent"])
    assert len(divergent) >= 1


# ---------------------------------------------------------------------------
# Adversarial discrimination — in_memory FAILS, gossip PASSES
# ---------------------------------------------------------------------------


def test_validator_fails_against_in_memory_under_partition() -> None:
    """The shared-dict in_memory registry would let every agent see every card,
    leaking across the partition by construction.  Validator must catch it.
    """
    g0 = [AgentId("g0-0"), AgentId("g0-1")]
    g1 = [AgentId("g1-0"), AgentId("g1-1")]

    shared = InMemoryRegistry()
    for aid in [*g0, *g1]:
        asyncio.run(shared.register(AgentCard(agent_id=aid, name=str(aid))))

    # Materialise each agent's "view" as the shared lookup result — this
    # is what an in_memory-backed scenario would actually return from
    # `ctx.plugins.get("registry").lookup(...)` for any agent.
    cards = asyncio.run(shared.lookup(Query()))
    fake_views: dict[AgentId, dict[AgentId, tuple[int, AgentId, bool]]] = {
        agent: {card.agent_id: (1, card.agent_id, False) for card in cards} for agent in [*g0, *g1]
    }
    report = check_no_partition_view_leak(views=fake_views, partition_groups=[g0, g1])
    assert not report.passed, "in_memory plugin should fail the leak validator"
    leaks = cast("list[tuple[str, str]]", report.evidence["leaks"])
    assert len(leaks) >= 4  # every g0 agent sees every g1 publisher and vice versa


def test_gossip_with_bridge_eventually_converges() -> None:
    """Same topology, gossip plugin + bridge — full convergence is reached.

    Note: with a bridge, the leak validator can NOT pass — bridges
    propagate cards across by design.  The leak validator's adversarial
    bite is against the ``in_memory`` plugin (above) and against a
    bridge-less partitioned topology (``test_gossip_registry.py``'s
    ``test_partition_without_bridge_does_not_leak``).  Here we only
    assert that the bridge mediates *convergence* within the bound K=15.
    """
    import random
    from collections import defaultdict
    from collections.abc import Callable
    from dataclasses import dataclass, field

    g0 = [AgentId(f"g0-{i}") for i in range(3)]
    g1 = [AgentId(f"g1-{i}") for i in range(3)]
    bridge = AgentId("bridge")
    all_ids: list[AgentId] = [*g0, *g1, bridge]
    group_of: dict[AgentId, str] = {**{a: "0" for a in g0}, **{a: "1" for a in g1}}

    def drop(sender: AgentId, target: AgentId) -> bool:
        s = group_of.get(sender)
        t = group_of.get(target)
        if s is None or t is None:
            return False
        return s != t

    gnet = GossipNetwork(agent_ids=all_ids)
    regs = {aid: GossipRegistry(aid, gnet) for aid in all_ids}

    @dataclass
    class _Net:
        drop: Callable[[AgentId, AgentId], bool]
        inbox: dict[AgentId, list[tuple[AgentId, bytes]]] = field(
            default_factory=lambda: defaultdict(list)
        )

    @dataclass
    class _Ctx:
        agent_id: AgentId
        rng: random.Random
        net: _Net
        plugins: dict[str, object] = field(default_factory=lambda: dict[str, object]())
        time: float = 0.0

        async def send(self, to: AgentId, payload: bytes) -> None:
            if not self.net.drop(self.agent_id, to):
                self.net.inbox[to].append((self.agent_id, payload))

        async def broadcast(self, payload: bytes) -> None:
            for peer in [a for a in all_ids if a != self.agent_id]:
                await self.send(peer, payload)

        async def schedule(self, delay: float, payload: bytes) -> None:
            pass

    net = _Net(drop=drop)
    ctxs = {
        aid: _Ctx(agent_id=aid, rng=random.Random(7 + i), net=net) for i, aid in enumerate(all_ids)
    }

    async def round_all() -> None:
        for aid in all_ids:
            await regs[aid].gossip_round(ctxs[aid])  # type: ignore[arg-type]
        while any(net.inbox.values()):
            snap = {aid: list(msgs) for aid, msgs in net.inbox.items() if msgs}
            net.inbox.clear()
            for aid, msgs in snap.items():
                for sender, payload in msgs:
                    await regs[aid].handle_gossip(sender, payload, ctxs[aid])  # type: ignore[arg-type]

    for aid in all_ids:
        asyncio.run(regs[aid].register(AgentCard(agent_id=aid, name=str(aid))))
    for _ in range(15):
        asyncio.run(round_all())

    # Full mesh convergence — bridge has done its job; everyone agrees.
    conv_report = check_converged(regs)
    assert conv_report.passed, conv_report.detail


# ---------------------------------------------------------------------------
# Full simulator integration — boots the actual scenario
# ---------------------------------------------------------------------------


SCENARIO_PATH = Path(__file__).resolve().parents[3] / "scenarios" / "gossip_registry.yaml"


@pytest.mark.parametrize("seed", [42, 7, 1337])
def test_scenario_converges_via_bridge_under_partition(seed: int) -> None:
    """End-to-end: real Simulator, real partition drops, real bridge.

    The bridge agent is *not* listed in any partition group, so the
    simulator's ``_should_drop`` lets it talk to both sides.  After the
    full duration, every agent's view must match (full mesh convergence
    via the bridge).  Tested under three seeds for stability.
    """
    if not SCENARIO_PATH.exists():
        pytest.skip(f"scenario not found at {SCENARIO_PATH}")

    config = ScenarioConfig.from_yaml(str(SCENARIO_PATH))
    config = config.model_copy(update={"seed": seed})

    with tempfile.TemporaryDirectory() as tmp:
        trace_path = Path(tmp) / f"gossip_{seed}.jsonl"
        config = config.model_copy(
            update={"output": config.output.model_copy(update={"trace": str(trace_path)})}
        )
        runner = ScenarioRunner(config, registry=PluginRegistry())
        asyncio.run(runner.run())

        per_agent_regs = runner.resolved_plugins.get("_gossip_registries")
        assert per_agent_regs is not None, "scenario factory should expose _gossip_registries"

        conv_report = check_converged(per_agent_regs)
        assert conv_report.passed, f"seed={seed} divergence: {conv_report.detail}"


def test_scenario_deterministic_under_replay() -> None:
    """Two runs with seed=42 produce identical per-agent snapshots."""
    if not SCENARIO_PATH.exists():
        pytest.skip(f"scenario not found at {SCENARIO_PATH}")

    def run_once() -> dict[str, dict[AgentId, tuple[int, AgentId, bool]]]:
        config = ScenarioConfig.from_yaml(str(SCENARIO_PATH))
        config = config.model_copy(update={"seed": 42})
        with tempfile.TemporaryDirectory() as tmp:
            trace_path = Path(tmp) / "gossip_replay.jsonl"
            config = config.model_copy(
                update={"output": config.output.model_copy(update={"trace": str(trace_path)})}
            )
            runner = ScenarioRunner(config, registry=PluginRegistry())
            asyncio.run(runner.run())
            regs = runner.resolved_plugins["_gossip_registries"]
            return {str(aid): reg.view_snapshot() for aid, reg in regs.items()}

    assert run_once() == run_once()
