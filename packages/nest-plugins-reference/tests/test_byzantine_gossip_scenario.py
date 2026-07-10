# SPDX-License-Identifier: Apache-2.0
"""End-to-end FAIL/PASS gate: byzantine gossip scenarios vs the reference plugin.

Task 6's deliverable: run each of the three adversarial scenarios
(``gossip_byzantine_forgery``, ``gossip_signed_equivocation``,
``gossip_eclipse``) under both ``registry: byzantine_gossip`` and
``registry: gossip`` -- same YAML, same seed, only ``layers.registry``
differs -- and prove the three mandated validators
(``nest_plugins_reference.validators.registry_byzantine_validators``) PASS
for ``byzantine_gossip`` and at least one FAILs for the reference ``gossip``
plugin, deterministically across seeds 42, 7, 1337.

The headline is ``gossip_signed_equivocation``: every card in that scenario
is validly signed by its real publisher key (see
``EquivocatorDriverAgent``) -- the failure it proves is not "signatures are
missing," it is "a registration-signing-only defense (prior art ``#67``)
cannot catch a publisher who signs two conflicting writes."
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import pytest
from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_core.types import AgentId, Query
from nest_plugins_reference.registry.byzantine_gossip import (
    REASON_BAD_SIGNATURE,
    REASON_MISSING_SIGNATURE,
    REASON_SIGNER_MISMATCH,
    content_hash,
)
from nest_plugins_reference.validators.registry_byzantine_validators import (
    EquivocationView,
    check_no_eclipse,
    check_no_equivocation_accepted,
    check_no_forged_card_in_view,
)

_SCENARIOS_DIR = Path(__file__).parent.parent.parent.parent / "scenarios"

_SEEDS = [42, 7, 1337]


def _config(yaml_name: str, registry_plugin: str, trace: Path, seed: int) -> ScenarioConfig:
    """Load a scenario YAML, override its registry plugin/seed/trace path.

    Example::

        config = _config("gossip_byzantine_forgery.yaml", "gossip", trace, 42)
    """
    config = ScenarioConfig.from_yaml(_SCENARIOS_DIR / yaml_name)
    config.layers.registry = registry_plugin
    config.output.trace = str(trace)
    config.seed = seed
    return config


_PHANTOM_SUFFIX_REASONS = {
    "missing": REASON_MISSING_SIGNATURE,
    "mismatch": REASON_SIGNER_MISMATCH,
    "badsig": REASON_BAD_SIGNATURE,
}
"""Maps each ``_forged_entries`` suffix to the rejection reason ``byzantine_gossip``
records for it (see ``nest_core.scenarios_builtin.gossip_byzantine._forged_entries``
and ``byzantine_gossip._verify_card``)."""


def _phantom_ids(yaml_name: str) -> dict[AgentId, str]:
    """Return every phantom id ``ForgerDriverAgent`` injects for ``yaml_name``, mapped to reason.

    Mirrors ``gossip_byzantine_forgery_factory``'s ``phantom_prefix=f"phantom-{i}"``
    enumeration over the scenario's ``forger`` role count and
    ``_forged_entries``'s three fixed suffixes per forger -- computed from the
    scenario YAML itself (not hardcoded) so a role-count change cannot silently
    desync this from the fleet the factory actually builds.

    Example::

        ids = _phantom_ids("gossip_byzantine_forgery.yaml")
        assert ids[AgentId("phantom-0-missing")] == REASON_MISSING_SIGNATURE
    """
    config = ScenarioConfig.from_yaml(_SCENARIOS_DIR / yaml_name)
    forger_count = next(role.count for role in config.agents.roles if role.name == "forger")
    return {
        AgentId(f"phantom-{i}-{suffix}"): reason
        for i in range(forger_count)
        for suffix, reason in _PHANTOM_SUFFIX_REASONS.items()
    }


async def _run(yaml_name: str, registry_plugin: str, trace: Path, seed: int) -> dict[str, Any]:
    """Run a scenario under ``registry_plugin``; return the resolved plugins dict.

    Example::

        plugins = await _run("gossip_eclipse.yaml", "byzantine_gossip", trace, 42)
    """
    runner = ScenarioRunner(_config(yaml_name, registry_plugin, trace, seed))
    await runner.run()
    return runner.resolved_plugins


async def _collect_cards(
    registries: dict[AgentId, Any], honest_ids: set[AgentId]
) -> dict[AgentId, Any]:
    """Pull one representative live ``AgentCard`` per published id from the honest views.

    Example::

        cards = await _collect_cards(registries, honest_ids)
    """
    cards: dict[AgentId, Any] = {}
    for aid in honest_ids:
        for card in await registries[aid].lookup(Query()):
            cards.setdefault(card.agent_id, card)
    return cards


async def _equivocation_views(
    registries: dict[AgentId, Any], honest_ids: set[AgentId]
) -> EquivocationView:
    """Build the content-aware ``EquivocationView`` shape from live registries.

    ``byzantine_gossip`` exposes the content hash directly via its public
    ``content_view()`` accessor, so its evidence is a single public call with
    no re-derivation (the clean drop-in the equivocation validator now enjoys,
    symmetric to the ``view_snapshot()`` the other two validators consume). The
    reference ``gossip`` plugin has no such accessor (by design -- it is the
    negative control, lacking both the ledger and the content view), so its
    evidence is assembled from its public ``view_snapshot()``/``lookup()`` plus
    the plugin module's public ``content_hash()`` helper -- still no private
    state, no ``_WriteTag``, no re-implemented codec.

    Example::

        views = await _equivocation_views(registries, honest_ids)
    """
    out: EquivocationView = {}
    for aid in honest_ids:
        reg = registries[aid]
        per_viewer: dict[AgentId, tuple[int, AgentId, bool, str | None]] = {}
        content_view = getattr(reg, "content_view", None)
        if content_view is not None:
            for pub_id, (version, writer, tombstone, chash) in content_view().items():
                per_viewer[pub_id] = (version, writer, tombstone, chash)
        else:
            snapshot = reg.view_snapshot()
            cards_by_id = {c.agent_id: c for c in await reg.lookup(Query())}
            for pub_id, (version, writer, tombstone) in snapshot.items():
                card = cards_by_id.get(pub_id)
                if card is None:
                    continue  # tombstoned/absent; not exercised by this scenario
                chash = content_hash(card, version, tombstone)
                per_viewer[pub_id] = (version, writer, tombstone, chash)
        out[aid] = per_viewer
    return out


def _equivocation_ledgers(
    registries: dict[AgentId, Any],
) -> dict[AgentId, list[tuple[AgentId, int]]]:
    """Read each registry's ``equivocations`` ledger, defaulting to empty for plugins without one.

    Example::

        ledgers = _equivocation_ledgers(registries)
    """
    return {aid: list(getattr(reg, "equivocations", [])) for aid, reg in registries.items()}


async def _validator_verdicts(plugins: dict[str, Any]) -> dict[str, bool]:
    """Run all three mandated validators against one completed scenario run.

    Example::

        verdicts = await _validator_verdicts(plugins)
        assert verdicts["forged"]
    """
    registries: dict[AgentId, Any] = plugins["_byzantine_registries"]
    identities: dict[AgentId, Any] = plugins["_byzantine_identities"]
    honest_ids: set[AgentId] = plugins["_honest_ids"]
    byzantine_ids: set[AgentId] = plugins["_byzantine_ids"]

    views = {aid: registries[aid].view_snapshot() for aid in honest_ids}
    cards = await _collect_cards(registries, honest_ids)
    forged_report = check_no_forged_card_in_view(views, identities, cards)

    equivocation_views = await _equivocation_views(registries, honest_ids)
    ledgers = _equivocation_ledgers(registries)
    equivocation_report = check_no_equivocation_accepted(ledgers, equivocation_views)

    eclipse_report = check_no_eclipse(views, honest_ids, byzantine_ids)

    return {
        "forged": forged_report.passed,
        "equivocation": equivocation_report.passed,
        "eclipse": eclipse_report.passed,
    }


# ---------------------------------------------------------------------------
# Scenario 1: forgery
# ---------------------------------------------------------------------------


class TestForgeryScenario:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("seed", _SEEDS)
    async def test_byzantine_gossip_passes_all_three(self, tmp_path: Path, seed: int) -> None:
        trace = tmp_path / f"forgery_byz_{seed}.jsonl"
        plugins = await _run("gossip_byzantine_forgery.yaml", "byzantine_gossip", trace, seed)
        verdicts = await _validator_verdicts(plugins)
        assert verdicts == {"forged": True, "equivocation": True, "eclipse": True}

    @pytest.mark.asyncio
    @pytest.mark.parametrize("seed", _SEEDS)
    async def test_reference_gossip_fails_forged_check(self, tmp_path: Path, seed: int) -> None:
        # NOTE: ``verdicts["forged"] is False`` here is also trivially true for a
        # structural reason unrelated to this scenario's attack -- plain `gossip`
        # never signs ANYTHING, including honest agents' own registrations, so
        # every honest card is "unsigned" regardless of whether a forger is even
        # present (see check_no_forged_card_in_view's docstring). That conflates
        # "gossip never signs" with "the injected phantom cards were accepted."
        # test_reference_gossip_accepts_phantom_cards /
        # test_byzantine_gossip_rejects_phantom_cards below assert the
        # attack-specific fact directly: the forger's phantom ids themselves land
        # in honest views under `gossip` and are rejected under
        # `byzantine_gossip`.
        trace = tmp_path / f"forgery_ref_{seed}.jsonl"
        plugins = await _run("gossip_byzantine_forgery.yaml", "gossip", trace, seed)
        verdicts = await _validator_verdicts(plugins)
        assert verdicts["forged"] is False

    @pytest.mark.asyncio
    @pytest.mark.parametrize("seed", _SEEDS)
    async def test_reference_gossip_accepts_phantom_cards(self, tmp_path: Path, seed: int) -> None:
        """The attack-specific fact: forged/impersonated phantom ids land in honest views.

        Causally clean discriminator counterpart to
        ``test_byzantine_gossip_rejects_phantom_cards``: asserts the thing the
        forgery attack actually causes under ``gossip`` -- not merely that
        ``check_no_forged_card_in_view`` fails (which it would even with zero
        forger agents, since ``gossip`` never signs anything).

        Example::

            plugins = await _run("gossip_byzantine_forgery.yaml", "gossip", trace, 42)
        """
        trace = tmp_path / f"forgery_ref_phantom_{seed}.jsonl"
        plugins = await _run("gossip_byzantine_forgery.yaml", "gossip", trace, seed)
        registries: dict[AgentId, Any] = plugins["_byzantine_registries"]
        honest_ids: set[AgentId] = plugins["_honest_ids"]
        phantom_ids = _phantom_ids("gossip_byzantine_forgery.yaml")

        cards = await _collect_cards(registries, honest_ids)
        missing = set(phantom_ids) - cards.keys()
        assert not missing, (
            f"expected every forged phantom id to be accepted into some honest "
            f"view under `gossip` (the attack this scenario proves); missing: "
            f"{sorted(missing)}"
        )

    @pytest.mark.asyncio
    @pytest.mark.parametrize("seed", _SEEDS)
    async def test_byzantine_gossip_rejects_phantom_cards(self, tmp_path: Path, seed: int) -> None:
        """The attack-specific fact: phantom ids are absent everywhere and land in ``rejections``.

        Mirror image of ``test_reference_gossip_accepts_phantom_cards``: under
        ``byzantine_gossip`` the same phantom ids from the same forger agents
        must be absent from *every* honest agent's view (rejected before
        ``_apply``, per-card, at the point ``handle_gossip`` verifies -- see
        ``ByzantineGossipRegistry.handle_gossip``) and each honest registry's
        ``rejections`` ledger must record the expected reason code for it. The
        forger ``ctx.broadcast``s directly to every peer (see
        ``ForgerDriverAgent``/``InMemoryTransport.broadcast``), so every honest
        registry independently receives and rejects each phantom card -- this
        checks all of them, not just "someone."

        Example::

            plugins = await _run("gossip_byzantine_forgery.yaml", "byzantine_gossip", trace, 42)
        """
        trace = tmp_path / f"forgery_byz_phantom_{seed}.jsonl"
        plugins = await _run("gossip_byzantine_forgery.yaml", "byzantine_gossip", trace, seed)
        registries: dict[AgentId, Any] = plugins["_byzantine_registries"]
        honest_ids: set[AgentId] = plugins["_honest_ids"]
        phantom_ids = _phantom_ids("gossip_byzantine_forgery.yaml")

        cards = await _collect_cards(registries, honest_ids)
        leaked = set(phantom_ids) & cards.keys()
        assert not leaked, (
            f"expected every forged phantom id to be rejected before `_apply` "
            f"under `byzantine_gossip`; leaked into a view: {sorted(leaked)}"
        )

        for aid in honest_ids:
            rejections = dict(getattr(registries[aid], "rejections", []))
            for phantom_id, expected_reason in phantom_ids.items():
                assert rejections.get(phantom_id) == expected_reason, (
                    f"expected honest agent {aid!r}'s rejections ledger to record "
                    f"({phantom_id!r}, {expected_reason!r}); got "
                    f"{rejections.get(phantom_id)!r}"
                )


# ---------------------------------------------------------------------------
# Scenario 2: signed equivocation -- THE NOVELTY PROOF
# ---------------------------------------------------------------------------


class TestSignedEquivocationScenario:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("seed", _SEEDS)
    async def test_byzantine_gossip_passes_all_three(self, tmp_path: Path, seed: int) -> None:
        trace = tmp_path / f"equiv_byz_{seed}.jsonl"
        plugins = await _run("gossip_signed_equivocation.yaml", "byzantine_gossip", trace, seed)
        verdicts = await _validator_verdicts(plugins)
        assert verdicts == {"forged": True, "equivocation": True, "eclipse": True}

    @pytest.mark.asyncio
    @pytest.mark.parametrize("seed", _SEEDS)
    async def test_reference_gossip_fails_equivocation_check(
        self, tmp_path: Path, seed: int
    ) -> None:
        trace = tmp_path / f"equiv_ref_{seed}.jsonl"
        plugins = await _run("gossip_signed_equivocation.yaml", "gossip", trace, seed)
        verdicts = await _validator_verdicts(plugins)
        # check_no_forged_card_in_view also FAILs here, but for an unrelated,
        # structural reason: plain `gossip` never signs ANYTHING, including
        # honest agents' own registrations, so every honest card is
        # "unsigned" regardless of this scenario's attack (see that
        # validator's docstring). The invariant THIS scenario proves is
        # narrower and does not depend on that: the equivocator's two cards
        # are both genuinely, validly signed (nothing forged about them),
        # yet the network still silently diverges on their content with no
        # record of it -- check_no_equivocation_accepted is what must FAIL.
        assert verdicts["equivocation"] is False


# ---------------------------------------------------------------------------
# Scenario 3: eclipse
# ---------------------------------------------------------------------------


class TestEclipseScenario:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("seed", _SEEDS)
    async def test_byzantine_gossip_passes_all_three(self, tmp_path: Path, seed: int) -> None:
        trace = tmp_path / f"eclipse_byz_{seed}.jsonl"
        plugins = await _run("gossip_eclipse.yaml", "byzantine_gossip", trace, seed)
        verdicts = await _validator_verdicts(plugins)
        assert verdicts == {"forged": True, "equivocation": True, "eclipse": True}

    @pytest.mark.asyncio
    @pytest.mark.parametrize("seed", _SEEDS)
    async def test_reference_gossip_fails_eclipse_check(self, tmp_path: Path, seed: int) -> None:
        trace = tmp_path / f"eclipse_ref_{seed}.jsonl"
        plugins = await _run("gossip_eclipse.yaml", "gossip", trace, seed)
        verdicts = await _validator_verdicts(plugins)
        assert verdicts["eclipse"] is False

    @pytest.mark.asyncio
    async def test_seed_bank_robustness_gossip_always_eclipsed(self, tmp_path: Path) -> None:
        """`gossip` must FAIL `check_no_eclipse` across the full seed bank, not just {42, 7, 1337}.

        A prior tuning of this scenario (`n_byz=24`, `fanout=2`) only checked
        the three seeds committed as the CI gate above and happened to leave
        2 of 28 seeds in the broader bank (8, 21) where an unlucky/lucky
        independent double-draw let `gossip`'s two honest agents converge
        anyway -- `check_no_eclipse` PASSed there too, so it failed to
        distinguish `gossip` from `byzantine_gossip` on those seeds. This
        test locks in the fix (`n_byz=40`, `fanout=1`, see
        `scenarios/gossip_eclipse.yaml`'s header comment for the sweep that
        produced these parameters): every seed in `range(25)` plus
        `42, 7, 1337` must FAIL for `gossip` while `byzantine_gossip` PASSes
        the full validator triple on every one of the same seeds.
        """
        seed_bank = [*range(25), 42, 7, 1337]
        gossip_pass_seeds: list[int] = []
        byzantine_fail_seeds: list[int] = []
        for seed in seed_bank:
            ref_trace = tmp_path / f"eclipse_seedbank_ref_{seed}.jsonl"
            ref_plugins = await _run("gossip_eclipse.yaml", "gossip", ref_trace, seed)
            ref_verdicts = await _validator_verdicts(ref_plugins)
            if ref_verdicts["eclipse"] is not False:
                gossip_pass_seeds.append(seed)

            byz_trace = tmp_path / f"eclipse_seedbank_byz_{seed}.jsonl"
            byz_plugins = await _run("gossip_eclipse.yaml", "byzantine_gossip", byz_trace, seed)
            byz_verdicts = await _validator_verdicts(byz_plugins)
            if byz_verdicts != {"forged": True, "equivocation": True, "eclipse": True}:
                byzantine_fail_seeds.append(seed)

        assert not gossip_pass_seeds, (
            f"expected `gossip` to FAIL check_no_eclipse on every seed in the bank; "
            f"it PASSed (converged, not eclipsed) on: {gossip_pass_seeds}"
        )
        assert not byzantine_fail_seeds, (
            f"expected `byzantine_gossip` to PASS all three validators on every seed "
            f"in the bank; it did not on: {byzantine_fail_seeds}"
        )


# ---------------------------------------------------------------------------
# Determinism: same seed -> byte-identical trace, across all three scenarios
# ---------------------------------------------------------------------------


class TestDeterminism:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "yaml_name",
        ["gossip_byzantine_forgery.yaml", "gossip_signed_equivocation.yaml", "gossip_eclipse.yaml"],
    )
    @pytest.mark.parametrize("registry_plugin", ["gossip", "byzantine_gossip"])
    async def test_same_seed_identical_trace(
        self, tmp_path: Path, yaml_name: str, registry_plugin: str
    ) -> None:
        t1 = tmp_path / "run1.jsonl"
        t2 = tmp_path / "run2.jsonl"
        await ScenarioRunner(_config(yaml_name, registry_plugin, t1, 42)).run()
        await ScenarioRunner(_config(yaml_name, registry_plugin, t2, 42)).run()
        h1 = hashlib.sha256(t1.read_bytes()).hexdigest()
        h2 = hashlib.sha256(t2.read_bytes()).hexdigest()
        assert h1 == h2
