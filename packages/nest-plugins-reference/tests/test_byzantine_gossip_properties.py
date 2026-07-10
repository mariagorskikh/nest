# SPDX-License-Identifier: Apache-2.0
"""Hypothesis property tests for the byzantine-resistant gossip registry.

Tasks 1-4 (see ``nest_plugins_reference.registry.byzantine_gossip``) built the
mechanism: signed cards re-verified on every gossip hop, an equivocation
witness map that quarantines a publisher caught signing two conflicting
writes at the same version, and an eclipse-resistant peer sampler. Task 6
proved that mechanism against three hand-authored adversarial scenarios.

This module is the "test rigor" muscle that generalizes past those three
hand-picked cases: every property below is checked against Hypothesis
-generated adversarial input (forged/mutated/replayed cards, arbitrary honest
write interleavings, arbitrary mixes of honest and equivocating publishers,
arbitrary byzantine fractions and seeds) instead of a fixed example. A
property that fails on some generated input is either a real plugin bug (do
not weaken the property -- report it) or a genuine, already-documented design
limit (the quarantine-then-honest-recovery edge case below is exactly that:
quarantine is permanent by design, see the plugin's module docstring).

Everything here drives the plugin directly (no ``Simulator``/scenario YAML,
unlike ``test_byzantine_gossip_scenario.py``) via a small deterministic
routing harness copied in spirit from ``test_byzantine_gossip.py``'s
``_RoutingContext`` -- ``ctx.send`` delivers straight into the target
registry's ``handle_gossip``, so a full push-pull round trip resolves
synchronously and reproducibly without spinning up the transport/simulator
layers. Determinism end to end: every agent's ``random.Random`` is seeded
from a SHA-256 digest of ``(seed, agent_id)``, never from Python's
hash-randomized ``hash()``, so replays are byte-identical regardless of
``PYTHONHASHSEED``.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import random
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from nest_core.types import AgentCard, AgentId, Query
from nest_plugins_reference.identity.did_key import DidKeyIdentity
from nest_plugins_reference.registry.byzantine_gossip import (
    ByzantineGossipRegistry,
    _verify_card,  # pyright: ignore[reportPrivateUsage]
    canonical_write_bytes,
)
from nest_plugins_reference.registry.gossip import (
    GOSSIP_PREFIX,
    OP_PUSH,
    GossipNetwork,
    _WriteTag,  # pyright: ignore[reportPrivateUsage]
)

# ---------------------------------------------------------------------------
# Deterministic routing harness
# ---------------------------------------------------------------------------


def _sha256_int(text: str) -> int:
    """Stable (non-hash-randomized) integer derived from ``text``.

    Python's ``hash()`` of ``str``/``tuple[str, ...]`` is salted per-process
    by ``PYTHONHASHSEED`` unless that env var is pinned. Seeding per-agent
    ``random.Random`` instances from ``hash()`` would make "same seed, same
    op sequence -> identical replay" (the determinism property this module
    exists to check) true only *within* one interpreter invocation, not
    across two. SHA-256 has no such salt.

    Example::

        n = _sha256_int("seed:42:agent-a")
    """
    return int.from_bytes(hashlib.sha256(text.encode()).digest()[:8], "big")


def _agent_rng(seed: int, agent_id: AgentId) -> random.Random:
    """Deterministic per-agent RNG derived from ``(seed, agent_id)``.

    Example::

        rng = _agent_rng(42, AgentId("a"))
    """
    return random.Random(_sha256_int(f"{seed}:{agent_id}"))


class _RoutingContext:
    """Minimal ``AgentContext`` stand-in that routes gossip synchronously.

    Structural copy of ``test_byzantine_gossip.py``'s ``_RoutingContext``:
    ``ctx.send`` delivers a payload straight into the target registry's
    ``handle_gossip`` using the *target's own* context, so a digest ->
    push-reply round trip resolves inline without a real transport/simulator.

    Example::

        ctx = _RoutingContext(AgentId("a"), rng, registries, contexts)
        await registries[AgentId("a")].gossip_round(ctx)  # type: ignore[arg-type]
    """

    def __init__(
        self,
        agent_id: AgentId,
        rng: random.Random,
        registries: dict[AgentId, ByzantineGossipRegistry],
        contexts: dict[AgentId, _RoutingContext],
    ) -> None:
        self.agent_id = agent_id
        self.rng = rng
        self._registries = registries
        self._contexts = contexts

    async def send(self, to: AgentId, payload: bytes) -> None:
        await self._registries[to].handle_gossip(
            self.agent_id,
            payload,
            self._contexts[to],  # type: ignore[arg-type]
        )


@dataclass
class _Harness:
    """A fully-wired ``ByzantineGossipRegistry`` mesh for property tests.

    Every agent in ``ids`` gets a ``DidKeyIdentity`` that knows every *other*
    agent's public key (so any genuinely-signed card verifies everywhere)
    plus a ``ByzantineGossipRegistry`` sharing one ``GossipNetwork`` (shared
    monotonic per-publisher versions) and a ``_RoutingContext`` seeded
    deterministically from ``(seed, agent_id)``.

    Example::

        h = _build_harness(["a", "b", "c"], seed=42)
        await h.registries[AgentId("a")].register(AgentCard(agent_id=AgentId("a"), name="A"))
    """

    ids: list[AgentId]
    net: GossipNetwork
    idents: dict[AgentId, DidKeyIdentity]
    registries: dict[AgentId, ByzantineGossipRegistry]
    contexts: dict[AgentId, _RoutingContext]


def _build_harness(names: list[str], *, seed: int, fanout: int = 3) -> _Harness:
    """Build a ``_Harness`` of ``ByzantineGossipRegistry`` peers named ``names``.

    Example::

        h = _build_harness(["a", "b"], seed=7)
    """
    ids = [AgentId(n) for n in names]
    idents = {aid: DidKeyIdentity(aid, seed=f"harness-{seed}-{aid}".encode()) for aid in ids}
    for aid, ident in idents.items():
        for peer_id, peer_ident in idents.items():
            if peer_id != aid:
                ident.register_peer(peer_id, peer_ident.public_key)
    net = GossipNetwork(agent_ids=ids, fanout=fanout)
    registries = {aid: ByzantineGossipRegistry(aid, net, idents[aid]) for aid in ids}
    contexts: dict[AgentId, _RoutingContext] = {}
    for aid in ids:
        contexts[aid] = _RoutingContext(aid, _agent_rng(seed, aid), registries, contexts)
    return _Harness(ids=ids, net=net, idents=idents, registries=registries, contexts=contexts)


def _push_payload(entries: list[tuple[AgentCard, _WriteTag, bool]]) -> bytes:
    """Hand-encode an ``OP_PUSH`` wire payload (mirrors ``gossip.py``'s ``_encode_push``).

    Example::

        payload = _push_payload([(card, tag, False)])
    """
    obj = [
        {
            "card": card.model_dump(mode="json"),
            "version": tag.version,
            "publisher": str(tag.publisher_id),
            "tombstone": tombstone,
        }
        for card, tag, tombstone in entries
    ]
    body = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
    return GOSSIP_PREFIX + OP_PUSH + body


def _signed_entry(
    ident: DidKeyIdentity,
    publisher_id: AgentId,
    version: int,
    name: str,
    capabilities: list[str],
    *,
    tombstone: bool = False,
) -> tuple[AgentCard, _WriteTag, bool]:
    """Build a genuinely-signed ``(card, tag, tombstone)`` push entry for ``publisher_id``.

    Example::

        entry = _signed_entry(ident, AgentId("e"), 1, "E", ["sell"])
    """
    content = AgentCard(agent_id=publisher_id, name=name, capabilities=capabilities)
    sig = ident.sign(canonical_write_bytes(content, version, tombstone))
    card = content.model_copy(
        update={
            "metadata": {
                "sig": {
                    "signer": str(publisher_id),
                    "value": sig.value.hex(),
                    "algorithm": sig.algorithm,
                }
            }
        }
    )
    return card, _WriteTag(version=version, publisher_id=publisher_id), tombstone


def _assert_all_views_verify(
    registries: dict[AgentId, ByzantineGossipRegistry], honest_ids: Iterable[AgentId]
) -> None:
    """Re-verify every card sitting in every honest agent's view, from scratch.

    This is property 1 made literal: it does not trust ``rejections`` or
    ``view_snapshot()`` membership bookkeeping, it re-runs
    ``_verify_card(card, version, tombstone, own_identity)`` -- the exact
    check ``handle_gossip`` uses -- against every card currently stored in
    every honest registry's local view. If this ever fails, an unverifiable
    card made it into an honest view, which is the one thing this whole
    plugin exists to prevent.

    Example::

        _assert_all_views_verify(h.registries, [AgentId("v"), AgentId("w")])
    """
    for aid in honest_ids:
        reg = registries[aid]
        for publisher_id, (version, _writer, tombstone) in reg.view_snapshot().items():
            versioned = reg._view[publisher_id]  # pyright: ignore[reportPrivateUsage]
            reason = _verify_card(
                versioned.card,
                version,
                tombstone,
                reg._identity,  # pyright: ignore[reportPrivateUsage]
            )
            assert reason is None, (
                f"{aid}'s view contains an unverifiable card from {publisher_id} "
                f"(reason={reason}); a forged/mutated/replayed card leaked in"
            )


_FULL_CONVERGENCE_ROUNDS = 12
"""Round budget for "drive every agent's ``gossip_round`` this many times, then
assert convergence." Derived the same way as the plain ``gossip`` plugin's
``K=10`` bound (module docstring of ``gossip.py``): ``O(log_F(N))`` in the
best case, generous safety margin added because push-pull here is
asymmetric-per-round (entries only flow INTO the agent that initiates a
round, see ``gossip_round``'s docstring) and because harness networks in
this module are small (<= 9 agents) but may dedicate some fanout slots to
non-relaying byzantine peers in the adversarial-fraction sweep.
"""


async def _run_full_rounds(h: _Harness, ids: list[AgentId], rounds: int) -> None:
    """Drive ``gossip_round`` for every id in ``ids``, ``rounds`` times, in order.

    Example::

        await _run_full_rounds(h, h.ids, _FULL_CONVERGENCE_ROUNDS)
    """
    for _ in range(rounds):
        for aid in ids:
            await _gossip_round(h, aid)


async def _gossip_round(h: _Harness, aid: AgentId) -> None:
    """Run one ``gossip_round`` for ``aid``, using its harness-owned ``_RoutingContext``.

    Isolates the ``_RoutingContext`` / ``AgentContext`` protocol mismatch
    (``_RoutingContext`` deliberately implements only ``send``, not the full
    ``AgentContext`` protocol -- see that class's docstring) to one place so
    the ``# type: ignore`` survives ``ruff format`` reflowing call sites.

    Example::

        await _gossip_round(h, AgentId("a"))
    """
    await h.registries[aid].gossip_round(h.contexts[aid])  # type: ignore[arg-type]


async def _deliver(h: _Harness, target: AgentId, sender: AgentId, payload: bytes) -> None:
    """Deliver ``payload`` into ``target``'s ``handle_gossip`` as if sent by ``sender``.

    Same rationale as ``_gossip_round``: one place for the
    ``_RoutingContext``/``AgentContext`` ``# type: ignore``, immune to
    ``ruff format`` splitting a multi-argument call across lines and
    stranding the comment on the wrong line.

    Example::

        await _deliver(h, AgentId("v"), attacker_id, payload)
    """
    await h.registries[target].handle_gossip(sender, payload, h.contexts[target])  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Property 1: forged-never-accepted
# ---------------------------------------------------------------------------


class _AttackKind(StrEnum):
    """Enumerates the forged/impersonated/replayed push-entry shapes property 1 generates.

    Example::

        kind = _AttackKind.GARBAGE_SIGNATURE
    """

    MISSING_SIGNATURE = "missing_signature"
    SIGNER_MISMATCH = "signer_mismatch"
    GARBAGE_SIGNATURE = "garbage_signature"
    WRONG_KEY_SIGNATURE = "wrong_key_signature"
    INFLATED_VERSION_REPLAY = "inflated_version_replay"
    TOMBSTONE_FLIP = "tombstone_flip"
    MUTATED_CONTENT = "mutated_content"


_attack_specs_strategy = st.lists(
    st.tuples(st.sampled_from(list(_AttackKind)), st.integers(min_value=0, max_value=999)),
    min_size=1,
    max_size=8,
)


def _materialize_attack(
    kind: _AttackKind,
    param: int,
    *,
    honest_card: AgentCard,
    honest_tag: _WriteTag,
    attacker_id: AgentId,
    attacker_ident: DidKeyIdentity,
) -> tuple[AgentCard, _WriteTag, bool]:
    """Turn an ``(_AttackKind, param)`` spec into a malicious push entry.

    ``REPLAY``/``TOMBSTONE_FLIP``/``MUTATED_CONTENT`` always target the real
    honest publisher (they model a relay-with-no-private-key attack on a
    genuine card). The others alternate (via ``param``'s parity) between
    impersonating the real honest publisher and forging a wholly new phantom
    id -- both are "no honest view ever contains an unverifiable card" cases.

    Example::

        entry = _materialize_attack(
            _AttackKind.GARBAGE_SIGNATURE, 3,
            honest_card=card, honest_tag=tag,
            attacker_id=AgentId("m"), attacker_ident=attacker_ident,
        )
    """
    publisher_id = honest_card.agent_id
    target_id = publisher_id if param % 2 == 0 else AgentId(f"phantom-{param}")

    if kind is _AttackKind.MISSING_SIGNATURE:
        card = AgentCard(agent_id=target_id, name="EVIL", metadata={})
        return card, _WriteTag(version=param + 1, publisher_id=target_id), False

    if kind is _AttackKind.SIGNER_MISMATCH:
        content = AgentCard(agent_id=target_id, name="EVIL")
        sig = attacker_ident.sign(canonical_write_bytes(content, param + 1, False))
        card = content.model_copy(
            update={
                "metadata": {
                    "sig": {
                        "signer": str(attacker_id),
                        "value": sig.value.hex(),
                        "algorithm": sig.algorithm,
                    }
                }
            }
        )
        return card, _WriteTag(version=param + 1, publisher_id=target_id), False

    if kind is _AttackKind.GARBAGE_SIGNATURE:
        garbage = hashlib.sha256(f"garbage-{param}".encode()).digest()
        card = AgentCard(
            agent_id=target_id,
            name="EVIL",
            metadata={
                "sig": {
                    "signer": str(target_id),
                    "value": garbage.hex(),
                    "algorithm": "sim-rsa-sha256",
                }
            },
        )
        return card, _WriteTag(version=param + 1, publisher_id=target_id), False

    if kind is _AttackKind.WRONG_KEY_SIGNATURE:
        content = AgentCard(agent_id=target_id, name="EVIL")
        sig = attacker_ident.sign(canonical_write_bytes(content, param + 1, False))
        card = content.model_copy(
            update={
                "metadata": {
                    "sig": {
                        "signer": str(target_id),
                        "value": sig.value.hex(),
                        "algorithm": sig.algorithm,
                    }
                }
            }
        )
        return card, _WriteTag(version=param + 1, publisher_id=target_id), False

    if kind is _AttackKind.INFLATED_VERSION_REPLAY:
        forged_tag = _WriteTag(version=honest_tag.version + param + 1, publisher_id=publisher_id)
        return honest_card, forged_tag, False

    if kind is _AttackKind.TOMBSTONE_FLIP:
        return honest_card, honest_tag, True

    # MUTATED_CONTENT
    mutated = honest_card.model_copy(update={"name": f"MUTATED-{param}"})
    return mutated, honest_tag, False


@given(attacks=_attack_specs_strategy)
@settings(max_examples=60, deadline=None)
def test_property_forged_never_accepted(attacks: list[tuple[_AttackKind, int]]) -> None:
    """No honest view ever contains a card whose signature doesn't verify.

    Builds a 3-agent honest mesh (``v``, ``w``, ``h``), registers one real
    card for ``h``, then bundles Hypothesis-generated forged/impersonated
    /replayed/mutated entries (plus the one genuine card, to check for
    collateral damage) into a single ``OP_PUSH`` from an outside attacker
    straight into ``v``. A few full gossip rounds then give any leak a
    chance to propagate to ``w`` too. ``_assert_all_views_verify`` is the
    property itself: every card left standing in ``v`` and ``w``'s views
    must independently re-verify.
    """
    seed = 42
    h = _build_harness(["v", "w", "h"], seed=seed)
    attacker_id = AgentId("m")
    attacker_ident = DidKeyIdentity(attacker_id, seed=b"attacker-seed-1")

    async def _drive() -> None:
        await h.registries[AgentId("h")].register(
            AgentCard(agent_id=AgentId("h"), name="H", capabilities=["sell"])
        )
        [honest_card] = await h.registries[AgentId("h")].lookup(Query())
        honest_tag = _WriteTag(version=1, publisher_id=AgentId("h"))

        entries = [
            _materialize_attack(
                kind,
                param,
                honest_card=honest_card,
                honest_tag=honest_tag,
                attacker_id=attacker_id,
                attacker_ident=attacker_ident,
            )
            for kind, param in attacks
        ]
        entries.append((honest_card, honest_tag, False))  # the genuine card, mixed in

        payload = _push_payload(entries)
        await _deliver(h, AgentId("v"), attacker_id, payload)

        await _run_full_rounds(h, h.ids, rounds=6)

    asyncio.run(_drive())

    _assert_all_views_verify(h.registries, [AgentId("v"), AgentId("w")])

    # No collateral damage: the one genuine card still reads back correctly.
    [seen] = asyncio.run(h.registries[AgentId("v")].lookup(Query(name_pattern="H")))
    assert seen.name == "H"
    assert seen.capabilities == ["sell"]


# ---------------------------------------------------------------------------
# Property 2: convergence of the honest sub-network
# ---------------------------------------------------------------------------

_HONEST_NAMES = ["a", "b", "c"]

_op_strategy = st.lists(
    st.tuples(
        st.sampled_from(range(len(_HONEST_NAMES))),
        st.sampled_from(["register", "deregister"]),
        st.lists(st.sampled_from(["sell", "buy", "ship"]), max_size=2, unique=True),
    ),
    min_size=1,
    max_size=12,
)


@given(ops=_op_strategy)
@settings(max_examples=60, deadline=None)
def test_property_honest_subnetwork_converges(ops: list[tuple[int, str, list[str]]]) -> None:
    """Any honest write interleaving converges to one identical snapshot within K rounds.

    ``ops`` is a Hypothesis-generated interleaving of register/deregister
    calls across 3 honest agents (arbitrary order, arbitrary repeats -- an
    agent may register, deregister, then register again). After applying
    every op, ``_FULL_CONVERGENCE_ROUNDS`` full rounds must be enough for
    every agent's ``view_snapshot()`` to become byte-identical.
    """
    seed = 7
    h = _build_harness(_HONEST_NAMES, seed=seed)
    ids = [AgentId(n) for n in _HONEST_NAMES]

    async def _drive() -> None:
        for idx, kind, caps in ops:
            aid = ids[idx]
            reg = h.registries[aid]
            if kind == "register":
                await reg.register(AgentCard(agent_id=aid, name=f"agent-{idx}", capabilities=caps))
            else:
                await reg.deregister(aid)
        await _run_full_rounds(h, ids, _FULL_CONVERGENCE_ROUNDS)

    asyncio.run(_drive())

    snapshots = {aid: h.registries[aid].view_snapshot() for aid in ids}
    reference = next(iter(snapshots.values()))
    for aid, snap in snapshots.items():
        assert snap == reference, (
            f"{aid} failed to converge within {_FULL_CONVERGENCE_ROUNDS} rounds"
        )


# ---------------------------------------------------------------------------
# Property 3: equivocation always caught + quarantined, no false positives
# ---------------------------------------------------------------------------

_PUBLISHER_NAMES = ["p0", "p1", "p2", "p3"]

_equivocation_flags_strategy = st.lists(st.booleans(), min_size=4, max_size=4)


@given(equivocating=_equivocation_flags_strategy)
@settings(max_examples=60, deadline=None)
def test_property_equivocation_always_caught_no_false_positive(equivocating: list[bool]) -> None:
    """Every equivocating publisher is quarantined + never in an honest view; honest ones are not.

    4 publisher slots, each independently marked equivocating or honest by
    Hypothesis. An equivocating slot gets two validly-signed, content
    -differing cards at the SAME version injected (in one push, so the
    witness map sees both); an honest slot gets exactly one genuinely
    -signed card. Both are injected directly into ``v``, then propagated to
    ``w`` over several full rounds -- so this also exercises that a
    publisher ``v`` already quarantined never gets relayed onward (``w``
    never even receives its entries) while honest publishers reliably do.
    """
    seed = 1337
    names = ["v", "w", *_PUBLISHER_NAMES]
    h = _build_harness(names, seed=seed)
    v, w = AgentId("v"), AgentId("w")
    publisher_ids = [AgentId(n) for n in _PUBLISHER_NAMES]

    async def _drive() -> None:
        for pid, is_equiv in zip(publisher_ids, equivocating, strict=True):
            ident = h.idents[pid]
            if is_equiv:
                entry_1 = _signed_entry(ident, pid, 1, "GOOD", ["sell"])
                entry_2 = _signed_entry(ident, pid, 1, "EVIL", ["buy"])
                payload = _push_payload([entry_1, entry_2])
                await _deliver(h, v, pid, payload)
            else:
                entry = _signed_entry(ident, pid, 1, "HONEST", ["sell"])
                payload = _push_payload([entry])
                await _deliver(h, v, pid, payload)

        await _run_full_rounds(h, [AgentId(n) for n in names], _FULL_CONVERGENCE_ROUNDS)

    asyncio.run(_drive())

    equivocators = {
        pid for pid, is_equiv in zip(publisher_ids, equivocating, strict=True) if is_equiv
    }
    honest_pubs = {
        pid for pid, is_equiv in zip(publisher_ids, equivocating, strict=True) if not is_equiv
    }

    for aid in (v, w):
        snap = h.registries[aid].view_snapshot()
        for pid in equivocators:
            assert pid not in snap, f"{aid}'s view still contains quarantined publisher {pid}"
        for pid in honest_pubs:
            assert pid in snap, f"{aid}'s view is missing honest publisher {pid} after convergence"

    v_ledger = {pid for pid, _version in h.registries[v].equivocations}
    assert v_ledger == equivocators, (
        f"v's equivocations ledger {v_ledger} does not match injected equivocators {equivocators}"
    )


# ---------------------------------------------------------------------------
# Property 4: determinism
# ---------------------------------------------------------------------------


@given(attacks=_attack_specs_strategy, equivocating=_equivocation_flags_strategy)
@settings(max_examples=60, deadline=None)
def test_property_determinism_same_seed_same_ops(
    attacks: list[tuple[_AttackKind, int]], equivocating: list[bool]
) -> None:
    """Same seed + same op sequence -> byte-identical ``view_snapshot()``/ledgers, twice.

    Reruns the exact composite scenario (forged attacks from property 1 +
    equivocating/honest publishers from property 3, on a fixed seed) in two
    completely fresh harnesses and asserts every agent's ``view_snapshot()``,
    ``rejections``, and ``equivocations`` are equal -- then hashes a
    canonical JSON encoding of the whole run to pin "byte-identical", not
    merely "structurally equal".
    """
    seed = 0xDEADBEEF
    names = ["v", "w", "h", *_PUBLISHER_NAMES]

    def _run_once() -> tuple[dict[str, object], ...]:
        h = _build_harness(names, seed=seed)
        attacker_id = AgentId("m")
        attacker_ident = DidKeyIdentity(attacker_id, seed=b"attacker-seed-det")

        async def _drive() -> None:
            await h.registries[AgentId("h")].register(
                AgentCard(agent_id=AgentId("h"), name="H", capabilities=["sell"])
            )
            [honest_card] = await h.registries[AgentId("h")].lookup(Query())
            honest_tag = _WriteTag(version=1, publisher_id=AgentId("h"))
            entries = [
                _materialize_attack(
                    kind,
                    param,
                    honest_card=honest_card,
                    honest_tag=honest_tag,
                    attacker_id=attacker_id,
                    attacker_ident=attacker_ident,
                )
                for kind, param in attacks
            ]
            entries.append((honest_card, honest_tag, False))
            payload = _push_payload(entries)
            await _deliver(h, AgentId("v"), attacker_id, payload)

            for pid, is_equiv in zip(
                [AgentId(n) for n in _PUBLISHER_NAMES], equivocating, strict=True
            ):
                ident = h.idents[pid]
                if is_equiv:
                    e1 = _signed_entry(ident, pid, 1, "GOOD", ["sell"])
                    e2 = _signed_entry(ident, pid, 1, "EVIL", ["buy"])
                    push = _push_payload([e1, e2])
                else:
                    push = _push_payload([_signed_entry(ident, pid, 1, "HONEST", ["sell"])])
                await _deliver(h, AgentId("v"), pid, push)

            await _run_full_rounds(h, [AgentId(n) for n in names], rounds=4)

        asyncio.run(_drive())

        return tuple(
            {
                "agent": n,
                "snapshot": {
                    str(pid): [ver, str(writer), tomb]
                    for pid, (ver, writer, tomb) in h.registries[AgentId(n)].view_snapshot().items()
                },
                "rejections": [
                    (str(aid), reason) for aid, reason in h.registries[AgentId(n)].rejections
                ],
                "equivocations": [
                    (str(aid), version) for aid, version in h.registries[AgentId(n)].equivocations
                ],
            }
            for n in names
        )

    run_1 = _run_once()
    run_2 = _run_once()
    assert run_1 == run_2

    canon_1 = json.dumps(run_1, sort_keys=True, separators=(",", ":")).encode()
    canon_2 = json.dumps(run_2, sort_keys=True, separators=(",", ":")).encode()
    assert hashlib.sha256(canon_1).hexdigest() == hashlib.sha256(canon_2).hexdigest()


# ---------------------------------------------------------------------------
# Property 5 (overlay #3): adversarial-fraction sweep
# ---------------------------------------------------------------------------

_SWEEP_SEEDS = [42, 7, 1337, 0xDEADBEEF]
_SWEEP_N = 9
_SWEEP_ROUNDS = 24


def _byzantine_fractions(n: int) -> list[int]:
    """``f`` values from 0 up to ``floor((n-1)/2)`` inclusive.

    Example::

        assert _byzantine_fractions(9) == [0, 1, 2, 3, 4]
    """
    return list(range(0, (n - 1) // 2 + 1))


def _byzantine_indices(n: int, f: int) -> set[int]:
    """``f`` distinct indices spread roughly evenly across ``range(n)``.

    Asserts the result has exactly ``f`` members: ``{int(i * step) for i in
    range(f)}`` silently collapses to FEWER than ``f`` distinct indices if
    ``step = n / f`` is small enough that two different ``i`` truncate to the
    same ``int(i * step)`` -- which would under-represent the byzantine
    fraction the caller asked for instead of failing loudly. That can only
    happen if ``_SWEEP_N`` (currently 9) is ever reduced relative to the
    ``f`` values ``_byzantine_fractions`` produces; this assertion is a
    tripwire for that future change.

    Example::

        assert _byzantine_indices(9, 4) == {0, 2, 4, 6}
    """
    if f <= 0:
        return set()
    step = n / f
    result = {int(i * step) for i in range(f)}
    assert len(result) == f, (
        f"_byzantine_indices(n={n}, f={f}) collapsed to {len(result)} distinct "
        f"indices {result}, expected {f}; _SWEEP_N is too small for this f"
    )
    return result


def _byzantine_bad_entries(
    byzantine_indices: Iterable[int],
    names: list[str],
    attacker_ident: DidKeyIdentity,
    idents: dict[AgentId, DidKeyIdentity],
) -> list[tuple[AgentCard, _WriteTag, bool]]:
    """Build the forged-phantom + equivocation-pair entries one byzantine slot injects.

    Two forged phantom-id entries (unsigned, and a wrong-key forgery) plus a
    genuinely-signed equivocating pair from the byzantine agent's OWN real
    identity (proving a byzantine publisher, not just a relay, can be
    caught) per byzantine slot.

    Example::

        entries = _byzantine_bad_entries({0, 2}, names, attacker_ident, idents)
    """
    entries: list[tuple[AgentCard, _WriteTag, bool]] = []
    for i in byzantine_indices:
        phantom_id = AgentId(f"phantom-{i}")
        entries.append(
            (
                AgentCard(agent_id=phantom_id, name="EVIL"),
                _WriteTag(version=1, publisher_id=phantom_id),
                False,
            )
        )

        content = AgentCard(agent_id=phantom_id, name="EVIL2")
        sig = attacker_ident.sign(canonical_write_bytes(content, 1, False))
        forged = content.model_copy(
            update={
                "metadata": {
                    "sig": {
                        "signer": str(phantom_id),
                        "value": sig.value.hex(),
                        "algorithm": sig.algorithm,
                    }
                }
            }
        )
        entries.append((forged, _WriteTag(version=1, publisher_id=phantom_id), False))

        byz_id = AgentId(names[i])
        ident = idents[byz_id]
        entries.append(_signed_entry(ident, byz_id, 1, "GOOD", ["sell"]))
        entries.append(_signed_entry(ident, byz_id, 1, "EVIL", ["buy"]))
    return entries


@pytest.mark.parametrize("seed", _SWEEP_SEEDS)
@pytest.mark.parametrize("f", _byzantine_fractions(_SWEEP_N))
def test_adversarial_fraction_sweep(f: int, seed: int) -> None:
    """For f/N from 0 up to floor((N-1)/2)/N: honest sub-network converges, nothing forged lands.

    ``N=9`` agents, ``f`` of them byzantine (spread across the id space, not
    adversarially chosen against the eclipse-resistance heuristic -- that
    positional worst case is covered separately by
    ``test_eclipse_resistance_keeps_honest_contact`` in
    ``test_byzantine_gossip.py``). Every byzantine slot broadcasts a forged
    -phantom pair and an equivocating pair directly into every honest
    agent's ``handle_gossip`` (worst case: a malicious relay reaches
    everyone), then only the honest agents run ``gossip_round`` for
    ``_SWEEP_ROUNDS``. Byzantine agents still occupy real peer slots (so
    honest agents "waste" some anchor/random draws contacting a silent,
    non-relaying byzantine registry), exercising the eclipse-resistant
    sampler under load.
    """
    n = _SWEEP_N
    names = [f"agent{i:02d}" for i in range(n)]
    byzantine_idx = _byzantine_indices(n, f)
    honest_idx = [i for i in range(n) if i not in byzantine_idx]

    h = _build_harness(names, seed=seed)
    attacker_id = AgentId("sweep-attacker")
    attacker_ident = DidKeyIdentity(attacker_id, seed=f"sweep-attacker-{seed}".encode())
    honest_ids = [AgentId(names[i]) for i in honest_idx]
    byz_ids = {AgentId(names[i]) for i in byzantine_idx}
    phantom_ids = {AgentId(f"phantom-{i}") for i in byzantine_idx}

    async def _drive() -> None:
        for idx in honest_idx:
            aid = AgentId(names[idx])
            await h.registries[aid].register(
                AgentCard(agent_id=aid, name=f"H{idx}", capabilities=["sell"])
            )

        bad_entries = _byzantine_bad_entries(sorted(byzantine_idx), names, attacker_ident, h.idents)
        if bad_entries:
            payload = _push_payload(bad_entries)
            for aid in honest_ids:
                await h.registries[aid].handle_gossip(attacker_id, payload, h.contexts[aid])  # type: ignore[arg-type]

        await _run_full_rounds(h, honest_ids, _SWEEP_ROUNDS)

    asyncio.run(_drive())

    _assert_all_views_verify(h.registries, honest_ids)

    snapshots = [h.registries[aid].view_snapshot() for aid in honest_ids]
    reference = snapshots[0]
    for aid, snap in zip(honest_ids, snapshots, strict=True):
        assert snap == reference, f"honest sub-network diverged at f={f}, seed={seed} ({aid})"

    for idx in honest_idx:
        aid = AgentId(names[idx])
        assert aid in reference, (
            f"honest publisher {aid} missing from converged view at f={f}, seed={seed}"
        )

    for aid in honest_ids:
        snap = h.registries[aid].view_snapshot()
        assert not (byz_ids & snap.keys()), f"byzantine publisher leaked into {aid}'s view at f={f}"
        assert not (phantom_ids & snap.keys()), (
            f"forged phantom id leaked into {aid}'s view at f={f}"
        )
        equivocator_set = {pid for pid, _version in h.registries[aid].equivocations}
        assert byz_ids <= equivocator_set, (
            f"{aid} failed to catch every byzantine equivocator at f={f}: "
            f"expected {byz_ids} subset of {equivocator_set}"
        )


# ---------------------------------------------------------------------------
# Edge cases (overlay #3)
# ---------------------------------------------------------------------------


def test_edge_empty_view() -> None:
    """A freshly-constructed registry has an empty view and empty lookup."""
    h = _build_harness(["a", "b"], seed=1)
    reg = h.registries[AgentId("a")]
    assert reg.view_snapshot() == {}
    assert asyncio.run(reg.lookup(Query())) == []
    assert reg.rejections == []
    assert reg.equivocations == []


def test_edge_single_agent_no_peers() -> None:
    """A single-agent network: gossip_round is a no-op (no peers), register/lookup still work."""
    h = _build_harness(["solo"], seed=2)
    aid = AgentId("solo")
    reg = h.registries[aid]

    asyncio.run(reg.register(AgentCard(agent_id=aid, name="Solo", capabilities=["sell"])))
    asyncio.run(reg.gossip_round(h.contexts[aid]))  # type: ignore[arg-type]  # must not raise

    [card] = asyncio.run(reg.lookup(Query()))
    assert card.name == "Solo"
    assert reg.view_snapshot() == {aid: (1, aid, False)}


def test_edge_all_byzantine_but_one() -> None:
    """One honest agent surrounded by N-1 byzantine peers: no forged card lands, no crash.

    With only one honest agent there is no honest peer to converge WITH, so
    this checks the narrower but still load-bearing claim: the lone honest
    agent's own view stays internally consistent (self-registered card
    intact, every stored card re-verifies) despite every peer slot being
    byzantine and every gossip round therefore contacting only silent
    /adversarial peers.
    """
    n = 6
    names = [f"agent{i:02d}" for i in range(n)]
    byzantine_idx = set(range(1, n))  # agent00 is the lone honest agent
    h = _build_harness(names, seed=3)
    attacker_id = AgentId("lone-attacker")
    attacker_ident = DidKeyIdentity(attacker_id, seed=b"lone-attacker-seed")
    honest_id = AgentId("agent00")

    async def _drive() -> None:
        await h.registries[honest_id].register(
            AgentCard(agent_id=honest_id, name="Lone", capabilities=["sell"])
        )
        bad_entries = _byzantine_bad_entries(sorted(byzantine_idx), names, attacker_ident, h.idents)
        payload = _push_payload(bad_entries)
        await h.registries[honest_id].handle_gossip(attacker_id, payload, h.contexts[honest_id])  # type: ignore[arg-type]
        await _run_full_rounds(h, [honest_id], rounds=6)

    asyncio.run(_drive())

    _assert_all_views_verify(h.registries, [honest_id])
    snap = h.registries[honest_id].view_snapshot()
    assert snap.get(honest_id) == (1, honest_id, False)
    byz_ids = {AgentId(names[i]) for i in byzantine_idx}
    phantom_ids = {AgentId(f"phantom-{i}") for i in byzantine_idx}
    assert not (byz_ids & snap.keys())
    assert not (phantom_ids & snap.keys())


def test_edge_quarantine_then_honest_recovery() -> None:
    """A quarantined publisher's LATER genuinely-honest card is still rejected.

    This is a documented DESIGN LIMIT, not a bug: ``equivocations``
    /``_quarantined`` have no expiry or appeal mechanism (see the plugin's
    module docstring: "quarantine is permanent for the lifetime of this
    registry instance"). A publisher that equivocates once can never write
    to this registry instance again, even if every subsequent write is
    perfectly honest. This test pins that behavior explicitly rather than
    silently relying on ``test_equivocation_detected_and_quarantined``'s
    tail assertion in ``test_byzantine_gossip.py``.
    """
    h = _build_harness(["e", "v"], seed=4)
    e, v = AgentId("e"), AgentId("v")
    ident = h.idents[e]

    async def _drive() -> None:
        entry_1 = _signed_entry(ident, e, 1, "GOOD", ["sell"])
        entry_2 = _signed_entry(ident, e, 1, "EVIL", ["buy"])
        await h.registries[v].handle_gossip(e, _push_payload([entry_1, entry_2]), h.contexts[v])  # type: ignore[arg-type]

    asyncio.run(_drive())
    assert h.registries[v].equivocations == [(e, 1)]
    assert e not in h.registries[v].view_snapshot()

    # E now behaves perfectly honestly at a fresh version -- still refused.
    async def _recover() -> None:
        honest_again = _signed_entry(ident, e, 2, "RECOVERED", ["sell"])
        await h.registries[v].handle_gossip(e, _push_payload([honest_again]), h.contexts[v])  # type: ignore[arg-type]

    asyncio.run(_recover())

    assert e not in h.registries[v].view_snapshot()  # NOT recovered -- quarantine is permanent
    assert h.registries[v].rejections[-1] == (e, "quarantined")
    assert h.registries[v].equivocations == [(e, 1)]  # unchanged; not re-litigated


def test_edge_duplicate_registration() -> None:
    """Two ``register()`` calls for the same agent: LWW keeps the latest, no equivocation.

    ``register()`` allocates a fresh monotonic version every call (via
    ``GossipNetwork.next_version``) and applies locally via ``_apply``, never
    through the ``handle_gossip``/witness-map path -- a publisher's own
    successive writes to its own registry are trusted outright, exactly like
    ``GossipRegistry``. Two registrations are therefore never at the "same"
    version and can never trip the equivocation witness locally.
    """
    h = _build_harness(["a"], seed=5)
    aid = AgentId("a")
    reg = h.registries[aid]

    asyncio.run(reg.register(AgentCard(agent_id=aid, name="A", capabilities=["sell"])))
    asyncio.run(reg.register(AgentCard(agent_id=aid, name="A", capabilities=["buy"])))

    snap = reg.view_snapshot()
    assert snap[aid] == (2, aid, False)
    [card] = asyncio.run(reg.lookup(Query()))
    assert card.capabilities == ["buy"]  # second write won
    assert reg.equivocations == []


def test_edge_tombstone_vs_register_race() -> None:
    """Out-of-order delivery: a higher-version tombstone arriving BEFORE its own predecessor.

    Publisher ``a`` really did register (v1) then deregister (v2, tombstone).
    Gossip delivers v2 to ``v`` first, then v1 arrives late (redelivery,
    reordering, whatever). LWW must keep v2 (the tombstone) regardless of
    arrival order -- the stale v1 push must not "win" or resurrect the
    agent, and must not get treated as a conflicting write either since it's
    a strictly lower version, not the same one.
    """
    h = _build_harness(["a", "v"], seed=6)
    a, v = AgentId("a"), AgentId("v")
    ident = h.idents[a]

    v1 = _signed_entry(ident, a, 1, "A", ["sell"])
    v2 = _signed_entry(ident, a, 2, "A", ["sell"], tombstone=True)

    async def _drive() -> None:
        # Tombstone (v2) arrives FIRST.
        await h.registries[v].handle_gossip(a, _push_payload([v2]), h.contexts[v])  # type: ignore[arg-type]
        assert h.registries[v].view_snapshot()[a] == (2, a, True)

        # Stale register (v1) arrives SECOND -- must not resurrect a.
        await h.registries[v].handle_gossip(a, _push_payload([v1]), h.contexts[v])  # type: ignore[arg-type]

    asyncio.run(_drive())

    assert h.registries[v].view_snapshot()[a] == (2, a, True)  # tombstone still wins
    assert asyncio.run(h.registries[v].lookup(Query())) == []  # tombstoned -> absent from lookup
    assert h.registries[v].equivocations == []  # different versions, never a conflict
