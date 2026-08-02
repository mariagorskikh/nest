# SPDX-License-Identifier: Apache-2.0
"""Conservation, checked over many randomized scenarios rather than a handful by hand.

`test_conservation.py` and `test_group_payment.py` pin specific, named
scenarios — a decline here, a backstop there — each chosen because it
exercises one invariant deliberately. What they cannot do is tell you
whether some *other* combination of principal count, weights, policy,
tolerance and approve/decline order breaks something nobody thought to
write by hand.

This file is that check, built without a new dependency: `hypothesis` would
be the standard tool, but the brief for this package is explicit about
staying dependency-light, and the property itself is simple enough that the
stdlib's own `random`, seeded per case via `pytest.mark.parametrize`, does
the job — each seed is an independent, individually-reportable test case
rather than one loop that swallows which draw failed.

Every case drives a real `pay_group()` through the real `_simulator.py`
engine, resolves every principal (approve or decline, in a randomised
order) until the group reaches some terminal state, and then checks the
same five `conservation_report()` invariants regardless of how that
particular draw turned out — committed, partial, or aborted.
"""

from __future__ import annotations

import random

import pytest
from nanda_town_prava import PravaMandates, Principal
from nanda_town_prava._simulator import SimulatedEngine
from nest_sdk import AgentId, Money, PaymentRef

# "organizer" is deliberately eligible to be drawn as a principal, not just
# the calling agent's id — otherwise every draw would exercise
# `agent_reserved == 0` (fronts nothing) and never touch this handle's own
# headroom bookkeeping at all.
NAMES = ["organizer", "Soham", "Arsh", "Dev", "Maya", "Priya", "Kabir", "Ishaan", "Neel"]


def _random_scenario(
    rng: random.Random,
) -> tuple[list[Principal], dict[str, object], int, int]:
    n = rng.randint(2, 6)
    names = rng.sample(NAMES, n)
    has_backstop = n >= 2 and rng.random() < 0.3

    principals: list[Principal] = []
    for i, name in enumerate(names):
        if has_backstop and i == n - 1:
            principals.append(
                Principal(name=name, role="backstop", backstop_cap=rng.randint(50, 500))
            )
        else:
            principals.append(Principal(name=name, weight=rng.randint(1, 3)))

    paying = [p for p in principals if p.role != "backstop"]
    kind = rng.choice(["all_of", "quorum", "weighted"])
    policy: dict[str, object]
    if kind == "all_of":
        policy = {"type": "all_of"}
    elif kind == "quorum":
        policy = {"type": "quorum", "m": rng.randint(1, len(paying))}
    else:
        policy = {"type": "weighted", "threshold": rng.randint(1, sum(p.weight for p in paying))}

    tolerance_bps = rng.choice([0, 100, 500, 1000, 5000])
    total = rng.randint(len(paying) * 10, len(paying) * 500)
    return principals, policy, tolerance_bps, total


async def _resolve_randomly(
    engine: SimulatedEngine, group_id: str, member_ids: list[str], rng: random.Random
) -> None:
    """Approve or decline every member, in a shuffled order, until terminal."""
    order = list(member_ids)
    rng.shuffle(order)
    resolved = frozenset({"charged", "declined", "dropped", "expired", "failed"})
    for member_id in order:
        view = await engine.get_group(group_id)
        if view["status"] in ("committed", "partial", "aborted", "expired"):
            return
        status = next((m["status"] for m in view["members"] if m["member_id"] == member_id), None)
        if status in resolved:
            continue
        if rng.random() < 0.8:
            await engine.approve_member(member_id)
        else:
            await engine.decline_member(member_id)


@pytest.mark.parametrize("seed", range(60))
async def test_conservation_holds_over_randomized_group_scenarios(seed: int) -> None:
    rng = random.Random(seed)
    engine = SimulatedEngine()
    payments = PravaMandates(
        AgentId("organizer"),
        initial_balance=10**9,
        engine=engine,
        auto_approve=False,
        await_seconds=0.0,
    )
    principals, policy, tolerance_bps, total = _random_scenario(rng)
    ref = PaymentRef(f"g-{seed}")

    await payments.pay_group(
        AgentId("merchant-0"),
        Money(amount=total),
        ref,
        principals=principals,
        policy=policy,
        tolerance_bps=tolerance_bps,
    )
    auth = payments.authorization(ref)
    assert auth is not None

    await _resolve_randomly(engine, auth.group_id, list(auth.member_ids), rng)
    await payments.verify_payment(ref)

    report = payments.conservation_report()
    assert report["authorization_conserved"], (seed, report)
    assert report["no_pooled_funds"], (seed, report)
    assert report["settlement_conserved"], (seed, report)
    assert report["headroom_consistent"], (seed, report)
    assert report["no_agent_overspent_its_cap"], (seed, report)

    # Two checks `conservation_report()` does not already make explicit:
    # nothing captured exceeds what was reserved, and the group's status is
    # always one this plugin recognises (`_GROUP_STATUS_KNOWN` in plugin.py)
    # — a randomised policy draw is exactly the kind of input that would
    # surface an unrecognised state if one existed.
    assert auth.captured <= auth.reserved, (seed, auth)
    assert not auth.unknown_states, (seed, auth.unknown_states)
