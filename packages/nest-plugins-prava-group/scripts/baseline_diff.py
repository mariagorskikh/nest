# SPDX-License-Identifier: Apache-2.0
"""Run the same scenario on both payment layers and diff what actually moved.

``nest run`` proves the two plugins are interchangeable. It does not prove
they are *different*, because the difference is invisible in a Nanda Town
trace: the trace carries four event kinds (``start``, ``send``, ``receive``,
``stop``) and no plugin can write to it — ``AgentContext`` holds the
``TraceWriter`` privately and hands plugins only ``ctx.plugins``.

So this runs the marketplace scenario twice, in process, through
``ScenarioRunner``, and afterwards reads the ledger each plugin was left
holding. Same YAML, same seed, same agents, same messages — one line of
config apart.

    python scripts/baseline_diff.py

Numbers reported, all from live plugin state rather than adjectives:

* how much value moved between agents inside the simulator
* how many agents ended richer than they started
* how much value left a card and reached a merchant outside the simulator

The upstream trace validators are run over both traces as well. They are
identical because the traces are identical; that is the drop-in claim, and
it is checked rather than asserted.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nanda_town_prava import PravaMandates, reset_shared_state  # noqa: E402
from nest_core.runner import ScenarioRunner  # noqa: E402
from nest_core.scenario import ScenarioConfig  # noqa: E402
from nest_core.types import AgentId  # noqa: E402
from nest_core.validators import validate_trace  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
INITIAL = 1000  # nest_core.scenarios_builtin.marketplace._instantiate_plugins


def rule(title: str) -> None:
    print(f"\n=== {title} " + "=" * max(0, 62 - len(title)))


async def run(scenario: Path) -> tuple[Any, Path]:
    """Run one scenario and hand back its live payments plugin + trace path."""
    reset_shared_state()
    config = ScenarioConfig.from_yaml(str(scenario))
    runner = ScenarioRunner(config)
    trace = await runner.run()
    return runner.resolved_plugins["payments"], trace


def ledger(payments: Any) -> dict[str, Any]:
    """What this plugin was left holding, read through its public surface."""
    agents = [AgentId(f"seller-{i}") for i in range(50)]
    agents += [AgentId(f"buyer-{i}") for i in range(50)]
    finals = {str(a): payments.balance(a) for a in agents}

    credited = {a: b - INITIAL for a, b in finals.items() if b > INITIAL}
    debited = {a: INITIAL - b for a, b in finals.items() if b < INITIAL}
    out: dict[str, Any] = {
        "plugin": type(payments).__name__,
        "agents": len(finals),
        "starting_total_in_simulator": INITIAL * len(finals),
        "final_total_in_simulator": sum(finals.values()),
        "agents_ending_richer_than_they_started": len(credited),
        "value_credited_to_agents": sum(credited.values()),
        "value_debited_from_agents": sum(debited.values()),
        # `_payments` is the receipt map the scenario factory hands both
        # plugins. Private upstream, read here only to count.
        "receipts": len(getattr(payments, "_payments", getattr(payments, "_receipts", {}))),
    }
    if isinstance(payments, PravaMandates):
        report = payments.conservation_report()
        out["value_that_left_a_card"] = report["captured"]
        out["value_that_reached_a_merchant"] = report["merchant_credited"]
        out["merchants_paid"] = len(report["merchants"])
        out["authorization_still_on_hold"] = report["outstanding"]
        out["conservation_report"] = report
    else:
        out["value_that_left_a_card"] = 0
        out["value_that_reached_a_merchant"] = 0
        out["merchants_paid"] = 0
    return out


def validators(trace: Path) -> list[tuple[bool, str, str]]:
    return [(r.passed, r.name, r.detail) for r in validate_trace(trace, "marketplace")]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


async def main() -> int:
    os.chdir(ROOT)
    baseline_yaml = ROOT / "baseline.yaml"
    bench_yaml = ROOT / "bench.yaml"
    if not baseline_yaml.exists():
        print("run `nest scenarios cp marketplace ./baseline.yaml` first")
        return 1

    rule("the only difference between the two scenarios")
    a = [ln for ln in baseline_yaml.read_text().splitlines() if ln.strip()]
    b = [
        ln
        for ln in bench_yaml.read_text().splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ]
    only_a = [ln for ln in a if ln not in b]
    only_b = [ln for ln in b if ln not in a]
    for ln in only_a:
        print(f"  - {ln}")
    for ln in only_b:
        print(f"  + {ln}")

    rule("prepaid_credits — the built-in pooled ledger")
    base_payments, base_trace = await run(baseline_yaml)
    base = ledger(base_payments)
    print(json.dumps({k: v for k, v in base.items() if k != "conservation_report"}, indent=2))

    rule("prava_mandates — real card mandates")
    prava_payments, prava_trace = await run(bench_yaml)
    prava = ledger(prava_payments)
    print(json.dumps({k: v for k, v in prava.items() if k != "conservation_report"}, indent=2))
    print("\n  conservation_report():")
    summary = dict(prava["conservation_report"])
    merchants = summary.pop("merchants")
    summary["merchants"] = f"<{len(merchants)} merchants, {sum(merchants.values())} total>"
    print("  " + json.dumps(summary, indent=2).replace("\n", "\n  "))
    top = sorted(merchants.items(), key=lambda kv: -kv[1])[:3]
    print(f"  largest merchant credits: {top}")

    rule("the traces")
    print(
        f"  {base_trace}: {len(base_trace.read_bytes())} bytes, "
        f"{len(base_trace.read_text().splitlines())} events"
    )
    print(
        f"  {prava_trace}: {len(prava_trace.read_bytes())} bytes, "
        f"{len(prava_trace.read_text().splitlines())} events"
    )
    print(f"  sha256 baseline: {sha256(base_trace)}")
    print(f"  sha256 prava   : {sha256(prava_trace)}")
    identical = sha256(base_trace) == sha256(prava_trace)
    print(f"  byte-identical : {identical}")

    rule("upstream validators, over both traces")
    base_v = validators(base_trace)
    prava_v = validators(prava_trace)
    for (ok_a, name, detail_a), (ok_b, _, detail_b) in zip(base_v, prava_v, strict=True):
        print(f"  {name}")
        print(f"    prepaid_credits: {'PASS' if ok_a else 'FAIL'} — {detail_a}")
        print(f"    prava_mandates : {'PASS' if ok_b else 'FAIL'} — {detail_b}")
    same = base_v == prava_v
    print(f"\n  identical results: {same}")
    print(f"  all pass         : {all(p for p, _, _ in base_v + prava_v)}")

    rule("what actually changed")
    rows = [
        (
            "value moved between agents in the simulator",
            base["value_credited_to_agents"],
            prava["value_credited_to_agents"],
        ),
        (
            "agents ending richer than they started",
            base["agents_ending_richer_than_they_started"],
            prava["agents_ending_richer_than_they_started"],
        ),
        (
            "value debited from agents",
            base["value_debited_from_agents"],
            prava["value_debited_from_agents"],
        ),
        (
            "credits still pooled inside the simulator",
            base["final_total_in_simulator"],
            prava["final_total_in_simulator"],
        ),
        (
            "value that left a real card",
            base["value_that_left_a_card"],
            prava["value_that_left_a_card"],
        ),
        (
            "value that reached a merchant outside",
            base["value_that_reached_a_merchant"],
            prava["value_that_reached_a_merchant"],
        ),
        ("distinct merchants paid", base["merchants_paid"], prava["merchants_paid"]),
        ("payments executed", base["receipts"], prava["receipts"]),
    ]
    width = max(len(r[0]) for r in rows)
    print(f"  {'':<{width}}  {'prepaid_credits':>16}  {'prava_mandates':>15}")
    for label, x, y in rows:
        print(f"  {label:<{width}}  {x:>16}  {y:>15}")

    rule("assertions")
    failures: list[str] = []

    def assert_(label: str, ok: bool, detail: str = "") -> None:
        print(f"  [{'PASS' if ok else 'FAIL'}] {label}{(' — ' + detail) if detail else ''}")
        if not ok:
            failures.append(label)

    assert_("both traces are byte-identical", identical)
    assert_(
        "both traces pass the same upstream validators identically",
        same and all(p for p, _, _ in base_v),
    )
    assert_(
        "prepaid_credits conserves value INSIDE the simulator",
        base["final_total_in_simulator"] == base["starting_total_in_simulator"],
        f"{base['final_total_in_simulator']} == {base['starting_total_in_simulator']}",
    )
    assert_(
        "prepaid_credits moved value between agents",
        base["value_credited_to_agents"] > 0,
        str(base["value_credited_to_agents"]),
    )
    assert_(
        "prava_mandates credited NO agent from another agent's payment",
        prava["agents_ending_richer_than_they_started"] == 0,
        str(prava["agents_ending_richer_than_they_started"]),
    )
    assert_(
        "prava_mandates moved every unit out of the simulator",
        prava["value_that_reached_a_merchant"] == prava["value_debited_from_agents"],
        f"{prava['value_that_reached_a_merchant']} == {prava['value_debited_from_agents']}",
    )
    assert_(
        "prepaid_credits moved nothing to any merchant", base["value_that_reached_a_merchant"] == 0
    )
    assert_(
        "prava_mandates leaves no authorization on hold",
        prava["conservation_report"]["outstanding"] == 0,
    )
    assert_(
        "prava_mandates: authorization_conserved",
        prava["conservation_report"]["authorization_conserved"],
    )
    assert_("prava_mandates: no_pooled_funds", prava["conservation_report"]["no_pooled_funds"])
    assert_(
        "prava_mandates: settlement_conserved", prava["conservation_report"]["settlement_conserved"]
    )
    assert_(
        "prava_mandates: headroom_consistent", prava["conservation_report"]["headroom_consistent"]
    )

    print()
    if failures:
        print(f"{len(failures)} FAILED: {failures}")
        return 1
    print("all assertions hold")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
