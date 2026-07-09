#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate JSONL trace fixtures for the nest-dashboard visualizer."""

from __future__ import annotations
import asyncio
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS_DIR = ROOT / "scenarios"
OUT_DIR = ROOT / "apps" / "nest-dashboard" / "public" / "scenario-traces"
NEW_SCENARIOS = (
    "memory_concurrent_writers",
    "escrow_marketplace",
    "streaming_payments",
    "sealed_bid_with_privacy",
    "bft_consensus_partition",
    "bft_consensus_byzantine",
    "multi_attribute_market",
    "provenance_supply_chain",
    "gossip_registry",
    "comms_versioning",
    "identity_rotation",
    "receipt_reputation",
    "http_marketplace",
)


async def _run_one(name: str, out_path: Path) -> None:
    from nest_core.runner import ScenarioRunner
    from nest_core.scenario import ScenarioConfig

    yaml_path = SCENARIOS_DIR / f"{name}.yaml"
    if not yaml_path.exists():
        print(f"skip missing scenario: {yaml_path}", file=sys.stderr)
        return
    data = ScenarioConfig.from_yaml(yaml_path).model_dump()
    data["duration"] = "ticks: 500"
    data.setdefault("output", {})["trace"] = str(out_path)
    config = ScenarioConfig.from_dict(data)
    runner = ScenarioRunner(config)
    await runner.run()
    print(f"wrote {out_path}")


async def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    fallback = OUT_DIR / "marketplace.jsonl"
    for name in NEW_SCENARIOS:
        out_path = OUT_DIR / f"{name}.jsonl"
        if out_path.exists() and out_path.stat().st_size > 0:
            continue
        try:
            await _run_one(name, out_path)
        except Exception as exc:  # noqa: BLE001
            print(f"failed {name}: {exc}", file=sys.stderr)
            if fallback.exists():
                shutil.copy2(fallback, out_path)
                print(f"copied fallback -> {out_path}")


if __name__ == "__main__":
    asyncio.run(main())
