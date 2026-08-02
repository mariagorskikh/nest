#!/usr/bin/env python3
"""Provision mandates for agents missing from mandates.json.

Only provisions agents that don't have a real Prava mandate ID.
Merges new mandates with existing ones.

Usage:
    python scenarios/agent_heist/provision_missing.py
"""

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, "scenarios/agent_heist")
from provision import PRAVA_BASE_URL, PRAVA_SECRET_KEY, PravaProvisioner

# All agents that should have mandates
ALL_AGENTS = [
    {"id": "buyer-naive-0", "name": "Naive Agent Alpha", "type": "naive"},
    {"id": "buyer-naive-1", "name": "Naive Agent Beta", "type": "naive"},
    {"id": "buyer-naive-2", "name": "Naive Agent Gamma", "type": "naive"},
    {"id": "buyer-naive-3", "name": "Naive Agent Delta", "type": "naive"},
    {"id": "buyer-defended-0", "name": "Defended Agent Alpha", "type": "defended"},
    {"id": "buyer-defended-1", "name": "Defended Agent Beta", "type": "defended"},
    {"id": "buyer-defended-2", "name": "Defended Agent Gamma", "type": "defended"},
    {"id": "buyer-defended-3", "name": "Defended Agent Delta", "type": "defended"},
]

MANDATES_FILE = Path(__file__).parent / "mandates.json"


def is_real_mandate_id(mandate_id: str) -> bool:
    """Check if a mandate ID is a real Prava ID (not a placeholder)."""
    # Real Prava mandate IDs start with mdt_01 or similar patterns
    # Placeholder IDs contain patterns like "NAIVE", "DEFENDED", "MANDATE"
    if not mandate_id:
        return False
    if "NAIVE" in mandate_id.upper() or "DEFENDED" in mandate_id.upper():
        return False
    if "MANDATE" in mandate_id.upper() and "0000" in mandate_id:
        return False
    return mandate_id.startswith("mdt_")


def load_existing_mandates() -> dict[str, dict]:
    """Load existing mandates and return dict by agent_id."""
    if not MANDATES_FILE.exists():
        return {}

    data = json.loads(MANDATES_FILE.read_text())
    return {m["agent_id"]: m for m in data.get("mandates", [])}


def find_missing_agents(existing: dict[str, dict]) -> list[dict]:
    """Find agents that need new mandates."""
    missing = []
    for agent in ALL_AGENTS:
        agent_id = agent["id"]
        if agent_id not in existing or not is_real_mandate_id(
            existing[agent_id].get("mandate_id", "")
        ):
            missing.append(agent)
    return missing


async def main():
    existing = load_existing_mandates()
    missing = find_missing_agents(existing)

    if not missing:
        print("All agents already have valid mandate IDs!")
        return

    print(f"Found {len(missing)} agents needing mandates:")
    for agent in missing:
        print(f"  - {agent['id']} ({agent['name']})")
    print()

    if not PRAVA_SECRET_KEY:
        print("Error: PRAVA_SECRET_KEY not set")
        sys.exit(1)

    p = PravaProvisioner(PRAVA_BASE_URL, PRAVA_SECRET_KEY)

    new_mandates = []
    for agent in missing:
        print(f"\n{'=' * 60}")
        print(f"Provisioning: {agent['name']} ({agent['id']})")
        print(f"{'=' * 60}")

        session = await p.create_session(agent)
        if session:
            mandate_id = await p.wait_for_approval(agent, session)
            if mandate_id:
                new_mandates.append(
                    {
                        "agent_id": agent["id"],
                        "agent_name": agent["name"],
                        "agent_type": agent["type"],
                        "mandate_id": mandate_id,
                        "approved_amount": "100.00",
                        "status": "active",
                    }
                )
                print(f"✓ Mandate created: {mandate_id}")
            else:
                print(f"✗ Failed to get mandate for {agent['id']}")
        else:
            print(f"✗ Failed to create session for {agent['id']}")

    await p.close()

    # Merge with existing mandates
    if new_mandates:
        for m in new_mandates:
            existing[m["agent_id"]] = m

        # Save merged mandates
        output = {
            "scenario": "agent_heist",
            "version": "1.0",
            "created_at": existing.get("buyer-naive-0", {}).get("created_at", ""),
            "mandates": list(existing.values()),
        }
        MANDATES_FILE.write_text(json.dumps(output, indent=2))
        print(f"\n✓ Saved {len(existing)} mandates to {MANDATES_FILE}")


if __name__ == "__main__":
    asyncio.run(main())
