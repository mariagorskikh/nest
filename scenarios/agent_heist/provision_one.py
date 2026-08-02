#!/usr/bin/env python3
"""Provision a single mandate for buyer-defended-0."""

import asyncio
import sys

sys.path.insert(0, "scenarios/agent_heist")
from provision import PRAVA_BASE_URL, PRAVA_SECRET_KEY, PravaProvisioner


async def main():
    p = PravaProvisioner(PRAVA_BASE_URL, PRAVA_SECRET_KEY)
    agent = {"id": "buyer-defended-0", "name": "Defended Agent Gamma", "type": "defended"}
    session = await p.create_session(agent)
    if session:
        mandate_id = await p.wait_for_approval(agent, session)
        if mandate_id:
            print(f"\nMandate ID: {mandate_id}")
            print("Add this to your mandates.json")
    await p.close()


asyncio.run(main())
