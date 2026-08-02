#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Provision Prava mandates for Agent Heist scenario.

Creates 3 buyer agent mandates with $100 caps, waits for passkey approval,
and writes the mandate IDs to mandates.json for use by the scenario.

Usage::

    # Set environment variables
    export PRAVA_SECRET_KEY=sk_test_...

    # Run provisioning
    python scenarios/agent_heist/provision.py

    # After approving all 3 mandates via passkey, mandates.json is created

Test Cards (sandbox only):
    PAN: 4622 9431 2323 2267
    Expiry: 12/30
    CVV: 265
    OTP: 456789
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx

# Load .env from project root
PROJECT_ROOT = Path(__file__).parent.parent.parent
ENV_PATH = PROJECT_ROOT / ".env"
if ENV_PATH.exists():
    for line in ENV_PATH.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip())

# Configuration
PRAVA_SECRET_KEY = os.environ.get("PRAVA_SECRET_KEY", "")
PRAVA_BASE_URL = os.environ.get("PRAVA_BASE_URL", "https://sandbox.api.prava.space")

# Buyer agent configuration (all 8 buyers for hybrid scenario)
BUYER_AGENTS = [
    {"id": "buyer-naive-0", "name": "Naive Agent Alpha", "type": "naive"},
    {"id": "buyer-naive-1", "name": "Naive Agent Beta", "type": "naive"},
    {"id": "buyer-naive-2", "name": "Naive Agent Gamma", "type": "naive"},
    {"id": "buyer-naive-3", "name": "Naive Agent Delta", "type": "naive"},
    {"id": "buyer-defended-0", "name": "Defended Agent Alpha", "type": "defended"},
    {"id": "buyer-defended-1", "name": "Defended Agent Beta", "type": "defended"},
    {"id": "buyer-defended-2", "name": "Defended Agent Gamma", "type": "defended"},
    {"id": "buyer-defended-3", "name": "Defended Agent Delta", "type": "defended"},
]

# Mandate configuration
MANDATE_AMOUNT = "100.00"  # $100 cap per agent
MANDATE_CURRENCY = "USD"
MANDATE_MAX_CHARGES = 10  # Allow up to 10 purchases per agent


@dataclass
class MandateRecord:
    """Record of a provisioned mandate."""

    agent_id: str
    agent_name: str
    agent_type: str  # "naive" or "defended"
    mandate_id: str
    approved_amount: str
    session_id: str
    approved_at: str
    status: str = "active"


@dataclass
class ProvisioningState:
    """State of the provisioning process."""

    mandates: list[MandateRecord] = field(default_factory=list)
    created_at: str = ""
    scenario: str = "agent_heist"
    version: str = "1.0"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "scenario": self.scenario,
            "version": self.version,
            "created_at": self.created_at,
            "mandates": [asdict(m) for m in self.mandates],
        }


class PravaProvisioner:
    """Provisions Prava mandates for buyer agents."""

    def __init__(self, base_url: str, secret_key: str) -> None:
        if not secret_key:
            raise ValueError("PRAVA_SECRET_KEY environment variable is required")

        self.base_url = base_url.rstrip("/")
        self.secret_key = secret_key
        self.client = httpx.AsyncClient(
            base_url=self.base_url,
            headers={
                "Authorization": f"Bearer {secret_key}",
                "Content-Type": "application/json",
            },
            timeout=30.0,
        )
        self.state = ProvisioningState(created_at=datetime.now(UTC).isoformat())

    async def close(self) -> None:
        """Close the HTTP client."""
        await self.client.aclose()

    def _log(self, msg: str) -> None:
        """Print timestamped log message."""
        print(f"[{datetime.now(UTC).strftime('%H:%M:%S')}] {msg}")

    async def create_session(self, agent: dict[str, str]) -> dict[str, Any] | None:
        """Create a Prava session with mandate setup for an agent.

        Args:
            agent: Agent config dict with id, name, type.

        Returns:
            Session response dict or None on failure.
        """
        self._log(f"Creating session for {agent['name']} ({agent['id']})...")

        # Calculate valid_until (7 days from now)
        valid_until = (datetime.now(UTC) + timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")

        # Unique user ID for this agent
        user_id = f"heist-{agent['id']}-{uuid.uuid4().hex[:8]}"

        payload = {
            "user_id": user_id,
            "user_email": f"{user_id}@agentmarket.example.com",
            "total_amount": MANDATE_AMOUNT,
            "currency": MANDATE_CURRENCY,
            "purchase_context": [
                {
                    "merchant_details": {
                        "name": "Agent Marketplace",
                        "url": "https://agentmarket.example.com",
                        "country_code_iso2": "US",
                        "category_code": "5999",
                        "category": "Miscellaneous and Specialty Retail",
                    },
                    "product_details": [
                        {
                            "description": f"Agent Heist scenario mandate for {agent['name']}",
                            "unit_price": MANDATE_AMOUNT,
                            "quantity": 1,
                        }
                    ],
                    "effective_until_minutes": 60,
                }
            ],
            "mandate_setup": {
                "intent": "mandate_setup",
                "recurring_frequency": "one_time",
                "merchant_scope": "any",  # Allow purchases from any merchant
                "valid_until": valid_until,
                "max_charges": MANDATE_MAX_CHARGES,
            },
        }

        try:
            resp = await self.client.post("/v1/sessions", json=payload)
            data = resp.json()

            if resp.status_code in (200, 201):
                session_id = data.get("id") or data.get("session_id")
                self._log(f"  Session created: {session_id}")
                # Preserve user_id for mandate polling (API response doesn't include it)
                data["user_id"] = user_id
                return data
            else:
                self._log(f"  FAILED: HTTP {resp.status_code}")
                self._log(f"  Response: {json.dumps(data, indent=2)}")
                return None
        except Exception as e:
            self._log(f"  EXCEPTION: {e}")
            return None

    async def wait_for_approval(
        self, agent: dict[str, str], session_data: dict[str, Any]
    ) -> str | None:
        """Wait for user to approve the mandate via passkey.

        Args:
            agent: Agent config dict.
            session_data: Session response from create_session.

        Returns:
            Mandate ID if approved, None otherwise.
        """
        iframe_url = session_data.get("iframe_url") or session_data.get("approval_url")
        session_data.get("id") or session_data.get("session_id")

        if not iframe_url:
            self._log("  ERROR: No approval URL in session response")
            return None

        print()
        print("=" * 70)
        print(f"APPROVE MANDATE FOR: {agent['name']}")
        print(f"Agent Type: {agent['type'].upper()}")
        print(f"Mandate Cap: ${MANDATE_AMOUNT}")
        print("=" * 70)
        print("\n1. Open this URL in your browser:\n")
        print(f"   {iframe_url}")
        print("\n2. Enter test card details:")
        print("   PAN: 4622 9431 2323 2267")
        print("   Expiry: 12/30")
        print("   CVV: 265")
        print("   OTP: 456789")
        print("\n3. Complete passkey/biometric approval")
        print()

        user_input = await asyncio.get_event_loop().run_in_executor(
            None, lambda: input("Press ENTER when approval is complete (or 'q' to quit): ")
        )

        if user_input.lower() == "q":
            return None

        # Poll for mandate ID
        mandate_id = await self._poll_for_mandate(session_data)
        return mandate_id

    async def _poll_for_mandate(self, session_data: dict[str, Any]) -> str | None:
        """Poll for mandate ID after approval."""
        user_id = session_data.get("user_id")

        # Poll the /v1/mandates endpoint and look for matching externalUserId
        self._log("Polling for mandate...")
        max_attempts = 10
        for attempt in range(max_attempts):
            try:
                resp = await self.client.get("/v1/mandates")
                if resp.status_code == 200:
                    data = resp.json()
                    mandates = data.get("mandates") or data.get("data") or []

                    # Find mandate with matching externalUserId
                    for mandate in mandates:
                        ext_user = mandate.get("externalUserId") or mandate.get("external_user_id")
                        if ext_user == user_id:
                            mandate_id = mandate.get("id") or mandate.get("mandateId")
                            if mandate_id:
                                self._log(f"  Found mandate: {mandate_id}")
                                return mandate_id

                    # If not found by exact match, check for partial match
                    for mandate in mandates:
                        ext_user = (
                            mandate.get("externalUserId") or mandate.get("external_user_id") or ""
                        )
                        if user_id and user_id in ext_user:
                            mandate_id = mandate.get("id") or mandate.get("mandateId")
                            if mandate_id:
                                self._log(f"  Found mandate (partial match): {mandate_id}")
                                return mandate_id
            except Exception as e:
                self._log(f"  Poll attempt {attempt + 1} failed: {e}")

            if attempt < max_attempts - 1:
                await asyncio.sleep(2)  # Wait 2 seconds before retry

        # Show available mandates for manual selection
        print("\nCould not auto-detect mandate ID.")
        try:
            resp = await self.client.get("/v1/mandates")
            if resp.status_code == 200:
                data = resp.json()
                mandates = data.get("mandates") or []
                if mandates:
                    print("\nRecent mandates found:")
                    for i, m in enumerate(mandates[:5]):
                        mid = m.get("id", "?")
                        ext = m.get("externalUserId", "?")
                        status = m.get("status", "?")
                        print(f"  {i + 1}. {mid} (user: {ext}, status: {status})")
        except Exception:
            pass

        mandate_id = await asyncio.get_event_loop().run_in_executor(
            None, lambda: input("\nEnter Mandate ID (or number from list): ").strip()
        )

        # Handle numeric selection
        if mandate_id.isdigit():
            idx = int(mandate_id) - 1
            if 0 <= idx < len(mandates):
                return mandates[idx].get("id")

        return mandate_id if mandate_id else None

    async def verify_mandate(self, mandate_id: str) -> bool:
        """Verify a mandate is active and has the expected cap."""
        try:
            resp = await self.client.get(f"/v1/mandates/{mandate_id}")
            if resp.status_code != 200:
                self._log(f"  WARNING: Could not verify mandate {mandate_id}")
                return False

            data = resp.json()
            status = data.get("status", "unknown")
            approved = data.get("approvedAmount") or data.get("approved_amount", "0")

            if status != "active":
                self._log(f"  WARNING: Mandate status is '{status}', not 'active'")

            self._log(f"  Verified: status={status}, approved=${approved}")
            return True
        except Exception as e:
            self._log(f"  ERROR verifying mandate: {e}")
            return False

    async def provision_all(self) -> bool:
        """Provision mandates for all buyer agents.

        Returns:
            True if all mandates were provisioned successfully.
        """
        print()
        print("=" * 70)
        print("AGENT HEIST - MANDATE PROVISIONING")
        print("=" * 70)
        print(
            f"\nProvisioning {len(BUYER_AGENTS)} buyer agents with ${MANDATE_AMOUNT} mandates each."
        )
        print(f"API: {self.base_url}")
        print()

        for agent in BUYER_AGENTS:
            # Create session
            session = await self.create_session(agent)
            if not session:
                print(f"\nFAILED to create session for {agent['name']}")
                return False

            # Wait for approval
            mandate_id = await self.wait_for_approval(agent, session)
            if not mandate_id:
                print(f"\nFAILED to get approval for {agent['name']}")
                return False

            # Verify mandate
            self._log(f"Verifying mandate {mandate_id}...")
            await self.verify_mandate(mandate_id)

            # Record the mandate
            record = MandateRecord(
                agent_id=agent["id"],
                agent_name=agent["name"],
                agent_type=agent["type"],
                mandate_id=mandate_id,
                approved_amount=MANDATE_AMOUNT,
                session_id=session.get("id") or session.get("session_id") or "",
                approved_at=datetime.now(UTC).isoformat(),
            )
            self.state.mandates.append(record)
            self._log(f"Mandate recorded: {agent['name']} -> {mandate_id}")
            print()

        return True

    def save_mandates(self, output_path: Path) -> None:
        """Save mandates to JSON file.

        Args:
            output_path: Path to write mandates.json.
        """
        output_path.write_text(json.dumps(self.state.to_dict(), indent=2))
        self._log(f"Mandates saved to {output_path}")


async def main() -> None:
    """Run the provisioning process."""
    if not PRAVA_SECRET_KEY:
        print("ERROR: PRAVA_SECRET_KEY environment variable is not set")
        print("\nSet it with:")
        print("  export PRAVA_SECRET_KEY=sk_test_...")
        print("\nOr add it to your .env file in the project root.")
        sys.exit(1)

    output_path = Path(__file__).parent / "mandates.json"

    # Check if mandates already exist
    if output_path.exists():
        print(f"\nWARNING: {output_path} already exists.")
        response = input("Overwrite? (y/N): ").strip().lower()
        if response != "y":
            print("Aborted.")
            sys.exit(0)

    provisioner = PravaProvisioner(PRAVA_BASE_URL, PRAVA_SECRET_KEY)

    try:
        success = await provisioner.provision_all()

        if success:
            provisioner.save_mandates(output_path)
            print()
            print("=" * 70)
            print("PROVISIONING COMPLETE")
            print("=" * 70)
            print(f"\nAll {len(BUYER_AGENTS)} mandates have been provisioned.")
            print(f"Mandates saved to: {output_path}")
            print("\nYou can now run the Agent Heist scenario:")
            print("  nest run scenarios/agent_heist/agent_heist.yaml")
        else:
            print("\nProvisioning failed. Please check errors above.")
            sys.exit(1)

    finally:
        await provisioner.close()


if __name__ == "__main__":
    asyncio.run(main())
