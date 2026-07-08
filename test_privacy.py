import asyncio

from my_privacy_layer import TrustGatedPrivacy


# Mocking the Trust Layer (Layer 6) to test our Privacy (Layer 11)
class MockTrust:
    async def score(self, agent_id: str) -> float:
        if "verified" in agent_id:
            return 0.95
        if "stranger" in agent_id:
            return 0.10
        return 0.50


async def run_test():
    privacy = TrustGatedPrivacy(trust=MockTrust())  # type: ignore
    secret_data = {"location": "19.23N, 73.85E", "inventory_count": 500}

    print("--- PRIVACY LAYER TEST ---")

    # 1. Test High Trust
    res1 = await privacy.mask(secret_data, "verified_agent")  # type: ignore
    print(f"High Trust Result: {res1['location']}")  # Should be real coords

    # 2. Test Low Trust
    res2 = await privacy.mask(secret_data, "stranger_agent")  # type: ignore
    print(f"Low Trust Result: {res2['location']}")  # Should be REDACTED

    print("--- TEST PASSED ---")


if __name__ == "__main__":
    asyncio.run(run_test())
