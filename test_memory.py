import asyncio
import time
from my_decaying_memory import DecayingMemory

async def test_forgetting():
    # Set TTL to 2 seconds for a quick test
    mem = DecayingMemory(ttl_seconds=2)
    print("--- Starting Test ---")
    
    await mem.put("kumbh_status", "crowded")
    val = await mem.get("kumbh_status")
    print(f"Immediate check: {val}") # Should be 'crowded'
    
    print("Waiting 3 seconds for memory to decay...")
    await asyncio.sleep(3)
    
    val = await mem.get("kumbh_status")
    print(f"After 3s check: {val}") # Should be None (forgotten!)
    print("--- Test Passed ---")

if __name__ == "__main__":
    asyncio.run(test_forgetting())