import time
from typing import Optional, Any, List
from nest_sdk import Memory 

class DecayingMemory(Memory):
    def __init__(self, ttl_seconds: int = 60):
        self.storage: dict[str, tuple[Any, float]] = {}
        self.ttl = ttl_seconds

    async def put(self, key: str, value: Any) -> None:
        self.storage[key] = (value, time.time())

    async def get(self, key: str) -> Optional[Any]:
        if key not in self.storage:
            return None
        value, timestamp = self.storage[key]
        if time.time() - timestamp > self.ttl:
            del self.storage[key]
            return None
        return value

    async def delete(self, key: str) -> None:
        if key in self.storage:
            del self.storage[key]

    # Added these to make the interface "Complete" (No more red lines)
    async def clear(self) -> None:
        self.storage.clear()

    async def list_keys(self) -> List[str]:
        # Cleanup expired keys before listing
        current_keys = list(self.storage.keys())
        for k in current_keys:
            await self.get(k) 
        return list(self.storage.keys())