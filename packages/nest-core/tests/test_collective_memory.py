import pytest
from nest_core.layers.collective_memory import CollectiveMemory


@pytest.mark.asyncio
async def test_read_write():
    mem = CollectiveMemory()
    assert await mem.read("agent_experience") is None

    await mem.write("agent_experience", b"success_route_alpha")
    assert await mem.read("agent_experience") == b"success_route_alpha"


@pytest.mark.asyncio
async def test_cas_success_and_failure():
    mem = CollectiveMemory()
    await mem.write("state", b"idle")

    # CAS should fail if expected doesn't match
    success = await mem.cas("state", b"busy", b"done")
    assert not success
    assert await mem.read("state") == b"idle"

    # CAS should succeed if expected matches
    success = await mem.cas("state", b"idle", b"running")
    assert success
    assert await mem.read("state") == b"running"
