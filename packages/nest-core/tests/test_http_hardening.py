# SPDX-License-Identifier: Apache-2.0
"""Tests for HTTP config hardening and JwtAuth virtual clock."""

from __future__ import annotations

import pytest
from nest_core.scenario import ScenarioConfig
from nest_core.sim.http_config import (
    http_auth_headers,
    http_auth_valid,
    http_shared_secret,
    require_http_shared_secret,
)
from nest_core.types import AgentId
from nest_plugins_reference.auth.jwt_auth import JwtAuth


class TestHttpAuthConfig:
    def test_auth_disabled_by_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("NEST_HTTP_SHARED_SECRET", raising=False)
        assert http_shared_secret() is None
        assert http_auth_headers() == {}
        assert http_auth_valid({}) is True

    def test_auth_required_when_configured(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("NEST_HTTP_SHARED_SECRET", "s3cret")
        assert http_auth_headers() == {"X-Nest-Auth": "s3cret"}
        assert http_auth_valid({"x-nest-auth": "s3cret"}) is True
        assert http_auth_valid({"x-nest-auth": "wrong"}) is False


class TestRequireHttpSharedSecret:
    def test_single_worker_localhost_ok_without_secret(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.delenv("NEST_HTTP_SHARED_SECRET", raising=False)
        config = ScenarioConfig.from_dict(
            {"name": "solo", "workers": 1, "worker_bind": "127.0.0.1"},
        )
        require_http_shared_secret(config)

    def test_multi_worker_requires_secret(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("NEST_HTTP_SHARED_SECRET", raising=False)
        config = ScenarioConfig.from_dict({"name": "dist", "workers": 2})
        with pytest.raises(ValueError, match="NEST_HTTP_SHARED_SECRET"):
            require_http_shared_secret(config)

    def test_multi_worker_ok_with_secret(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("NEST_HTTP_SHARED_SECRET", "s3cret")
        config = ScenarioConfig.from_dict({"name": "dist", "workers": 2})
        require_http_shared_secret(config)

    def test_exposed_bind_requires_secret(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("NEST_HTTP_SHARED_SECRET", raising=False)
        config = ScenarioConfig.from_dict(
            {"name": "exposed", "workers": 1, "worker_bind": "0.0.0.0"},
        )
        with pytest.raises(ValueError, match="NEST_HTTP_SHARED_SECRET"):
            require_http_shared_secret(config)


class TestCheckHealthAuth:
    @pytest.mark.asyncio
    async def test_health_with_shared_secret(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from nest_core.sim.network_runner import WorkerHttpBridge, check_health
        from nest_core.sim.simulator import Simulator

        monkeypatch.setenv("NEST_HTTP_SHARED_SECRET", "health-secret")
        sim = Simulator(seed=1, trace_path=None, parallel=True)
        bridge = WorkerHttpBridge(sim.event_queue, sim.clock)
        port = await bridge.start(0, host="127.0.0.1")
        try:
            assert await check_health(f"http://127.0.0.1:{port}") is True
        finally:
            await bridge.stop()


class TestJwtAuthClock:
    @pytest.mark.asyncio
    async def test_virtual_clock_is_deterministic(self) -> None:
        clock = {"now": 100.0}
        auth = JwtAuth(secret=b"secret", clock=lambda: clock["now"])
        token = await auth.issue(AgentId("a1"), ["read"])
        ctx = await auth.verify(token)
        assert ctx.expires_at == 100.0 + 3600

        clock["now"] = 5000.0
        with pytest.raises(ValueError, match="expired"):
            await auth.verify(token)

    @pytest.mark.asyncio
    async def test_revocation_is_bounded(self) -> None:
        auth = JwtAuth(secret=b"secret", clock=0.0, max_revoked=2)
        tokens = [await auth.issue(AgentId(f"a{i}"), ["read"]) for i in range(3)]
        for token in tokens:
            await auth.revoke(token)
        assert auth.revoked_count == 2


class TestPluginWiring:
    @pytest.mark.asyncio
    async def test_wire_auth_instantiates_jwt_with_sim_clock(self) -> None:
        from nest_core.sim.plugin_wiring import wire_auth_to_sim_clock

        clock = {"now": 42.0}
        plugins: dict[str, object] = {"auth": JwtAuth}
        wire_auth_to_sim_clock(plugins, lambda: clock["now"])
        auth = plugins["auth"]
        assert isinstance(auth, JwtAuth)
        token = await auth.issue(AgentId("a1"), ["read"])
        ctx = await auth.verify(token)
        assert ctx.expires_at == 42.0 + 3600
        clock["now"] = 5000.0
        with pytest.raises(ValueError, match="expired"):
            await auth.verify(token)
