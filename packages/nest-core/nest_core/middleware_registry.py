# SPDX-License-Identifier: Apache-2.0
"""Middleware registry — resolves middleware names to implementations.

Example::

    registry = MiddlewareRegistry()
    cls = registry.resolve("resilience")
    mw = cls(config={})
"""

from __future__ import annotations

import importlib.metadata
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class MiddlewareFactory(Protocol):
    """Built-in and third-party middleware factories."""

    def __init__(self, *, config: dict[str, Any] | None = None) -> None: ...

    async def on_send(self, ctx: Any) -> Any | None: ...

    async def on_receive(self, ctx: Any) -> Any | None: ...


_BUILTINS: dict[str, str] = {
    "resilience": "nest_core.sim.middleware_builtins.resilience:ResilienceMiddleware",
    "observability": "nest_core.sim.middleware_builtins.observability:ObservabilityMiddleware",
    "auth_scope": "nest_core.sim.middleware_builtins.auth_scope:AuthScopeMiddleware",
    "latency": "nest_core.sim.middleware_builtins.latency:LatencyMiddleware",
}


def _import_dotted(path: str) -> Any:
    module_path, _, attr = path.rpartition(":")
    mod = __import__(module_path, fromlist=[attr])
    return getattr(mod, attr)


class MiddlewareRegistry:
    """Resolves middleware names to factory classes."""

    def __init__(self) -> None:
        self._cache: dict[str, Any] = {}
        self._discover_entry_points()

    def _discover_entry_points(self) -> None:
        eps = importlib.metadata.entry_points(group="nest.middleware")
        for ep in eps:
            self._cache[ep.name] = ep

    def resolve(self, name: str) -> type[MiddlewareFactory]:
        """Resolve a middleware name to its factory class."""
        cached = self._cache.get(name)
        if cached is not None:
            if hasattr(cached, "load"):
                cls = cached.load()
                self._cache[name] = cls
                return cls
            return cached

        builtin = _BUILTINS.get(name)
        if builtin is not None:
            cls = _import_dotted(builtin)
            self._cache[name] = cls
            return cls

        msg = f"No middleware found for name={name!r}"
        raise KeyError(msg)

    def instantiate(self, name: str, config: dict[str, Any] | None = None) -> MiddlewareFactory:
        """Resolve and construct a middleware instance."""
        cls = self.resolve(name)
        return cls(config=config or {})

    def list_middleware(self) -> list[str]:
        """List available middleware names."""
        names: set[str] = set(self._cache.keys())
        names.update(_BUILTINS.keys())
        return sorted(names)
