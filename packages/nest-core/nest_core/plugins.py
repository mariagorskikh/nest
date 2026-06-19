# SPDX-License-Identifier: Apache-2.0
"""Plugin registry — resolves plugin names to implementations.

Discovers plugins via entry points and provides built-in defaults for all 12 layers.

Example::

    registry = PluginRegistry()
    transport_cls = registry.resolve("transport", "in_memory")
"""

from __future__ import annotations

import importlib.metadata
from typing import Any

# Built-in reference plugins keyed by (layer, name)
_REF = "nest_plugins_reference"
_BUILTINS: dict[tuple[str, str], str] = {
    ("transport", "in_memory"): f"{_REF}.transport.in_memory:StandaloneInMemoryTransport",
    ("comms", "nest_native"): f"{_REF}.comms.nest_native:NestNativeComms",
    ("comms", "versioned"): f"{_REF}.comms.versioned:VersionedComms",
    ("identity", "did_key"): f"{_REF}.identity.did_key:DidKeyIdentity",
    ("registry", "in_memory"): f"{_REF}.registry.in_memory:InMemoryRegistry",
    ("auth", "jwt"): f"{_REF}.auth.jwt_auth:JwtAuth",
    ("trust", "score_average"): f"{_REF}.trust.score_average:ScoreAverageTrust",
    ("payments", "prepaid_credits"): f"{_REF}.payments.prepaid_credits:PrepaidCredits",
    ("payments", "streaming"): f"{_REF}.payments.streaming:StreamingPayments",
    ("coordination", "contract_net"): f"{_REF}.coordination.contract_net:ContractNet",
    ("negotiation", "alternating_offers"): (
        f"{_REF}.negotiation.alternating_offers:AlternatingOffers"
    ),
    ("memory", "blackboard"): f"{_REF}.memory.blackboard:Blackboard",
    ("memory", "lww_register"): f"{_REF}.memory.lww_register:LwwRegisterMemory",
    ("privacy", "noop"): f"{_REF}.privacy.noop:NoopPrivacy",
    ("datafacts", "datafacts_v1"): f"{_REF}.datafacts.datafacts_v1:DataFactsV1",
}


def _import_dotted(path: str) -> Any:
    module_path, _, attr = path.rpartition(":")
    mod = __import__(module_path, fromlist=[attr])
    return getattr(mod, attr)


class PluginRegistry:
    """Resolves plugin names to their implementations.

    Example::

        reg = PluginRegistry()
        cls = reg.resolve("payments", "prepaid_credits")
    """

    def __init__(self) -> None:
        self._cache: dict[tuple[str, str], Any] = {}
        self._discover_entry_points()

    def _discover_entry_points(self) -> None:
        for layer in [
            "transport",
            "comms",
            "identity",
            "registry",
            "auth",
            "trust",
            "payments",
            "coordination",
            "negotiation",
            "memory",
            "privacy",
            "datafacts",
        ]:
            group = f"nest.plugins.{layer}"
            eps = importlib.metadata.entry_points(group=group)
            for ep in eps:
                self._cache[(layer, ep.name)] = ep

    def resolve(self, layer: str, name: str) -> Any:
        """Resolve a (layer, name) pair to a plugin class.

        Example::

            cls = registry.resolve("transport", "in_memory")
        """
        key = (layer, name)
        cached = self._cache.get(key)
        if cached is not None:
            if hasattr(cached, "load"):
                cls = cached.load()
                self._cache[key] = cls
                return cls
            return cached

        builtin = _BUILTINS.get(key)
        if builtin is not None:
            cls = _import_dotted(builtin)
            self._cache[key] = cls
            return cls

        msg = f"No plugin found for layer={layer!r}, name={name!r}"
        raise KeyError(msg)

    def list_plugins(self, layer: str | None = None) -> list[tuple[str, str]]:
        """List available plugins, optionally filtered by layer.

        Example::

            plugins = registry.list_plugins("payments")
        """
        all_keys: set[tuple[str, str]] = set()
        all_keys.update(self._cache.keys())
        all_keys.update(_BUILTINS.keys())
        if layer is not None:
            return sorted(k for k in all_keys if k[0] == layer)
        return sorted(all_keys)
