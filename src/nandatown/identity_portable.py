"""Portable identity: controller keys, the town registry, run grants.

The design from the doc, built: a long-lived controller key that never
becomes a model tool and never enters a participant's environment; a
registry mapping a portable agent id to its controller's public key
(the local file registry is the town's testnet registry; resolvers are
pluggable, including an eth_call resolver whose contract and selector
are configuration); and a Run Grant, a signed, time-limited permission
letting one disposable session key act in one run with named
permissions. The agent-facing experience stays the same while the
source of authority becomes portable.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .records import canonical_json, fingerprint

DEFAULT_PERMISSIONS = ["join", "claim", "send", "ack"]
GRANT_TTL_SECONDS = 3600.0
OPERATOR_NAME = "town-operator"


def default_keystore_dir() -> str:
    home = os.environ.get("NANDATOWN_HOME",
                          os.path.expanduser("~/.nandatown"))
    return os.path.join(home, "identity")


class IdentityError(Exception):
    pass


def _sign(private_hex: str, payload: Any) -> str:
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_hex))
    return key.sign(canonical_json(payload).encode()).hex()


def verify_signature(public_hex: str, payload: Any,
                     signature_hex: str) -> bool:
    try:
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex))
        key.verify(bytes.fromhex(signature_hex),
                   canonical_json(payload).encode())
        return True
    except (InvalidSignature, ValueError):
        return False


class Keystore:
    """Controller keys on disk, plus the town's testnet registry."""

    def __init__(self, directory: str):
        self.directory = directory
        os.makedirs(directory, exist_ok=True)
        self.registry_path = os.path.join(directory, "registry.json")

    def _registry(self) -> dict[str, Any]:
        if os.path.exists(self.registry_path):
            with open(self.registry_path) as f:
                return json.load(f)
        return {}

    def _write_registry(self, registry: dict[str, Any]) -> None:
        with open(self.registry_path, "w") as f:
            json.dump(registry, f, indent=2, sort_keys=True)

    def _key_path(self, name: str) -> str:
        return os.path.join(self.directory, f"{name}.controller.key")

    def new_identity(self, name: str) -> dict[str, Any]:
        if os.path.exists(self._key_path(name)):
            return self.identity(name)
        private = Ed25519PrivateKey.generate()
        private_hex = private.private_bytes_raw().hex()
        public_hex = private.public_key().public_bytes_raw().hex()
        agent_id = ("did:town:"
                    + fingerprint(public_hex).removeprefix("sha256:")[:24])
        with open(self._key_path(name), "w") as f:
            f.write(private_hex + "\n")
        os.chmod(self._key_path(name), 0o600)
        registry = self._registry()
        registry[agent_id] = {"name": name,
                              "controller_public": public_hex,
                              "registered_at": time.time()}
        self._write_registry(registry)
        return {"name": name, "agent_id": agent_id,
                "controller_public": public_hex}

    def identity(self, name: str) -> dict[str, Any]:
        for agent_id, entry in self._registry().items():
            if entry["name"] == name:
                return {"name": name, "agent_id": agent_id,
                        "controller_public": entry["controller_public"]}
        raise IdentityError(f"no identity {name!r} in {self.directory}")

    def identities(self) -> list[dict[str, Any]]:
        return [
            {"name": entry["name"], "agent_id": agent_id,
             "controller_public": entry["controller_public"]}
            for agent_id, entry in sorted(self._registry().items())
        ]

    def _controller_private(self, name: str) -> str:
        path = self._key_path(name)
        if not os.path.exists(path):
            raise IdentityError(f"no controller key for {name!r}")
        with open(path) as f:
            return f.read().strip()

    def sign(self, name: str, payload: Any) -> str:
        return _sign(self._controller_private(name), payload)

    def make_grant(self, name: str, run_id: str,
                   permissions: list[str] | None = None,
                   ttl: float = GRANT_TTL_SECONDS,
                   now: float | None = None) -> dict[str, Any]:
        """One disposable session key, authorized for one run.

        The controller key signs and stays here; only the session
        private key leaves, and it is worthless outside this run."""
        identity = self.identity(name)
        session = Ed25519PrivateKey.generate()
        now = time.time() if now is None else now
        grant = {
            "agent_id": identity["agent_id"],
            "run_id": run_id,
            "session_public": session.public_key().public_bytes_raw().hex(),
            "permissions": sorted(DEFAULT_PERMISSIONS if permissions is None
                                  else permissions),
            "issued_at": now,
            "expires_at": now + ttl,
        }
        signature = _sign(self._controller_private(name), grant)
        return {"grant": grant, "grant_signature": signature,
                "session_private":
                    session.private_bytes_raw().hex()}


def session_proof(session_private_hex: str, run_id: str,
                  name: str) -> str:
    return _sign(session_private_hex,
                 {"purpose": "join", "run_id": run_id, "name": name})


def verify_grant(grant: dict[str, Any], grant_signature: str,
                 controller_public: str, run_id: str, name: str,
                 proof: str, now: float | None = None) -> None:
    """Raises IdentityError unless the whole chain holds: the pinned
    controller signed this grant, for this run, unexpired, and the
    joiner holds the grant's session key."""
    now = time.time() if now is None else now
    if grant.get("run_id") != run_id:
        raise IdentityError("grant names a different run")
    if now > float(grant.get("expires_at", 0)):
        raise IdentityError("grant expired")
    permissions = grant.get("permissions")
    if not isinstance(permissions, list) \
            or not all(isinstance(p, str) for p in permissions):
        raise IdentityError("grant permissions must be a list of names")
    if not isinstance(grant.get("issued_at"), (int, float)) \
            or isinstance(grant.get("issued_at"), bool):
        raise IdentityError("grant issued_at must be a timestamp")
    if not verify_signature(controller_public, grant, grant_signature):
        raise IdentityError("grant signature does not verify against"
                            " the pinned controller key")
    if not verify_signature(
            grant["session_public"],
            {"purpose": "join", "run_id": run_id, "name": name}, proof):
        raise IdentityError("session proof does not verify against the"
                            " grant's session key")


# -- registry resolvers ------------------------------------------------


def resolve_file(registry_path: str, agent_id: str) -> str:
    with open(registry_path) as f:
        registry = json.load(f)
    if agent_id not in registry:
        raise IdentityError(f"{agent_id} not in {registry_path}")
    return registry[agent_id]["controller_public"]


def resolve_eth(rpc_url: str, contract: str, selector: str,
                agent_id: str, http=None) -> str:
    """Resolve a controller key from a chain registry via eth_call.

    The contract address and function selector are configuration: the
    registry's semantics live in the deployed contract, and this
    resolver only performs the read. The argument is the 32-byte hash
    of the agent id; the return is ABI-encoded dynamic bytes holding
    the controller public key."""
    import hashlib

    import httpx

    client = http or httpx.Client(timeout=15.0)
    argument = hashlib.sha256(agent_id.encode()).hexdigest()
    data = "0x" + selector.removeprefix("0x") + argument
    response = client.post(rpc_url, json={
        "jsonrpc": "2.0", "id": 1, "method": "eth_call",
        "params": [{"to": contract, "data": data}, "latest"]})
    response.raise_for_status()
    payload = response.json()
    if "error" in payload:
        raise IdentityError(f"eth_call failed: {payload['error']}")
    raw = bytes.fromhex(payload["result"].removeprefix("0x"))
    if len(raw) < 96:
        raise IdentityError("eth_call returned no key")
    length = int.from_bytes(raw[32:64], "big")
    key = raw[64:64 + length]
    if not key:
        raise IdentityError("registry holds no controller key for"
                            f" {agent_id}")
    return key.hex()
