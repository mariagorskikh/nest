# SPDX-License-Identifier: Apache-2.0
"""DID:key identity plugin — deterministic public-key signatures for simulation.
This is intentionally dependency-free and deterministic so traces replay
byte-for-byte.  It is not production cryptography; for real deployments, swap
to a proper Ed25519 implementation.
Example::
    identity = DidKeyIdentity(AgentId("a1"), seed=b"secret")
    sig = identity.sign(b"payload")
    ok = identity.verify(b"payload", sig, AgentId("a1"))
"""

from __future__ import annotations

import hashlib
import json
import math
import warnings

from nest_core.types import AgentId, AgentIdentity, Signature


class DidKeyIdentity:
    """Public-verifiable identity for simulation.
    Example::
        ident = DidKeyIdentity(AgentId("a1"), seed=b"seed")
        sig = ident.sign(b"hello")
    """

    _warned: bool = False

    def __init__(self, agent_id: AgentId, seed: bytes = b"") -> None:
        if not DidKeyIdentity._warned:
            warnings.warn(
                "DidKeyIdentity uses deterministic textbook RSA (~512-bit) for "
                "simulation only; it is not production cryptography. Prefer "
                "ed25519_rotating for real deployments.",
                stacklevel=2,
                category=UserWarning,
            )
            DidKeyIdentity._warned = True
        self._agent_id = agent_id
        self._seed = seed
        self._public_numbers, self._private_exponent = _derive_keypair(seed, agent_id)
        self._public_key = _encode_public_key(self._public_numbers)
        self._known_keys: dict[AgentId, tuple[int, int]] = {agent_id: self._public_numbers}

    def register_peer(
        self,
        agent_id: AgentId,
        public_key: bytes,
        private_key: bytes | None = None,
    ) -> None:
        """Register a peer's public key for verification.
        Example::
            ident.register_peer(AgentId("a2"), peer_pk)
        """
        if private_key is not None:
            msg = "register_peer accepts public keys only"
            raise ValueError(msg)
        self._known_keys[agent_id] = _decode_public_key(public_key)

    @property
    def public_key(self) -> bytes:
        """This agent's public key.
        Example::
            pk = ident.public_key
        """
        return self._public_key

    def sign(self, payload: bytes) -> Signature:
        """Sign a payload with this agent's private key.
        Example::
            sig = ident.sign(b"data")
        """
        n, _e = self._public_numbers
        digest = _digest_int(payload, n)
        sig_int = pow(digest, self._private_exponent, n)
        size = (n.bit_length() + 7) // 8
        sig_bytes = sig_int.to_bytes(size, "big")
        return Signature(signer=self._agent_id, value=sig_bytes, algorithm="sim-rsa-sha256")

    def verify(self, payload: bytes, sig: Signature, agent: AgentId) -> bool:
        """Verify a signature from a given agent.
        Example::
            ok = ident.verify(b"data", sig, AgentId("a1"))
        """
        if sig.signer != agent:
            return False
        public_numbers = self._known_keys.get(agent)
        if public_numbers is None:
            return False
        n, e = public_numbers
        sig_int = int.from_bytes(sig.value, "big")
        if sig_int >= n:
            return False
        expected = _digest_int(payload, n)
        actual = pow(sig_int, e, n)
        return actual == expected

    async def resolve(self, agent: AgentId) -> AgentIdentity:
        """Resolve an agent ID to its identity record.
        Example::
            info = await ident.resolve(AgentId("a1"))
        """
        public_numbers = self._known_keys.get(agent)
        pk = _encode_public_key(public_numbers) if public_numbers is not None else b""
        return AgentIdentity(
            agent_id=agent,
            public_key=pk,
            method="did:key",
        )


_PUBLIC_EXPONENT = 65537


def _derive_keypair(seed: bytes, agent_id: AgentId) -> tuple[tuple[int, int], int]:
    p = _derive_prime(seed, agent_id, b"p")
    q = _derive_prime(seed, agent_id, b"q")
    counter = 0
    while p == q or math.gcd(_PUBLIC_EXPONENT, (p - 1) * (q - 1)) != 1:
        counter += 1
        q = _derive_prime(seed, agent_id, b"q" + counter.to_bytes(2, "big"))
    n = p * q
    phi = (p - 1) * (q - 1)
    d = pow(_PUBLIC_EXPONENT, -1, phi)
    return (n, _PUBLIC_EXPONENT), d


def _derive_prime(seed: bytes, agent_id: AgentId, label: bytes) -> int:
    counter = 0
    while True:
        material = seed + b":" + str(agent_id).encode() + b":" + label + counter.to_bytes(4, "big")
        digest = hashlib.sha512(material).digest()
        candidate = int.from_bytes(digest[:32], "big")
        candidate |= 1
        candidate |= 1 << 255
        if _is_probable_prime(candidate):
            return candidate
        counter += 1


def _is_probable_prime(n: int) -> bool:
    if n < 2:
        return False
    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    for prime in small_primes:
        if n == prime:
            return True
        if n % prime == 0:
            return False
    d = n - 1
    s = 0
    while d % 2 == 0:
        s += 1
        d //= 2
    for base in small_primes:
        if base >= n:
            continue
        x = pow(base, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _encode_public_key(public_numbers: tuple[int, int]) -> bytes:
    n, e = public_numbers
    return json.dumps(
        {"alg": "sim-rsa-sha256", "e": e, "n": format(n, "x")},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _decode_public_key(public_key: bytes) -> tuple[int, int]:
    try:
        data = json.loads(public_key.decode("ascii"))
        if data.get("alg") != "sim-rsa-sha256":
            raise ValueError
        return int(data["n"], 16), int(data["e"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        msg = "Invalid public key"
        raise ValueError(msg) from exc


def _digest_int(payload: bytes, modulus: int) -> int:
    return int.from_bytes(hashlib.sha256(payload).digest(), "big") % modulus
