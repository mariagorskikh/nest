# SPDX-License-Identifier: Apache-2.0
"""Hypothesis property-based tests for the ``hybrid_x25519`` privacy plugin.

Each invariant is checked over generated payloads, seeds, audiences, credential
field sets, and reveal subsets — so the guarantees hold for *all* inputs, not
just the hand-picked cases in ``test_hybrid_x25519.py``:

1. **Round-trip.** Every member of the audience recovers the exact plaintext.
2. **Audience confidentiality.** A non-audience agent never recovers the
   plaintext (decrypt always fails).
3. **Determinism.** In deterministic mode, the same ``(seed, agent, payload,
   audience, call order)`` yields byte-identical envelopes (Tier-1 replay).
4. **Tamper-evidence.** Corrupting the ciphertext always breaks authentication.
5. **Replay.** The second presentation of any envelope is always rejected.
6. **Revocation monotonicity.** After revocation a member is blocked from
   *future* messages while non-revoked members still read them.
7. **Selective-disclosure completeness & soundness.** An honest proof over any
   field set and any non-empty reveal subset verifies; tampering any revealed
   field always makes it fail.

The plugin's ``encrypt``/``decrypt``/``prove``/``verify_proof`` are ``async`` by
the ``Privacy`` protocol, so each property drives them through ``asyncio.run``
inside an otherwise-synchronous Hypothesis test.

Example::

    pytest packages/nest-plugins-reference/tests/test_hybrid_x25519_properties.py
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Coroutine
from typing import Any

from hypothesis import given, settings
from hypothesis import strategies as st
from nest_core.types import AgentId, Statement, Witness
from nest_plugins_reference.privacy.hybrid_x25519 import (
    HybridX25519Privacy,
    commit_credential,
)
from nest_plugins_reference.validators import corrupt_proof

# Letters g-z only: never collide with hex (0-9a-f) and never a JSON metachar,
# so generated values stay distinctive without tripping substring heuristics.
_letters = "ghijklmnopqrstuvwxyz"
_payloads = st.binary(min_size=0, max_size=128)
_seeds = st.binary(min_size=0, max_size=32)
_names = st.text(alphabet=_letters, min_size=1, max_size=6)
_values = st.text(alphabet=_letters, min_size=1, max_size=8)
_field_sets = st.dictionaries(_names, _values, min_size=1, max_size=5)


def _run(coro: Coroutine[Any, Any, None]) -> None:
    asyncio.run(coro)


def _sender(seed: bytes, *, deterministic: bool = False) -> HybridX25519Privacy:
    return HybridX25519Privacy(AgentId("sender"), seed=seed, deterministic=deterministic)


def _recipient(index: int, seed: bytes, *, deterministic: bool = False) -> HybridX25519Privacy:
    return HybridX25519Privacy(
        AgentId(f"r{index}"), seed=seed + bytes([index % 256]), deterministic=deterministic
    )


async def _failed(coro: Coroutine[Any, Any, bytes]) -> bool:
    """Return ``True`` iff awaiting *coro* raises (i.e. the decrypt was blocked)."""
    try:
        await coro
    except Exception:  # noqa: BLE001 - any failure counts as "blocked"
        return True
    return False


class TestEncryptionInvariants:
    @settings(max_examples=40, deadline=None)
    @given(payload=_payloads, k=st.integers(min_value=1, max_value=4), seed=_seeds)
    def test_all_audience_members_recover_plaintext(
        self, payload: bytes, k: int, seed: bytes
    ) -> None:
        async def go() -> None:
            sender = _sender(seed)
            recipients = [_recipient(i, seed) for i in range(k)]
            ids = [AgentId(f"r{i}") for i in range(k)]
            for rid, plugin in zip(ids, recipients, strict=True):
                sender.register_peer(rid, plugin.public_key)
            env = await sender.encrypt(payload, ids)
            for plugin in recipients:
                assert await plugin.decrypt(env) == payload

        _run(go())

    @settings(max_examples=40, deadline=None)
    @given(payload=_payloads, seed=_seeds)
    def test_outsider_never_recovers_plaintext(self, payload: bytes, seed: bytes) -> None:
        async def go() -> None:
            sender = _sender(seed)
            bob = _recipient(0, seed)
            outsider = _recipient(99, seed)
            sender.register_peer(AgentId("r0"), bob.public_key)
            env = await sender.encrypt(payload, [AgentId("r0")])
            assert await _failed(outsider.decrypt(env))

        _run(go())

    @settings(max_examples=30, deadline=None)
    @given(payload=_payloads, seed=_seeds)
    def test_deterministic_mode_is_byte_reproducible(self, payload: bytes, seed: bytes) -> None:
        async def go() -> None:
            def build() -> tuple[HybridX25519Privacy, list[AgentId]]:
                sender = _sender(seed, deterministic=True)
                bob = _recipient(0, seed, deterministic=True)
                sender.register_peer(AgentId("r0"), bob.public_key)
                return sender, [AgentId("r0")]

            s1, ids1 = build()
            s2, ids2 = build()
            assert await s1.encrypt(payload, ids1) == await s2.encrypt(payload, ids2)

        _run(go())

    @settings(max_examples=40, deadline=None)
    @given(payload=st.binary(min_size=1, max_size=128), seed=_seeds)
    def test_ciphertext_tamper_always_detected(self, payload: bytes, seed: bytes) -> None:
        async def go() -> None:
            sender = _sender(seed)
            bob = _recipient(0, seed)
            sender.register_peer(AgentId("r0"), bob.public_key)
            env = bytearray(await sender.encrypt(payload, [AgentId("r0")]))
            # Flip the first ciphertext char (always encodes a significant bit,
            # so the decoded ciphertext byte 0 always changes -> AEAD rejects).
            start = env.index(b'"ct":"') + len(b'"ct":"')
            env[start] = ord("B") if env[start] == ord("A") else ord("A")
            assert await _failed(bob.decrypt(bytes(env)))

        _run(go())

    @settings(max_examples=40, deadline=None)
    @given(payload=_payloads, seed=_seeds)
    def test_replay_always_rejected(self, payload: bytes, seed: bytes) -> None:
        async def go() -> None:
            sender = _sender(seed)
            bob = _recipient(0, seed)
            sender.register_peer(AgentId("r0"), bob.public_key)
            env = await sender.encrypt(payload, [AgentId("r0")])
            assert await bob.decrypt(env) == payload
            assert await _failed(bob.decrypt(env))

        _run(go())

    @settings(max_examples=30, deadline=None)
    @given(payload=_payloads, seed=_seeds)
    def test_revocation_blocks_future_only(self, payload: bytes, seed: bytes) -> None:
        async def go() -> None:
            sender = _sender(seed)
            keep = _recipient(0, seed)
            victim = _recipient(1, seed)
            ids = [AgentId("r0"), AgentId("r1")]
            sender.register_peer(AgentId("r0"), keep.public_key)
            sender.register_peer(AgentId("r1"), victim.public_key)
            pre = await sender.encrypt(payload, ids)
            assert await victim.decrypt(pre) == payload  # had access before
            sender.revoke(AgentId("r1"))
            post = await sender.encrypt(payload, ids)
            assert await keep.decrypt(post) == payload  # non-revoked still reads
            assert await _failed(victim.decrypt(post))  # revoked is blocked

        _run(go())


class TestSelectiveDisclosureInvariants:
    @settings(max_examples=40, deadline=None)
    @given(fields=_field_sets, seed=_seeds, data=st.data())
    def test_completeness_and_soundness(
        self, fields: dict[str, str], seed: bytes, data: st.DataObject
    ) -> None:
        async def go() -> None:
            names = sorted(fields)
            reveal = data.draw(
                st.lists(st.sampled_from(names), min_size=1, max_size=len(names), unique=True)
            )
            root, salts = commit_credential(fields, salt_seed=seed)
            statement = Statement(
                predicate="selective_disclosure",
                public_inputs={"root": root, "reveal": ",".join(sorted(set(reveal)))},
            )
            witness = Witness(
                private_inputs={**fields, "__salts__": json.dumps(salts, sort_keys=True)}
            )
            priv = _sender(seed)
            proof = await priv.prove(statement, witness)
            # Completeness: an honest proof over any reveal subset verifies.
            assert await priv.verify_proof(statement, proof)
            # Soundness: tampering any revealed field is always rejected.
            assert not await priv.verify_proof(statement, corrupt_proof(proof))

        _run(go())
