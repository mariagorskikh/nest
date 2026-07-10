# SPDX-License-Identifier: Apache-2.0
"""embx-backed semantic memory plugin -- recall by meaning, not by key.

The default ``blackboard`` memory plugin is an 80-line shared dict: write a
value under a key, read it back under the *same* key. Nothing else. If agent-A
files a fact under ``"airport-departure-gate"`` and agent-B asks for
``"flight-boarding-info"``, blackboard returns ``None``. The keys have to match
byte-for-byte or the fact is invisible. For a swarm that's the whole problem:
different agents name the same thing differently, and the shared state goes
unused.

This plugin implements the same :class:`~nest_core.layers.memory.Memory`
surface (``read`` / ``write`` / ``subscribe`` / ``cas``) but every write also
embeds the key, and a new :meth:`semantic_lookup` ranks stored entries by
**cosine similarity** to a query key -- so a read for a *related* key finds the
stored value even when the literal keys disagree.

The embedding backend is **embx** (https://embx.net), a real semantic-vector
memory service. ``write`` posts the key to embx's ``/v1/embeddings`` endpoint
and stores the returned vector alongside the value; ``semantic_lookup`` embeds
the query and ranks stored entries by cosine similarity. In production this is
genuine semantic recall over a 384-dimensional embedding space.

Determinism -- why there is a fallback
--------------------------------------

Nanda Town's contract is byte-reproducible traces under a fixed seed. A live
LLM embedding model is not deterministic across hardware and needs network, so
it cannot be the path CI runs. This plugin therefore has a **deterministic
fallback**: when ``EMBX_BASE_URL`` is unset, or the embx endpoint is
unreachable, or the HTTP call fails for any reason, the plugin falls back to a
hash-based pseudo-embedding. The fallback is deterministic (pure function of
the key text) and is *deliberately semantic-ish*: it lowercases, tokenises on
non-alphanumerics, and hashes each token into the vector with a per-token seed,
so keys that share tokens (``"departure-gate"`` and ``"gate-departures"``)
produce vectors that overlap and score high under cosine similarity, while
keys with no shared tokens score near zero. That is enough to prove the plugin
ranks by similarity rather than exact-matching -- the property the test asserts
-- without ever touching the network.

The real embx path is exercised in production (point ``EMBX_BASE_URL`` at the
live service and supply ``EMBX_API_KEY``); the test and CI path exercises the
fallback and stays offline + reproducible.

Example::

    mem = EmbxSemanticMemory("agent-0")
    await mem.write("airport-departure-gate", b"A23")
    # Exact read still works (Protocol contract):
    assert await mem.read("airport-departure-gate") == b"A23"
    # Semantic read finds it under a different, related key:
    hit = await mem.semantic_lookup("flight-boarding-gate")
    assert hit is not None and hit.key == "airport-departure-gate"
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import urllib.error
import urllib.request
from collections.abc import AsyncIterator
from typing import Any, cast

DEFAULT_EMBX_BASE_URL = "https://embx.net"
"""The live embx endpoint. This is the production target you point
``EMBX_BASE_URL`` at to enable real semantic recall. It is NOT the default
when the env var is unset -- see :data:`EMBX_BASE_URL` semantics below.

Unsetting ``EMBX_BASE_URL`` deliberately forces the deterministic fallback so
CI runs offline and reproducibly. The live path is opt-in: set
``EMBX_BASE_URL=https://embx.net`` (and optionally ``EMBX_API_KEY``) to turn it
on in production.
"""

EMBEDDING_DIM = 384
"""Vector width for both the embx path (matches embx's native
``frankenstein-22.8mb-int8`` dimension) and the deterministic fallback (kept
the same so downstream code never branches on dimension)."""

EMBX_TIMEOUT_S = 2.0
"""Per-request timeout for the embx HTTP call. Short on purpose: if embx is
slow or down we fall back fast rather than stall the agent loop. The fallback
is deterministic, so a timeout degrades to reproducible behaviour, not a
hang."""

_SIMILARITY_FLOOR = 0.05
"""Minimum cosine similarity for a semantic match. Below this the stored
entry is treated as unrelated and skipped, so an empty-ish store does not hand
back a near-zero best-effort match as if it were a hit. Kept above the noise
floor of the hash-embedding fallback so disjoint-token keys (which score a
small positive value from coordinate collisions) do not sneak through."""


def _tokenize(text: str) -> list[str]:
    """Split text into lowercase alphanumeric tokens for the fallback embedder.

    Tokens are run together after lowercasing and stripping everything that is
    not a letter or digit, so ``"flight-boarding_gate"`` and
    ``"Flight Boarding Gate"`` collapse to the same token set. This is the
    property that makes the fallback rank related keys together.

    Example::

        assert _tokenize("Gate-23!") == ["gate", "23"]
    """
    out: list[str] = []
    current: list[str] = []
    for ch in text.lower():
        if ch.isalnum():
            current.append(ch)
        elif current:
            out.append("".join(current))
            current = []
    if current:
        out.append("".join(current))
    return out


def _hash_embedding(text: str, dim: int = EMBEDDING_DIM) -> list[float]:
    """Deterministic, semantic-ish pseudo-embedding of ``text``.

    The vector is a **bag-of-tokens** sketch: each distinct token is hashed to
    a seed, and the seed drives a fixed set of coordinate perturbations that
    are *accumulated* into the vector. Order does not matter -- two keys that
    share the same token multiset produce the same vector (cosine = 1.0);
    keys that share some tokens overlap on those coordinates and score a
    fractional cosine; keys with disjoint tokens land in disjoint coordinates
    and score near zero. That is the property that lets
    :meth:`EmbxSemanticMemory.semantic_lookup` rank related keys together.

    The result is a pure function of the input text -- same bytes in, same
    vector out, every run, every machine -- which is what makes the fallback
    CI-safe.

    This is not a learned embedding and it does not understand synonyms; it
    understands shared surface tokens. That is the intended ceiling of the
    deterministic path. The learned embx path replaces it in production.

    Example::

        v = _hash_embedding("departure gate")
        assert len(v) == EMBEDDING_DIM
    """
    vec = [0.0] * dim
    tokens = _tokenize(text)
    if not tokens:
        return vec
    # Seed by token alone (not position) so the embedding is a function of the
    # token multiset -- order-independent, which is what makes shared-token
    # keys land on the same coordinates.
    for token in tokens:
        seed = token.encode("utf-8")
        digest = hashlib.sha256(seed).digest()
        # Spread each token across a fixed band of coordinates driven by the
        # hash. Band start is token-specific so distinct tokens mostly touch
        # distinct coordinates, keeping disjoint-token similarity near zero.
        band_start = int.from_bytes(digest[:2], "little") % dim
        for i in range(12):
            byte = digest[(i + 2) % len(digest)]
            coord = (band_start + i) % dim
            sign = 1.0 if (byte & 1) == 0 else -1.0
            vec[coord] += sign
    # L2-normalize so cosine similarity is just a dot product.
    norm = sum(v * v for v in vec) ** 0.5
    if norm > 0:
        vec = [v / norm for v in vec]
    return vec


def _cosine(a: list[float], b: list[float]) -> float:
    """Cosine similarity of two equal-length, L2-normalised vectors.

    Both inputs are assumed already normalised (the embx path returns unit
    vectors and :func:`_hash_embedding` normalises), so this is a plain dot
    product. A defensive check keeps it correct if a caller hands in a raw
    vector.

    Example::

        assert _cosine([1.0, 0.0], [1.0, 0.0]) == 1.0
    """
    if len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    na = sum(x * x for x in a) ** 0.5
    nb = sum(y * y for y in b) ** 0.5
    if na == 0.0 or nb == 0.0:
        return 0.0
    return dot / (na * nb)


class EmbxSemanticMemory:
    """embx-backed semantic memory implementing the ``Memory`` protocol.

    ``read`` / ``write`` / ``subscribe`` / ``cas`` match the ``blackboard``
    contract exactly (exact-key read, subscriber notification, CAS on the
    current value). The semantic capability lives in :meth:`semantic_lookup`,
    which ranks stored entries by cosine similarity to a query key and returns
    the best match above :data:`_SIMILARITY_FLOOR`.

    Configuration is read from the environment so the plugin can be dropped
    into a scenario with no constructor changes:

    - ``EMBX_BASE_URL`` -- embx endpoint. **Unset by default**, which forces
      the deterministic fallback so CI runs offline and reproducibly. Set this
      to :data:`DEFAULT_EMBX_BASE_URL` (``https://embx.net``) in production to
      enable real semantic recall over the live service.
    - ``EMBX_API_KEY`` -- bearer token for authenticated embx calls. When
      absent the plugin still functions via the anonymous/free embx path or
      the fallback.
    - ``EMBX_TIMEOUT_S`` -- per-request timeout override (float seconds).

    The single-argument constructor (``EmbxSemanticMemory("agent-0")``) matches
    the convention the ``memory_concurrent_writers`` scenario factory uses to
    instantiate per-agent memory replicas, so this plugin drops into any
    scenario that currently names ``memory: blackboard`` or
    ``memory: lww_register``.

    Example::

        mem = EmbxSemanticMemory("agent-0")
        await mem.write("airport-departure-gate", b"A23")
        assert await mem.read("airport-departure-gate") == b"A23"
    """

    def __init__(self, node_id: str = "node") -> None:
        """Create a semantic-memory replica with a stable ``node_id``.

        ``node_id`` is accepted for protocol-shape parity with
        :class:`~nest_plugins_reference.memory.lww_register.LwwRegisterMemory`
        (the per-agent replica factory passes the agent id); it is not used in
        ranking but is exposed for traceability.

        Example::

            mem = EmbxSemanticMemory("agent-0")
        """
        self._node_id = str(node_id)
        self._store: dict[str, bytes] = {}
        self._vectors: dict[str, list[float]] = {}
        self._subscribers: dict[str, list[asyncio.Queue[bytes]]] = {}

        # The live embx path is opt-in. When EMBX_BASE_URL is unset (the CI
        # default) the plugin uses the deterministic fallback so traces stay
        # offline and byte-reproducible. Set EMBX_BASE_URL=https://embx.net in
        # production to enable real semantic recall.
        base = os.environ.get("EMBX_BASE_URL", "")
        self._base_url = base.strip() or None
        self._api_key = os.environ.get("EMBX_API_KEY", "").strip() or None
        try:
            self._timeout_s = float(os.environ.get("EMBX_TIMEOUT_S", "") or EMBX_TIMEOUT_S)
        except ValueError:
            self._timeout_s = EMBX_TIMEOUT_S
        # Lazy flag: once an embx call fails, stop retrying the network for the
        # rest of this replica's life and go straight to the fallback. Avoids
        # a per-write timeout tax when the endpoint is down.
        self._embx_unavailable = False

    @property
    def node_id(self) -> str:
        """The stable node identifier passed at construction.

        Example::

            assert EmbxSemanticMemory("agent-0").node_id == "agent-0"
        """
        return self._node_id

    @property
    def using_embx(self) -> bool:
        """True iff this replica will attempt live embx calls.

        False when ``EMBX_BASE_URL`` was unset/empty (forced fallback) or after
        the first embx failure has tripped the lazy unavailable flag. Useful
        for tests that need to assert which path is active.

        Example::

            assert EmbxSemanticMemory().using_embx in (True, False)
        """
        return self._base_url is not None and not self._embx_unavailable

    # -- embedding backend ------------------------------------------------

    def _embed(self, text: str) -> list[float]:
        """Embed ``text`` via embx, falling back to the hash embedding.

        The fallback fires when the endpoint is unset, already known-bad, or
        returns any error (network, non-200, malformed JSON, wrong shape).
        The method is synchronous because the Memory protocol methods are
        async and wrap this call -- the network I/O here is a short, bounded
        urllib request, not a long-lived stream.

        Example::

            vec = mem._embed("departure gate")
            assert len(vec) == EMBEDDING_DIM
        """
        if self.using_embx:
            vec = self._embed_via_embx(text)
            if vec is not None:
                return vec
            # embx call failed -- trip the flag so subsequent writes go straight
            # to the fallback instead of re-paying the timeout.
            self._embx_unavailable = True
        return _hash_embedding(text)

    def _embed_via_embx(self, text: str) -> list[float] | None:
        """POST to embx ``/v1/embeddings`` and return the vector, or None.

        Returns ``None`` on any failure (network, HTTP error, bad JSON,
        dimension mismatch) so :meth:`_embed` can fall back cleanly. Never
        raises -- a broken embx is a fallback signal, not a plugin crash.

        Example::

            vec = mem._embed_via_embx("gate")  # None if embx unreachable
        """
        if self._base_url is None:
            return None
        url = f"{self._base_url.rstrip('/')}/v1/embeddings"
        body = json.dumps({"input": text, "model": "frankenstein-22.8mb-int8"}).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        try:
            req = urllib.request.Request(url, data=body, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=self._timeout_s) as resp:  # noqa: S310
                if resp.status != 200:
                    return None
                raw = resp.read()
        except (urllib.error.URLError, OSError, TimeoutError):
            return None
        try:
            parsed: Any = json.loads(raw)
        except (ValueError, TypeError):
            return None
        if not isinstance(parsed, dict):
            return None
        payload = cast("dict[str, Any]", parsed)
        data = cast("list[Any] | None", payload.get("data"))
        if not data:
            return None
        first = cast("dict[str, Any]", data[0])
        embedding = cast("list[Any] | None", first.get("embedding"))
        if not embedding:
            return None
        floats: list[float] = []
        for x in embedding:
            floats.append(float(cast("float", x)))
        if len(floats) != EMBEDDING_DIM:
            # embx supports a dynamic ``dimension`` adapter; if the server
            # returned a different width (e.g. the free-tier clamp), reproject
            # via the deterministic hasher so downstream cosine math still has
            # a fixed-width vector to compare against.
            return _hash_embedding(text)
        return floats

    # -- Memory protocol --------------------------------------------------

    async def read(self, key: str) -> bytes | None:
        """Read a value by exact key, returning None if absent.

        This is the protocol-mandated exact lookup; semantic recall is
        :meth:`semantic_lookup`. Keeping ``read`` exact preserves the contract
        every existing caller and scenario relies on.

        Example::

            val = await mem.read("counter")
        """
        return self._store.get(key)

    async def write(self, key: str, value: bytes) -> None:
        """Write ``value`` for ``key`` and embed the key for semantic recall.

        The value is stored immediately (synchronous dict write) so an
        immediately-following :meth:`read` sees it even if the embedding path
        is still in flight. Subscribers are notified after the embedding lands
        so the stored vector always matches the stored value.

        Example::

            await mem.write("gate", b"A23")
        """
        self._store[key] = value
        self._vectors[key] = self._embed(key)
        await self._notify(key, value)

    async def subscribe(self, key: str) -> AsyncIterator[bytes]:
        """Subscribe to changes for a key.

        Example::

            async for val in mem.subscribe("counter"):
                print(val)
        """
        q: asyncio.Queue[bytes] = asyncio.Queue()
        self._subscribers.setdefault(key, []).append(q)
        try:
            while True:
                yield await q.get()
        finally:
            self._subscribers[key].remove(q)

    async def cas(self, key: str, expected: bytes, new: bytes) -> bool:
        """Compare-and-swap: update only if the current value matches expected.

        On success this performs a full :meth:`write` (which re-embeds the key
        and notifies subscribers), matching the ``blackboard`` CAS contract.

        Example::

            ok = await mem.cas("counter", b"42", b"43")
        """
        if self._store.get(key) == expected:
            await self.write(key, new)
            return True
        return False

    # -- semantic recall --------------------------------------------------

    async def semantic_lookup(self, query: str) -> tuple[str, bytes] | None:
        """Find the stored entry most similar to ``query`` by cosine similarity.

        Ranks every stored key's embedding against the query embedding and
        returns ``(key, value)`` for the best match, or ``None`` if the store
        is empty or no entry clears :data:`_SIMILARITY_FLOOR`. This is the
        capability the default ``blackboard`` plugin cannot provide: finding a
        fact under a different-but-related key.

        Example::

            await mem.write("airport-departure-gate", b"A23")
            hit = await mem.semantic_lookup("flight-boarding-gate")
            assert hit is not None and hit[0] == "airport-departure-gate"
        """
        if not self._store:
            return None
        query_vec = self._embed(query)
        best_key: str | None = None
        best_score = _SIMILARITY_FLOOR
        best_value: bytes | None = None
        for key, value in self._store.items():
            stored = self._vectors.get(key)
            if stored is None:
                continue
            score = _cosine(query_vec, stored)
            if score > best_score:
                best_score = score
                best_key = key
                best_value = value
        if best_key is None or best_value is None:
            return None
        return best_key, best_value

    async def semantic_rank(self, query: str, limit: int = 5) -> list[tuple[str, bytes, float]]:
        """Rank stored entries by similarity to ``query``, descending.

        Returns up to ``limit`` ``(key, value, score)`` triples above the
        similarity floor. Handy for debugging and for agents that want a
        shortlist rather than a single best hit.

        Example::

            ranked = await mem.semantic_rank("gate", limit=3)
        """
        if not self._store:
            return []
        query_vec = self._embed(query)
        scored: list[tuple[str, bytes, float]] = []
        for key, value in self._store.items():
            stored = self._vectors.get(key)
            if stored is None:
                continue
            score = _cosine(query_vec, stored)
            if score > _SIMILARITY_FLOOR:
                scored.append((key, value, score))
        scored.sort(key=lambda t: t[2], reverse=True)
        return scored[:limit]

    # -- internals --------------------------------------------------------

    async def _notify(self, key: str, value: bytes) -> None:
        for q in self._subscribers.get(key, []):
            await q.put(value)
