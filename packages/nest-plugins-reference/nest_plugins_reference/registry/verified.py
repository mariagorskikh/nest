# SPDX-License-Identifier: Apache-2.0
"""Signature-verified registry plugin — registration requires proof of identity.

The default ``in_memory`` registry and the reference ``gossip`` registry
believe anyone: ``register(card)`` stores whatever ``AgentCard`` it is handed.
Any agent can register a card carrying **another agent's**
``agent_id`` — silently overwriting the victim's card and poisoning every
subsequent ``lookup`` — or advertise capabilities it never proved it holds.

``VerifiedRegistry`` closes that gap by routing registration through the
identity layer.  A card is admitted only when its metadata carries a
signature, by the card's own ``agent_id``, over the card's canonical bytes:

* **missing signature** → rejected (``missing_signature``),
* **signature by someone other than the claimed** ``agent_id`` → rejected
  (``signer_mismatch``) — the impersonation case,
* **signature that does not verify over the canonical card** → rejected
  (``bad_signature``) — covers forged signature values, unknown signers, and
  cards mutated after signing (capability forgery).

Rejections raise :class:`RegistrationRejectedError` with a typed ``reason`` so
scenarios and validators can assert *why* a registration was refused, not
just that it was.  Accepted cards behave exactly like ``in_memory``:
dict-backed ``lookup``/``subscribe``/``deregister``.

Verification is delegated to any ``Identity``-layer plugin (``did_key``,
``ed25519_rotating``, ...) — this plugin implements no cryptography of its
own.  ``sign_card`` passes through ``key_id``/``signed_at`` when the identity
plugin provides them, so rotating identities compose without changes here.

Known residual (deliberate, documented): the ``Registry`` protocol's
``deregister(agent)`` carries no authentication material, so eviction is not
authenticated — fixing that requires a protocol change, which is outside a
single plugin's scope.

Example::

    verifier = DidKeyIdentity(AgentId("verifier"), seed=b"s")
    verifier.register_peer(AgentId("a1"), a1_identity.public_key)
    registry = VerifiedRegistry(verifier)
    await registry.register(sign_card(card, a1_identity))
"""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING, cast

from nest_core.types import AgentCard, AgentId, Query, Signature

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from nest_core.layers.identity import Identity

REASON_MISSING_SIGNATURE = "missing_signature"
"""Rejection reason: the card carries no (or a malformed) signature record."""

REASON_SIGNER_MISMATCH = "signer_mismatch"
"""Rejection reason: the signature's signer is not the card's ``agent_id``."""

REASON_BAD_SIGNATURE = "bad_signature"
"""Rejection reason: the signature does not verify over the canonical card."""

_SIGNATURE_KEY = "signature"


class RegistrationRejectedError(Exception):
    """A registration was refused by :class:`VerifiedRegistry`.

    ``reason`` is one of the module-level ``REASON_*`` constants; ``detail``
    is a human-readable elaboration.

    Example::

        try:
            await registry.register(card)
        except RegistrationRejectedError as exc:
            print(exc.reason, exc.detail)
    """

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


def canonical_card_bytes(card: AgentCard) -> bytes:
    """Deterministic byte encoding of the card fields covered by the signature.

    Covers ``agent_id``, ``name``, ``capabilities`` (order-independent), and
    ``endpoint``.  ``metadata`` is deliberately excluded — the signature
    itself rides there.  Sorted keys and fixed separators make the encoding
    byte-stable across runs.

    Example::

        payload = canonical_card_bytes(card)
    """
    payload = {
        "agent_id": str(card.agent_id),
        "name": card.name,
        "capabilities": sorted(card.capabilities),
        "endpoint": card.endpoint,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_card(card: AgentCard, identity: Identity) -> AgentCard:
    """Return a copy of ``card`` carrying the signer's signature in its metadata.

    The signature is produced by ``identity.sign`` over
    :func:`canonical_card_bytes` and stored as a JSON-safe dict under
    ``metadata["signature"]``.  Optional ``key_id``/``signed_at`` fields from
    rotating identity plugins are passed through when present.

    Example::

        signed = sign_card(card, my_identity)
        await registry.register(signed)
    """
    sig = identity.sign(canonical_card_bytes(card))
    record: dict[str, str | float] = {
        "signer": str(sig.signer),
        "value": sig.value.hex(),
        "algorithm": sig.algorithm,
    }
    if sig.key_id is not None:
        record["key_id"] = sig.key_id
    if sig.signed_at is not None:
        record["signed_at"] = sig.signed_at
    signed = card.model_copy(deep=True)
    signed.metadata[_SIGNATURE_KEY] = record
    return signed


def _extract_signature(card: AgentCard) -> Signature:
    """Reconstruct the ``Signature`` from a card's metadata or reject.

    Example::

        sig = _extract_signature(card)
    """
    raw = card.metadata.get(_SIGNATURE_KEY)
    if not isinstance(raw, dict):
        raise RegistrationRejectedError(REASON_MISSING_SIGNATURE, "no signature record in metadata")
    sig_dict = cast("dict[str, object]", raw)
    signer: object = sig_dict.get("signer")
    value: object = sig_dict.get("value")
    algorithm: object = sig_dict.get("algorithm")
    if not (isinstance(signer, str) and isinstance(value, str) and isinstance(algorithm, str)):
        raise RegistrationRejectedError(REASON_MISSING_SIGNATURE, "malformed signature record")
    try:
        sig_bytes = bytes.fromhex(value)
    except ValueError as exc:
        raise RegistrationRejectedError(
            REASON_MISSING_SIGNATURE, "signature value is not valid hex"
        ) from exc
    key_id: object = sig_dict.get("key_id")
    signed_at: object = sig_dict.get("signed_at")
    return Signature(
        signer=AgentId(signer),
        value=sig_bytes,
        algorithm=algorithm,
        key_id=key_id if isinstance(key_id, str) else None,
        signed_at=float(signed_at) if isinstance(signed_at, int | float) else None,
    )


class VerifiedRegistry:
    """Dictionary-backed registry that admits only identity-signed cards.

    Implements the ``Registry`` protocol but requires an ``Identity`` verifier
    at construction time. ``register`` verifies; ``lookup``, ``subscribe``,
    and ``deregister`` behave like ``in_memory``. Rejected registrations mutate
    nothing: no card is stored and no subscriber is notified. This plugin does
    not replicate cards or validate gossip traffic.

    Example::

        registry = VerifiedRegistry(verifier)
        await registry.register(sign_card(card, identity))
        results = await registry.lookup(Query(capabilities=["sell"]))
    """

    def __init__(self, verifier: Identity) -> None:
        self._verifier = verifier
        self._cards: dict[AgentId, AgentCard] = {}
        self._subscribers: list[asyncio.Queue[AgentCard]] = []

    async def register(self, card: AgentCard) -> None:
        """Admit ``card`` iff it carries a valid signature by its own ``agent_id``.

        Raises :class:`RegistrationRejectedError` with a typed reason otherwise.

        Example::

            await registry.register(sign_card(card, identity))
        """
        sig = _extract_signature(card)
        if sig.signer != card.agent_id:
            raise RegistrationRejectedError(
                REASON_SIGNER_MISMATCH,
                f"card claims {card.agent_id!r} but signature is by {sig.signer!r}",
            )
        if not self._verifier.verify(canonical_card_bytes(card), sig, card.agent_id):
            raise RegistrationRejectedError(
                REASON_BAD_SIGNATURE,
                f"signature by {sig.signer!r} does not verify over the canonical card",
            )
        self._cards[card.agent_id] = card
        for q in self._subscribers:
            await q.put(card)

    async def lookup(self, query: Query) -> list[AgentCard]:
        """Look up admitted agents matching a query.

        Example::

            results = await registry.lookup(Query(capabilities=["sell"]))
        """
        return [card for card in self._cards.values() if self._matches(card, query)]

    async def subscribe(self, query: Query) -> AsyncIterator[AgentCard]:
        """Subscribe to newly *admitted* registrations matching a query.

        Rejected registrations never reach subscribers.

        Example::

            async for card in registry.subscribe(query):
                print(card.name)
        """
        q: asyncio.Queue[AgentCard] = asyncio.Queue()
        self._subscribers.append(q)
        try:
            while True:
                card = await q.get()
                if self._matches(card, query):
                    yield card
        finally:
            self._subscribers.remove(q)

    async def deregister(self, agent: AgentId) -> None:
        """Remove an agent from the registry (unauthenticated — see module docs).

        Example::

            await registry.deregister(AgentId("a1"))
        """
        self._cards.pop(agent, None)

    @staticmethod
    def _matches(card: AgentCard, query: Query) -> bool:
        if query.capabilities and not all(cap in card.capabilities for cap in query.capabilities):
            return False
        return not (query.name_pattern and query.name_pattern not in card.name)
