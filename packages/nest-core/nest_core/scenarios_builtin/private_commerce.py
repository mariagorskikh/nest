# SPDX-License-Identifier: Apache-2.0
"""Private commerce scenario — a four-layer cross-plugin composition.

Every hackathon plugin so far was tested in isolation: gossip registry
against a partition, streaming payments against a drain attack, hybrid
encryption against an eavesdropper, receipt reputation against a collusion
ring. This scenario is the first to run four of them **together** and
instrument the emergent, cross-layer invariants none of the single-layer
validators can see:

1. **Discovery honesty × privacy.** Buyers may only learn sellers through
   gossip that respects the partition; every encrypted bid must be preceded
   by an honest discovery event (``registry`` × ``privacy``).
2. **Bid opacity.** The bid amount travels the wire only inside a hybrid
   X25519 envelope. A ground-truth ``bidmeta:`` sidecar marker lets the
   validator assert the plaintext never leaks (``privacy`` × transport).
3. **Undelivered streams are penalized.** A seller that drains a payment
   stream and never delivers must end with a low receipt-based trust score
   — even when it wash-trades fake receipts with a shill partner
   (``payments`` × ``trust``).
4. **Delivery is rewarded.** Sellers that fulfil their bid end with an
   adequate trust score, and every fulfilment is backed by an earlier
   payment stream (``payments`` × ``trust``).

Cast (12 agents):

* ``buyer-0..4`` — discover sellers via per-agent gossip registries, open a
  payment stream, send a hybrid-encrypted bid, then verify delivery. An
  unfulfilled bid triggers a ``negative:`` report to the auditor.
* ``seller-0..3`` — honest sellers. Register a ``sell`` card, decrypt bids,
  acknowledge delivery, and issue an Ed25519 cross-signed purchase receipt
  co-signed by the buyer. They also settle among themselves in a directed
  cycle of ``payment_received`` receipts, which makes the honest guild a
  strongly-connected anchor for the trust layer's collusion severance.
* ``shill_seller-0`` — the adversary. Registers a ``sell`` card, decrypts
  the bid, drains the stream, never delivers — and covers its tracks by
  wash-trading fake ``purchase`` receipts with ``shill-0``. Under the
  ``score_average`` reference trust plugin the fake receipts *raise* its
  score; under ``agent_receipts`` the isolated mutual pair is severed and it
  collapses to zero. That asymmetry is exactly what validator 3 catches.
* ``shill-0`` — the wash-trading partner. Issues the mirror-image fake
  receipts.
* ``auditor-0`` — owns the single trust-plugin instance, ingests receipts
  and negatives, and emits one ``score:`` line per roster agent at the end.

Trace-marker protocol (all markers are broadcasts, so they are recorded in
the trace at send time and cannot be lost to message drops):

* ``discovered:<buyer>:<seller>`` — first gossip lookup that returned the seller.
* ``bidmeta:<buyer>:<seller>:<ref>:<amount>`` — ground-truth sidecar for the
  opacity validator. Would not exist in production; exists so the validator
  can bind the invariant to a known plaintext.
* ``stream:open:<buyer>:<seller>:<ref>:<rate>`` / ``stream:close:...:<total>``
* ``fulfilled:<seller>:<buyer>:<ref>`` — seller acknowledged delivery.
* ``receipt:<issuer>:<json>`` — receipt en route to the auditor.
* ``negative:<buyer>:<seller>:<ref>`` — buyer reporting non-delivery.
* ``score:<agent>:<score>:<confidence>`` — auditor's final trust scores.

The wire bid itself is ``b"bid:" + envelope`` sent point-to-point; with
``privacy: hybrid_x25519`` the envelope is ciphertext, with ``privacy: noop``
it is plaintext and the opacity validator fails — the charter's adversarial
bar, demonstrated per layer by swapping exactly one YAML line.

Determinism: every agent uses the simulator's seeded RNG and logical clock;
the privacy plugin runs in ``deterministic=True`` mode; receipt identities
derive from ``sha256(agent_id)``. Same seed → byte-identical trace.

Example::

    agents = private_commerce_factory(config, plugins)
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, cast

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentCard, AgentId, Evidence, PaymentRef, Query

GOSSIP_TICK = b"COMMERCE_GOSSIP_TICK"
"""Self-message: run one gossip round."""

DISCOVER_TICK = b"COMMERCE_DISCOVER_TICK"
"""Self-message: attempt a registry lookup and maybe bid."""

CHECK_TICK = b"COMMERCE_CHECK_TICK"
"""Self-message: verify delivery of the outstanding bid."""

FINALIZE_TICK = b"COMMERCE_FINALIZE_TICK"
"""Self-message: auditor scores the roster."""

BID_WIRE_PREFIX = b"bid:"
"""Wire prefix for the (possibly encrypted) bid payload."""

ACK_PREFIX = b"ack:"
"""Wire prefix for the seller's delivery acknowledgement."""

TICK_REDUNDANCY = 5
"""Redundant self-wake-ups per scheduled tick.

``ctx.schedule`` self-deliveries are subject to the simulator's
``message_drop`` rate like any other delivery; five independent wake-ups
drop the chain-death probability per tick to ``0.05 ** 5`` (~3e-7).
"""

SEND_REDUNDANCY = 3
"""Copies of each point-to-point functional message (bid, ack).

Receivers deduplicate by reference, so redundancy is invisible above the
wire. Markers don't need it — broadcasts are traced at send time.
"""

DEFAULT_GOSSIP_INTERVAL = 200.0
DEFAULT_DISCOVER_START = 1000.0
DEFAULT_DISCOVER_EVERY = 500.0
DEFAULT_BID_DEADLINE = 9000.0
DEFAULT_CHECK_DELAY = 1000.0
DEFAULT_FINALIZE_AT = 12000.0
DEFAULT_BID_AMOUNT = 150
DEFAULT_STREAM_RATE = 10
DEFAULT_STREAM_MAX = 500
DEFAULT_INITIAL_BALANCE = 5000

TRUST_THRESHOLD = 0.3
"""Score boundary the joint validators check against.

An honest seller with one corroborated ``purchase`` receipt scores
``1 - exp(-5/10) ≈ 0.39`` under ``agent_receipts``; a severed shill scores
``0.0``; the reference neutral prior is ``0.5``. ``0.3`` separates the
severed adversary from every honest outcome with margin on both sides.
"""


def _seed_for(agent: AgentId) -> bytes:
    """Deterministic 32-byte Ed25519 seed for an agent (matches ``agent_receipts``).

    Example::

        seed = _seed_for(AgentId("seller-0"))
    """
    return hashlib.sha256(str(agent).encode()).digest()[:32]


def _did_for(agent: AgentId) -> str:
    """The receipt identity (hex pubkey) for an agent — matches the trust plugin.

    Example::

        did = _did_for(AgentId("seller-0"))
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from nest_plugins_reference.trust.agent_receipts import did_for_pubkey

    sk = Ed25519PrivateKey.from_private_bytes(_seed_for(agent))
    pub = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return did_for_pubkey(pub)


def _build_receipt(
    issuer: AgentId,
    counterparty: AgentId,
    *,
    receipt_id: str,
    category: str = "purchase",
) -> dict[str, Any]:
    """Build an issuer-signed, counterparty-co-signed receipt.

    Both signatures are genuine — the *fraud* in the shill pair is not forged
    crypto but wash-traded provenance, which is exactly the attack the
    ``agent_receipts`` severance defeats and ``score_average`` rewards.

    Example::

        r = _build_receipt(AgentId("seller-0"), AgentId("buyer-0"), receipt_id="r0")
    """
    from nest_plugins_reference.trust.agent_receipts import cosign_receipt, sign_receipt

    receipt: dict[str, Any] = {
        "receipt_id": receipt_id,
        "issuer_did": _did_for(issuer),
        "action": {"category": category, "counterparty_did": _did_for(counterparty)},
    }
    receipt = sign_receipt(receipt, issuer_seed=_seed_for(issuer))
    return cosign_receipt(receipt, counterparty_seed=_seed_for(counterparty))


class _GossipParticipant(StateMachineAgent):
    """Shared gossip-driving behaviour for all commerce agents.

    Subclasses call :meth:`_start_gossip` in ``on_start`` and
    :meth:`_handle_gossip_or_tick` first in ``on_message``; it returns
    ``True`` when the payload was gossip machinery and is fully consumed.

    Example::

        handled = await self._handle_gossip_or_tick(ctx, sender, payload)
    """

    def __init__(self, agent_id: AgentId, gossip_interval: float) -> None:
        self._id = agent_id
        self._gossip_interval = gossip_interval
        self._last_round_at: float = -1.0

    async def _arm_gossip(self, ctx: AgentContext) -> None:
        for i in range(TICK_REDUNDANCY):
            await ctx.schedule(self._gossip_interval + float(i), GOSSIP_TICK)

    async def _start_gossip(self, ctx: AgentContext, capabilities: list[str]) -> None:
        registry = ctx.plugins.get("registry")
        if registry is not None and hasattr(registry, "register"):
            await registry.register(
                AgentCard(agent_id=self._id, name=str(self._id), capabilities=capabilities)
            )
        await self._arm_gossip(ctx)

    async def _handle_gossip_or_tick(
        self, ctx: AgentContext, sender: AgentId, payload: bytes
    ) -> bool:
        if sender == ctx.agent_id and payload == GOSSIP_TICK:
            if ctx.time - self._last_round_at >= self._gossip_interval:
                self._last_round_at = ctx.time
                registry = ctx.plugins.get("registry")
                if registry is not None and hasattr(registry, "gossip_round"):
                    await registry.gossip_round(ctx)
                await self._arm_gossip(ctx)
            return True
        registry = ctx.plugins.get("registry")
        if registry is not None and hasattr(registry, "handle_gossip"):
            handled = await registry.handle_gossip(sender, payload, ctx)
            if handled:
                return True
        return False


class CommerceBuyer(_GossipParticipant):
    """Discovers a seller via gossip, streams payment, sends an encrypted bid.

    The buyer's target is deterministic: the ``i``-th buyer takes the ``i``-th
    entry of the sorted list of discovered sell-capable cards, so with full
    gossip convergence every buyer-seller pairing is stable across seeds and
    the shill seller is guaranteed exactly one victim.

    Example::

        buyer = CommerceBuyer(AgentId("buyer-0"), index=0, auditor=AgentId("auditor-0"),
                              config={})
    """

    def __init__(
        self,
        agent_id: AgentId,
        *,
        index: int,
        auditor: AgentId,
        config: dict[str, Any],
    ) -> None:
        super().__init__(agent_id, float(config.get("gossip_interval", DEFAULT_GOSSIP_INTERVAL)))
        self._index = index
        self._auditor = auditor
        self._discover_start = float(config.get("discover_start", DEFAULT_DISCOVER_START))
        self._discover_every = float(config.get("discover_every", DEFAULT_DISCOVER_EVERY))
        self._bid_deadline = float(config.get("bid_deadline", DEFAULT_BID_DEADLINE))
        self._check_delay = float(config.get("check_delay", DEFAULT_CHECK_DELAY))
        self._bid_amount = int(config.get("bid_amount", DEFAULT_BID_AMOUNT))
        self._stream_rate = int(config.get("stream_rate", DEFAULT_STREAM_RATE))
        self._stream_max = int(config.get("stream_max", DEFAULT_STREAM_MAX))
        self._expected_sellers = int(config.get("expected_sellers", 5))
        self._announced: set[AgentId] = set()
        self._bid_seller: AgentId | None = None
        self._bid_ref: PaymentRef | None = None
        self._acked = False
        self._closed = False
        self._checked = False

    async def on_start(self, ctx: AgentContext) -> None:
        """Register a buyer card, start gossip, arm the discovery pulses.

        Example::

            await buyer.on_start(ctx)
        """
        await self._start_gossip(ctx, capabilities=["buy"])
        for i in range(TICK_REDUNDANCY):
            await ctx.schedule(self._discover_start + float(i), DISCOVER_TICK)

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Dispatch gossip, discovery pulses, delivery checks, and acks.

        Example::

            await buyer.on_message(ctx, sender, payload)
        """
        if sender == ctx.agent_id and payload == DISCOVER_TICK:
            await self._discover(ctx)
            return
        if sender == ctx.agent_id and payload == CHECK_TICK:
            await self._check_delivery(ctx)
            return
        if payload.startswith(ACK_PREFIX):
            await self._on_ack(ctx, sender, payload)
            return
        await self._handle_gossip_or_tick(ctx, sender, payload)

    async def _discover(self, ctx: AgentContext) -> None:
        """Look up sellers; announce new discoveries; bid when the view is ready."""
        if self._bid_ref is not None:
            return
        registry = ctx.plugins.get("registry")
        if registry is None:
            return
        cards = await registry.lookup(Query(capabilities=["sell"]))
        seller_ids = sorted({card.agent_id for card in cards}, key=str)
        for seller in seller_ids:
            if seller not in self._announced:
                self._announced.add(seller)
                await ctx.broadcast(f"discovered:{self._id}:{seller}".encode())
        ready = len(seller_ids) >= self._expected_sellers
        deadline_passed = ctx.time >= self._bid_deadline
        if seller_ids and (ready or deadline_passed):
            target = seller_ids[self._index % len(seller_ids)]
            await self._place_bid(ctx, target)
            return
        for i in range(TICK_REDUNDANCY):
            await ctx.schedule(self._discover_every + float(i), DISCOVER_TICK)

    async def _place_bid(self, ctx: AgentContext, seller: AgentId) -> None:
        """Open the payment stream and send the encrypted bid."""
        ref = PaymentRef(f"bid-{self._id}")
        self._bid_seller = seller
        self._bid_ref = ref
        payments = ctx.plugins.get("payments")
        if payments is not None and hasattr(payments, "open_stream"):
            await payments.open_stream(
                to=seller, rate_per_tick=self._stream_rate, max_total=self._stream_max, ref=ref
            )
            await ctx.broadcast(
                f"stream:open:{self._id}:{seller}:{ref}:{self._stream_rate}".encode()
            )
        plaintext = f"bidamount:{self._bid_amount}:from:{self._id}:ref:{ref}".encode()
        privacy = ctx.plugins.get("privacy")
        envelope = plaintext
        if privacy is not None and hasattr(privacy, "encrypt"):
            envelope = await privacy.encrypt(plaintext, [seller])
        await ctx.broadcast(f"bidmeta:{self._id}:{seller}:{ref}:{self._bid_amount}".encode())
        for _ in range(SEND_REDUNDANCY):
            await ctx.send(seller, BID_WIRE_PREFIX + envelope)
        for i in range(TICK_REDUNDANCY):
            await ctx.schedule(self._check_delay + float(i), CHECK_TICK)

    async def _on_ack(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Record the seller's delivery ack (deduplicated by ref)."""
        if self._bid_ref is None or sender != self._bid_seller:
            return
        ref = payload[len(ACK_PREFIX) :].decode("utf-8", errors="replace")
        if ref != str(self._bid_ref) or self._acked:
            return
        self._acked = True
        await self._close_stream(ctx)

    async def _check_delivery(self, ctx: AgentContext) -> None:
        """After the check delay: close the stream; report non-delivery."""
        if self._checked or self._bid_ref is None or self._bid_seller is None:
            return
        self._checked = True
        await self._close_stream(ctx)
        if not self._acked:
            for _ in range(SEND_REDUNDANCY):
                await ctx.broadcast(
                    f"negative:{self._id}:{self._bid_seller}:{self._bid_ref}".encode()
                )

    async def _close_stream(self, ctx: AgentContext) -> None:
        if self._closed or self._bid_ref is None or self._bid_seller is None:
            return
        self._closed = True
        payments = ctx.plugins.get("payments")
        total = 0
        if payments is not None and hasattr(payments, "close_stream"):
            receipt = await payments.close_stream(self._bid_ref)
            total = int(receipt.amount.amount)
        await ctx.broadcast(
            f"stream:close:{self._id}:{self._bid_seller}:{self._bid_ref}:{total}".encode()
        )


class CommerceSeller(_GossipParticipant):
    """Honest seller: decrypts bids, acknowledges delivery, issues receipts.

    On start it also submits its pre-built guild settlement receipt (the
    directed honest cycle) so the honest sellers form one strongly-connected
    anchor for collusion severance.

    Example::

        seller = CommerceSeller(AgentId("seller-0"), auditor=AgentId("auditor-0"),
                                cycle_receipts=[], config={})
    """

    def __init__(
        self,
        agent_id: AgentId,
        *,
        auditor: AgentId,
        cycle_receipts: list[dict[str, Any]],
        config: dict[str, Any],
    ) -> None:
        super().__init__(agent_id, float(config.get("gossip_interval", DEFAULT_GOSSIP_INTERVAL)))
        self._auditor = auditor
        self._cycle_receipts = cycle_receipts
        self._fulfilled_refs: set[str] = set()

    async def on_start(self, ctx: AgentContext) -> None:
        """Register the sell card, start gossip, submit guild receipts.

        Example::

            await seller.on_start(ctx)
        """
        await self._start_gossip(ctx, capabilities=["sell"])
        for receipt in self._cycle_receipts:
            for _ in range(SEND_REDUNDANCY):
                await ctx.broadcast(f"receipt:{self._id}:{json.dumps(receipt)}".encode())

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Decrypt bids, fulfil them, and emit cross-signed purchase receipts.

        Example::

            await seller.on_message(ctx, buyer, b"bid:...")
        """
        if payload.startswith(BID_WIRE_PREFIX):
            await self._on_bid(ctx, sender, payload[len(BID_WIRE_PREFIX) :])
            return
        await self._handle_gossip_or_tick(ctx, sender, payload)

    async def _on_bid(self, ctx: AgentContext, buyer: AgentId, envelope: bytes) -> None:
        plaintext = await self._open_envelope(ctx, envelope)
        if plaintext is None:
            return
        ref = self._parse_ref(plaintext)
        if ref is None or ref in self._fulfilled_refs:
            return
        self._fulfilled_refs.add(ref)
        for _ in range(SEND_REDUNDANCY):
            await ctx.send(buyer, ACK_PREFIX + ref.encode())
        await ctx.broadcast(f"fulfilled:{self._id}:{buyer}:{ref}".encode())
        receipt = _build_receipt(
            self._id, buyer, receipt_id=f"purchase-{self._id}-{ref}", category="purchase"
        )
        for _ in range(SEND_REDUNDANCY):
            await ctx.broadcast(f"receipt:{self._id}:{json.dumps(receipt)}".encode())

    async def _open_envelope(self, ctx: AgentContext, envelope: bytes) -> bytes | None:
        privacy = ctx.plugins.get("privacy")
        if privacy is None or not hasattr(privacy, "decrypt"):
            return envelope
        try:
            return await privacy.decrypt(envelope)
        except Exception:  # noqa: BLE001 - replayed/foreign envelopes are dropped
            return None

    @staticmethod
    def _parse_ref(plaintext: bytes) -> str | None:
        parts = plaintext.decode("utf-8", errors="replace").split(":")
        # bidamount:<amount>:from:<buyer>:ref:<ref>
        if len(parts) >= 6 and parts[0] == "bidamount" and parts[4] == "ref":
            return parts[5]
        return None


class ShillSeller(CommerceSeller):
    """The adversary: drains the stream, never delivers, wash-trades cover.

    Inherits the honest seller's discovery surface (it *looks* legitimate on
    the registry) but overrides fulfilment: it decrypts the bid, keeps the
    stream money, sends no ack and no genuine receipt. Its fake receipts —
    mutually co-signed with ``shill-0`` — are submitted on start.

    Example::

        shill = ShillSeller(AgentId("shill_seller-0"), auditor=AgentId("auditor-0"),
                            cycle_receipts=fake_receipts, config={})
    """

    async def _on_bid(self, ctx: AgentContext, buyer: AgentId, envelope: bytes) -> None:
        plaintext = await self._open_envelope(ctx, envelope)
        if plaintext is None:
            return
        # Take the money and run: no ack, no fulfilment marker, no receipt.
        return


class ShillAccomplice(_GossipParticipant):
    """Wash-trading partner: submits the mirror-image fake receipts on start.

    Registers a card without the ``sell`` capability so buyers never target
    it; its only job is to complete the mutual co-signature loop that makes
    the fake receipts individually corroborated.

    Example::

        accomplice = ShillAccomplice(AgentId("shill-0"), fake_receipts=[],
                                     gossip_interval=200.0)
    """

    def __init__(
        self,
        agent_id: AgentId,
        *,
        fake_receipts: list[dict[str, Any]],
        gossip_interval: float,
    ) -> None:
        super().__init__(agent_id, gossip_interval)
        self._fake_receipts = fake_receipts

    async def on_start(self, ctx: AgentContext) -> None:
        """Register a non-sell card and submit the fake receipts.

        Example::

            await accomplice.on_start(ctx)
        """
        await self._start_gossip(ctx, capabilities=["shill"])
        for receipt in self._fake_receipts:
            for _ in range(SEND_REDUNDANCY):
                await ctx.broadcast(f"receipt:{self._id}:{json.dumps(receipt)}".encode())

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Only gossip machinery; the accomplice ignores everything else.

        Example::

            await accomplice.on_message(ctx, sender, payload)
        """
        await self._handle_gossip_or_tick(ctx, sender, payload)


class CommerceAuditor(StateMachineAgent):
    """Owns the single trust instance; ingests receipts; scores the roster.

    Receipt broadcasts are deduplicated by ``receipt_id`` and negatives by
    payment ref, so the senders' drop-redundancy never double-reports.

    Example::

        auditor = CommerceAuditor(AgentId("auditor-0"), roster=[], config={})
    """

    def __init__(
        self,
        agent_id: AgentId,
        *,
        roster: list[AgentId],
        config: dict[str, Any],
    ) -> None:
        self._id = agent_id
        self._roster = roster
        self._finalize_at = float(config.get("finalize_at", DEFAULT_FINALIZE_AT))
        self._trust: Any = None
        self._seen_receipts: set[str] = set()
        self._seen_negatives: set[str] = set()
        self._finalized = False

    async def on_start(self, ctx: AgentContext) -> None:
        """Instantiate the configured trust plugin and arm the finalize pulse.

        Example::

            await auditor.on_start(ctx)
        """
        trust_cls = ctx.plugins.get("trust")
        self._trust = trust_cls() if isinstance(trust_cls, type) else trust_cls
        for i in range(TICK_REDUNDANCY):
            await ctx.schedule(self._finalize_at + float(i), FINALIZE_TICK)

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        """Ingest receipts and negatives; score everyone on the finalize pulse.

        Example::

            await auditor.on_message(ctx, seller, b"receipt:seller-0:{...}")
        """
        if sender == ctx.agent_id and payload == FINALIZE_TICK:
            await self._finalize(ctx)
            return
        msg = payload.decode("utf-8", errors="replace")
        if msg.startswith("receipt:"):
            await self._ingest_receipt(msg)
            return
        if msg.startswith("negative:"):
            await self._ingest_negative(msg)

    async def _ingest_receipt(self, msg: str) -> None:
        if self._trust is None:
            return
        _, issuer, receipt_json = msg.split(":", 2)
        try:
            parsed: object = json.loads(receipt_json)
        except json.JSONDecodeError:
            return
        if not isinstance(parsed, dict):
            return
        receipt_dict = cast("dict[str, Any]", parsed)
        receipt_id = str(receipt_dict.get("receipt_id", ""))
        if not receipt_id or receipt_id in self._seen_receipts:
            return
        self._seen_receipts.add(receipt_id)
        await self._trust.report(
            AgentId(issuer),
            Evidence(
                reporter=self._id, subject=AgentId(issuer), kind="positive", detail=receipt_json
            ),
        )

    async def _ingest_negative(self, msg: str) -> None:
        if self._trust is None:
            return
        parts = msg.split(":")
        # negative:<buyer>:<seller>:<ref>
        if len(parts) < 4:
            return
        _, buyer, seller, ref = parts[:4]
        if ref in self._seen_negatives:
            return
        self._seen_negatives.add(ref)
        await self._trust.report(
            AgentId(seller),
            Evidence(
                reporter=AgentId(buyer),
                subject=AgentId(seller),
                kind="negative",
                detail=f"undelivered:{ref}",
            ),
        )

    async def _finalize(self, ctx: AgentContext) -> None:
        """Emit one ``score:`` line per roster agent (idempotent)."""
        if self._finalized or self._trust is None:
            return
        self._finalized = True
        for agent in sorted(self._roster, key=str):
            rep = await self._trust.score(agent)
            await ctx.broadcast(f"score:{agent}:{rep.score:.6f}:{rep.confidence:.6f}".encode())


def _role_ids(config: ScenarioConfig, role_name: str) -> list[AgentId]:
    """All agent ids for a role, in index order.

    Example::

        buyers = _role_ids(config, "buyer")
    """
    for role in config.agents.roles:
        if role.name == role_name:
            return [AgentId(f"{role_name}-{i}") for i in range(role.count)]
    return []


def private_commerce_factory(config: ScenarioConfig, plugins: dict[str, Any]) -> dict[AgentId, Any]:
    """Build the twelve-agent private-commerce fleet with per-agent plugin wiring.

    Per-agent instances are injected through the runner's ``_agent_plugins``
    override channel: gossip registries share one :class:`GossipNetwork`
    (or one shared ``InMemoryRegistry`` when the YAML says ``registry:
    in_memory`` — the adversarial leak configuration), streaming-payment
    ledgers are per-buyer, and hybrid-privacy keypairs are cross-registered
    so any agent can wrap to any other.

    Example::

        agents = private_commerce_factory(config, plugins)
    """
    task_cfg: dict[str, Any] = config.task.config or {}
    gossip_interval = float(task_cfg.get("gossip_interval", DEFAULT_GOSSIP_INTERVAL))
    initial_balance = int(task_cfg.get("initial_balance", DEFAULT_INITIAL_BALANCE))

    buyers = _role_ids(config, "buyer")
    sellers = _role_ids(config, "seller")
    shill_sellers = _role_ids(config, "shill_seller")
    shills = _role_ids(config, "shill")
    auditors = _role_ids(config, "auditor")
    auditor = auditors[0] if auditors else AgentId("auditor-0")

    gossip_ids = [*buyers, *sellers, *shill_sellers, *shills]
    all_ids = [*gossip_ids, auditor]
    task_cfg.setdefault("expected_sellers", len(sellers) + len(shill_sellers))

    overrides: dict[AgentId, dict[str, Any]] = {aid: {} for aid in all_ids}

    # -- registry: per-agent gossip views, or one shared dict (adversarial) --
    if config.layers.registry == "gossip":
        from nest_plugins_reference.registry.gossip import GossipNetwork, GossipRegistry

        network = GossipNetwork(agent_ids=list(gossip_ids))
        for aid in gossip_ids:
            overrides[aid]["registry"] = GossipRegistry(aid, network)
    else:
        from nest_plugins_reference.registry.in_memory import InMemoryRegistry

        shared_registry = InMemoryRegistry()
        for aid in gossip_ids:
            overrides[aid]["registry"] = shared_registry

    # -- privacy: per-agent keypairs with a fully cross-registered directory --
    if config.layers.privacy == "hybrid_x25519":
        from nest_plugins_reference.privacy.hybrid_x25519 import HybridX25519Privacy

        privacy_instances = {
            aid: HybridX25519Privacy(aid, seed=str(aid).encode(), deterministic=True)
            for aid in all_ids
        }
        for aid, instance in privacy_instances.items():
            for peer, peer_instance in privacy_instances.items():
                if peer != aid:
                    instance.register_peer(peer, peer_instance.public_key)
            overrides[aid]["privacy"] = instance
    else:
        from nest_plugins_reference.privacy.noop import NoopPrivacy

        for aid in all_ids:
            overrides[aid]["privacy"] = NoopPrivacy()

    # -- payments: per-buyer streaming ledgers --
    from nest_plugins_reference.payments.streaming import StreamingPayments

    for aid in buyers:
        overrides[aid]["payments"] = StreamingPayments(aid, initial_balance=initial_balance)

    # -- receipts: honest guild cycle + wash-traded shill pair --
    cycle_receipts: dict[AgentId, list[dict[str, Any]]] = {aid: [] for aid in sellers}
    for i, seller in enumerate(sellers):
        nxt = sellers[(i + 1) % len(sellers)]
        cycle_receipts[seller].append(
            _build_receipt(
                seller, nxt, receipt_id=f"guild-{seller}-{nxt}", category="payment_received"
            )
        )

    fake_by_shill_seller: dict[AgentId, list[dict[str, Any]]] = {}
    fake_by_shill: dict[AgentId, list[dict[str, Any]]] = {}
    for shill_seller, shill in zip(shill_sellers, shills, strict=False):
        fake_by_shill_seller[shill_seller] = [
            _build_receipt(
                shill_seller, shill, receipt_id=f"wash-{shill_seller}-{k}", category="purchase"
            )
            for k in range(3)
        ]
        fake_by_shill[shill] = [
            _build_receipt(shill, shill_seller, receipt_id=f"wash-{shill}-{k}", category="purchase")
            for k in range(3)
        ]

    # -- assemble agents --
    agents: dict[AgentId, Any] = {}
    for i, aid in enumerate(buyers):
        agents[aid] = CommerceBuyer(aid, index=i, auditor=auditor, config=task_cfg)
    for aid in sellers:
        agents[aid] = CommerceSeller(
            aid, auditor=auditor, cycle_receipts=cycle_receipts[aid], config=task_cfg
        )
    for aid in shill_sellers:
        agents[aid] = ShillSeller(
            aid, auditor=auditor, cycle_receipts=fake_by_shill_seller.get(aid, []), config=task_cfg
        )
    for aid in shills:
        agents[aid] = ShillAccomplice(
            aid, fake_receipts=fake_by_shill.get(aid, []), gossip_interval=gossip_interval
        )
    agents[auditor] = CommerceAuditor(
        auditor, roster=[*sellers, *shill_sellers, *shills], config=task_cfg
    )

    plugins["_agent_plugins"] = overrides
    return agents
