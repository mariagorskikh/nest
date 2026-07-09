# SPDX-License-Identifier: Apache-2.0
"""Shared types used across all Nanda Town layers and plugins.

Example::

    from nest_core.types import AgentId, Message, Money
    agent = AgentId("agent-42")
    msg = Message(sender=agent, receiver=AgentId("agent-7"), payload=b"hello")
"""

from __future__ import annotations

import enum
from datetime import datetime
from typing import Any, NewType

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Scalar identifiers
# ---------------------------------------------------------------------------

AgentId = NewType("AgentId", str)
"""Unique identifier for an agent within a simulation run.

Example::

    agent = AgentId("buyer-01")
"""

MessageId = NewType("MessageId", str)
"""Unique identifier for a single message."""

CorrelationId = NewType("CorrelationId", str)
"""Identifier that links related events across layers."""

PaymentRef = NewType("PaymentRef", str)
"""Reference handle for a payment transaction."""

DataFactsUrl = NewType("DataFactsUrl", str)
"""URL pointing to a DataFacts metadata record."""

ServiceRef = NewType("ServiceRef", str)
"""Reference to a service offered by an agent."""


# ---------------------------------------------------------------------------
# Core data models
# ---------------------------------------------------------------------------


class Message(BaseModel):
    """A message exchanged between two agents.

    Example::

        msg = Message(
            id=MessageId("m1"), sender=AgentId("a1"),
            receiver=AgentId("a2"), payload=b"hi",
        )
    """

    id: MessageId
    sender: AgentId
    receiver: AgentId
    payload: bytes
    correlation_id: CorrelationId | None = None
    timestamp: float | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class AgentCard(BaseModel):
    """Public profile of an agent, used for discovery and capability advertisement.

    Example::

        card = AgentCard(agent_id=AgentId("a1"), name="DataSeller", capabilities=["sell_data"])
    """

    agent_id: AgentId
    name: str
    capabilities: list[str] = Field(default_factory=list)
    endpoint: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class Query(BaseModel):
    """A query for discovering agents via a registry.

    Example::

        q = Query(capabilities=["sell_data"])
    """

    capabilities: list[str] = Field(default_factory=list)
    name_pattern: str | None = None
    metadata_filter: dict[str, Any] = Field(default_factory=dict)


class Money(BaseModel):
    """A monetary amount with currency.

    Example::

        price = Money(amount=100, currency="credits")
    """

    amount: int
    currency: str = "credits"


class Quote(BaseModel):
    """A price quote for a service.

    Example::

        quote = Quote(service=ServiceRef("svc-1"), price=Money(amount=50), ttl_seconds=300)
    """

    service: ServiceRef
    price: Money
    ttl_seconds: int = 300
    metadata: dict[str, Any] = Field(default_factory=dict)


class Receipt(BaseModel):
    """Proof that a payment was made.

    Example::

        receipt = Receipt(
            ref=PaymentRef("pay-1"), payer=AgentId("a1"),
            payee=AgentId("a2"), amount=Money(amount=50),
        )
    """

    ref: PaymentRef
    payer: AgentId
    payee: AgentId
    amount: Money
    timestamp: float | None = None


class PaymentStatus(enum.Enum):
    """Status of a payment transaction.

    Example::

        status = PaymentStatus.CONFIRMED
    """

    PENDING = "pending"
    CONFIRMED = "confirmed"
    STREAMING = "streaming"
    FAILED = "failed"
    REFUNDED = "refunded"


class Response(BaseModel):
    """A response to a communication request.

    Example::

        resp = Response(success=True, payload=b"ok")
    """

    success: bool
    payload: bytes = b""
    error: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Identity types
# ---------------------------------------------------------------------------


class Signature(BaseModel):
    """A cryptographic signature over a payload.

    ``key_id`` and ``signed_at`` are optional so existing callers (e.g.
    ``did_key``, which has no key rotation) and existing ``Signature`` consumers
    such as :class:`Attestation` keep working unchanged. They are populated by
    rotating-identity plugins:

    - ``key_id`` binds the signature to the specific public key that produced
      it, enabling verification *as-of* the key's validity window even after the
      signer has rotated to a newer key.
    - ``signed_at`` is the logical tick the signer *claims* to have signed at.
      It is **advisory audit metadata only**: a verifier must never use it as
      the as-of authority (an attacker controls it), and instead anchors
      verification to an externally observed tick. See
      ``nest_plugins_reference.identity.ed25519_rotating``.

    Example::

        sig = Signature(signer=AgentId("a1"), value=b"sig-bytes", algorithm="ed25519")
        rotated = Signature(
            signer=AgentId("a1"), value=b"sig", algorithm="ed25519-rotating/1",
            key_id="3b1f...", signed_at=42.0,
        )
    """

    signer: AgentId
    value: bytes
    algorithm: str = "ed25519"
    key_id: str | None = None
    signed_at: float | None = None


class AgentIdentity(BaseModel):
    """Resolved identity information for an agent.

    Example::

        identity = AgentIdentity(agent_id=AgentId("a1"), public_key=b"pk", method="did:key")
    """

    agent_id: AgentId
    public_key: bytes
    method: str = "did:key"
    metadata: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Auth types
# ---------------------------------------------------------------------------

Token = NewType("Token", str)
"""An opaque authentication/authorization token.

Example::

    token = Token("eyJhbGciOi...")
"""


class AuthContext(BaseModel):
    """Verified authentication context extracted from a token.

    Example::

        ctx = AuthContext(subject=AgentId("a1"), scopes=["read", "write"])
    """

    subject: AgentId
    scopes: list[str] = Field(default_factory=list)
    issued_at: float | None = None
    expires_at: float | None = None


# ---------------------------------------------------------------------------
# Trust types
# ---------------------------------------------------------------------------


class ReputationScore(BaseModel):
    """Reputation score for an agent.

    Example::

        score = ReputationScore(agent_id=AgentId("a1"), score=0.85, confidence=0.9, sample_count=42)
    """

    agent_id: AgentId
    score: float
    confidence: float = 0.0
    sample_count: int = 0


class Claim(BaseModel):
    """An attestation claim about an agent.

    Example::

        claim = Claim(subject=AgentId("a1"), predicate="completed_task", value="task-99")
    """

    subject: AgentId
    predicate: str
    value: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class Attestation(BaseModel):
    """A signed attestation by one agent about another.

    Example::

        att = Attestation(issuer=AgentId("a2"), claim=claim, signature=sig)
    """

    issuer: AgentId
    claim: Claim
    signature: Signature
    timestamp: float | None = None


class Evidence(BaseModel):
    """Evidence of misbehavior for trust reporting.

    Example::

        ev = Evidence(
            reporter=AgentId("a1"), subject=AgentId("a2"),
            kind="byzantine", detail="sent garbage",
        )
    """

    reporter: AgentId
    subject: AgentId
    kind: str
    detail: str = ""
    timestamp: float | None = None


# ---------------------------------------------------------------------------
# Coordination types
# ---------------------------------------------------------------------------


class Task(BaseModel):
    """A task proposed for group coordination.

    Example::

        task = Task(id="task-1", description="Process dataset X", requirements=["gpu"])
    """

    id: str
    description: str
    requirements: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class Round(BaseModel):
    """A coordination round (e.g., an auction or vote).

    Example::

        rnd = Round(id="round-1", task=task, participants=[AgentId("a1")])
    """

    id: str
    task: Task
    participants: list[AgentId] = Field(default_factory=lambda: list[AgentId]())
    metadata: dict[str, Any] = Field(default_factory=dict)


class Vote(BaseModel):
    """A vote cast in a coordination round.

    Example::

        vote = Vote(voter=AgentId("a1"), round_id="round-1", value="yes")
    """

    voter: AgentId
    round_id: str
    value: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class Bid(BaseModel):
    """A bid in an auction-style coordination round.

    Example::

        bid = Bid(bidder=AgentId("a1"), round_id="round-1", amount=Money(amount=100))
    """

    bidder: AgentId
    round_id: str
    amount: Money
    metadata: dict[str, Any] = Field(default_factory=dict)


class Outcome(BaseModel):
    """The resolved outcome of a coordination round.

    Example::

        outcome = Outcome(round_id="round-1", winner=AgentId("a1"), task=task)
    """

    round_id: str
    winner: AgentId | None = None
    task: Task
    metadata: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Negotiation types
# ---------------------------------------------------------------------------


class Terms(BaseModel):
    """Terms proposed or counter-proposed during negotiation.

    Example::

        terms = Terms(price=Money(amount=50), conditions={"delivery": "immediate"})
    """

    price: Money | None = None
    conditions: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


class NegotiationStatus(enum.Enum):
    """Status of a negotiation session.

    Example::

        status = NegotiationStatus.OPEN
    """

    OPEN = "open"
    AGREED = "agreed"
    REJECTED = "rejected"
    EXPIRED = "expired"


class NegotiationSession(BaseModel):
    """An active negotiation session between agents.

    Example::

        session = NegotiationSession(id="neg-1", initiator=AgentId("a1"), partner=AgentId("a2"))
    """

    id: str
    initiator: AgentId
    partner: AgentId
    status: NegotiationStatus = NegotiationStatus.OPEN
    current_terms: Terms | None = None
    history: list[Terms] = Field(default_factory=lambda: list[Terms]())


class NegotiationResponse(BaseModel):
    """Response to a negotiation offer.

    Example::

        resp = NegotiationResponse(accepted=False, counter_terms=Terms(price=Money(amount=40)))
    """

    accepted: bool
    counter_terms: Terms | None = None


class Agreement(BaseModel):
    """A finalized agreement from a negotiation.

    Example::

        agreement = Agreement(
            session_id="neg-1", terms=terms,
            parties=[AgentId("a1"), AgentId("a2")],
        )
    """

    session_id: str
    terms: Terms
    parties: list[AgentId]
    timestamp: float | None = None


# ---------------------------------------------------------------------------
# Privacy types
# ---------------------------------------------------------------------------


class Statement(BaseModel):
    """A statement to be proven in zero-knowledge.

    Example::

        stmt = Statement(predicate="balance_gte", public_inputs={"threshold": "100"})
    """

    predicate: str
    public_inputs: dict[str, str] = Field(default_factory=dict)


class Witness(BaseModel):
    """Private witness data for a zero-knowledge proof.

    Example::

        witness = Witness(private_inputs={"balance": "500"})
    """

    private_inputs: dict[str, str] = Field(default_factory=dict)


class Proof(BaseModel):
    """A zero-knowledge proof.

    Example::

        proof = Proof(statement=stmt, data=b"proof-bytes", scheme="mock_zkp")
    """

    statement: Statement
    data: bytes
    scheme: str = "mock_zkp"


# ---------------------------------------------------------------------------
# DataFacts types
# ---------------------------------------------------------------------------


class DatasetMetadata(BaseModel):
    """Metadata about a dataset published via DataFacts.

    Example::

        meta = DatasetMetadata(name="weather-2024", owner=AgentId("a1"), schema_version="1.0")
    """

    name: str
    owner: AgentId
    description: str = ""
    schema_version: str = "1.0"
    created_at: datetime | None = None
    updated_at: datetime | None = None
    tags: list[str] = Field(default_factory=list)
    size_bytes: int | None = None
    checksum: str | None = None
    access_tier: str = "public"
    metadata: dict[str, Any] = Field(default_factory=dict)


class AccessGrant(BaseModel):
    """Grant of access to a dataset.

    Example::

        grant = AccessGrant(url=DataFactsUrl("df://weather"), grantee=AgentId("a2"), tier="read")
    """

    url: DataFactsUrl
    grantee: AgentId
    tier: str = "read"
    expires_at: float | None = None


# ---------------------------------------------------------------------------
# Failure detection
# ---------------------------------------------------------------------------


class Suspicion(BaseModel):
    """A failure detector's verdict about a single peer at a point in time.

    ``phi`` is the accrual suspicion level (higher means more suspicious); for
    a fixed-timeout detector it is the elapsed/timeout ratio.  ``suspected`` is
    the thresholded boolean verdict.  ``last_heartbeat`` is the logical time of
    the most recent heartbeat observed from the peer, or ``None`` if none has
    been seen yet.

    Example::

        s = Suspicion(peer=AgentId("peer-1"), suspected=True, phi=8.5)
    """

    peer: AgentId
    suspected: bool
    phi: float
    last_heartbeat: float | None = None
    observed_at: float = 0.0


# ---------------------------------------------------------------------------
# Transport capabilities
# ---------------------------------------------------------------------------


class TransportCapabilities(BaseModel):
    """Declared capabilities of a transport plugin.

    Example::

        caps = TransportCapabilities(supports_streaming=True, ordered=True, reliable=True)
    """

    supports_streaming: bool = False
    ordered: bool = True
    reliable: bool = True
    max_payload_bytes: int | None = None
