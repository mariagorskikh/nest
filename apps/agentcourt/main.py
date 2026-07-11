# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nanda Town Authors

"""
AgentCourt: A decentralized agent escrow and dispute resolution service.
"""

from __future__ import annotations

import logging
import os
import time
import uuid
from enum import StrEnum
from threading import Lock

from fastapi import FastAPI, HTTPException, status
from fastapi.responses import PlainTextResponse, RedirectResponse
from pydantic import BaseModel, Field, field_validator

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("agentcourt")

app = FastAPI(
    title="AgentCourt API",
    description="A decentralized escrow and dispute arbitration service for AI agents.",
    version="1.0.0",
)

# Thread-safe in-memory databases
db_lock = Lock()
escrow_db: dict[str, Escrow] = {}
dispute_db: dict[str, Dispute] = {}


class EscrowStatus(StrEnum):
    HELD = "HELD"
    RELEASED = "RELEASED"
    REFUNDED = "REFUNDED"
    IN_DISPUTE = "IN_DISPUTE"


class DisputeStatus(StrEnum):
    PENDING = "PENDING"
    RELEASED_BY_VOTE = "RELEASED_BY_VOTE"
    REFUNDED_BY_VOTE = "REFUNDED_BY_VOTE"


# Pydantic models for request/response validation
class EscrowCreateRequest(BaseModel):
    buyer_id: str = Field(..., description="ID of the agent purchasing the service/item.")
    seller_id: str = Field(..., description="ID of the agent selling the service/item.")
    amount: float = Field(..., gt=0, description="Amount of credits/funds to be held in escrow.")
    timeout_seconds: float | None = Field(
        3600.0,
        gt=0.0,
        description="Time in seconds before the escrow automatically expires and can be refunded.",
    )
    arbitrators: list[str] | None = Field(
        default_factory=list,
        description=(
            "Optional list of authorized juror agent IDs. If empty, any agent can act as a juror."
        ),
    )
    vote_threshold: int | None = Field(
        3, ge=1, description="Number of matching votes required to resolve a dispute."
    )

    @field_validator("buyer_id", "seller_id")
    @classmethod
    def validate_ids(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("ID cannot be empty or only whitespace.")
        return stripped


class EscrowResponse(BaseModel):
    id: str
    buyer_id: str
    seller_id: str
    amount: float
    timeout_seconds: float
    created_at: float
    expires_at: float
    status: EscrowStatus
    evidence_url: str | None = None
    evidence_hash: str | None = None
    arbitrators: list[str]
    vote_threshold: int


class EscrowActionRequest(BaseModel):
    agent_id: str = Field(
        ...,
        description="ID of the agent initiating the action. Must be authorized for this escrow.",
    )

    @field_validator("agent_id")
    @classmethod
    def validate_agent_id(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("Agent ID cannot be empty or only whitespace.")
        return stripped


class EscrowDisputeRequest(BaseModel):
    agent_id: str = Field(
        ..., description="ID of the agent raising the dispute. Must be buyer or seller."
    )
    evidence_url: str | None = Field(
        None, description="Optional URL detailing the transaction issue/evidence."
    )
    evidence_hash: str | None = Field(
        None, description="Optional cryptographic hash of the evidence data."
    )

    @field_validator("agent_id")
    @classmethod
    def validate_agent_id(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("Agent ID cannot be empty or only whitespace.")
        return stripped


class JurorVoteRequest(BaseModel):
    juror_id: str = Field(..., description="ID of the juror agent casting the vote.")
    vote: str = Field(..., description="Vote outcome. Must be either 'RELEASE' or 'REFUND'.")
    rationale: str = Field(
        ..., min_length=10, description="Plain English reasoning explaining the juror's vote."
    )

    @field_validator("juror_id")
    @classmethod
    def validate_juror_id(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("Juror ID cannot be empty or only whitespace.")
        return stripped

    @field_validator("rationale")
    @classmethod
    def validate_rationale(cls, v: str) -> str:
        stripped = v.strip()
        if len(stripped) < 10:
            raise ValueError("Rationale must be at least 10 characters after stripping whitespace.")
        return stripped


class DisputeResponse(BaseModel):
    escrow_id: str
    buyer_votes: int
    seller_votes: int
    votes: dict[str, str]
    status: DisputeStatus
    resolved_at: float | None = None


# Internal Python representations
class Escrow:
    def __init__(
        self,
        buyer_id: str,
        seller_id: str,
        amount: float,
        timeout_seconds: float,
        arbitrators: list[str],
        vote_threshold: int,
    ):
        self.id = str(uuid.uuid4())[:8]  # short readable uuid
        self.buyer_id = buyer_id
        self.seller_id = seller_id
        self.amount = amount
        self.timeout_seconds = timeout_seconds
        self.created_at = time.time()
        self.expires_at = self.created_at + timeout_seconds
        self.status = EscrowStatus.HELD
        self.evidence_url: str | None = None
        self.evidence_hash: str | None = None
        self.arbitrators = arbitrators
        self.vote_threshold = vote_threshold

    def to_response(self) -> EscrowResponse:
        # Check and handle timeout expiration dynamically
        if self.status == EscrowStatus.HELD and time.time() > self.expires_at:
            self.status = EscrowStatus.REFUNDED
            logger.info(f"Escrow {self.id} automatically refunded due to timeout expiration.")
        return EscrowResponse(
            id=self.id,
            buyer_id=self.buyer_id,
            seller_id=self.seller_id,
            amount=self.amount,
            timeout_seconds=self.timeout_seconds,
            created_at=self.created_at,
            expires_at=self.expires_at,
            status=self.status,
            evidence_url=self.evidence_url,
            evidence_hash=self.evidence_hash,
            arbitrators=self.arbitrators,
            vote_threshold=self.vote_threshold,
        )


class Dispute:
    def __init__(self, escrow_id: str):
        self.escrow_id = escrow_id
        self.buyer_votes = 0  # votes for REFUND
        self.seller_votes = 0  # votes for RELEASE
        self.votes: dict[str, str] = {}  # juror_id -> vote_type
        self.status = DisputeStatus.PENDING
        self.resolved_at: float | None = None

    def to_response(self) -> DisputeResponse:
        return DisputeResponse(
            escrow_id=self.escrow_id,
            buyer_votes=self.buyer_votes,
            seller_votes=self.seller_votes,
            votes=self.votes,
            status=self.status,
            resolved_at=self.resolved_at,
        )


@app.get("/", include_in_schema=False)
async def root_redirect():
    """
    Redirects root requests to the /skill.md document.
    """
    return RedirectResponse(url="/skill.md")


@app.get("/health", status_code=status.HTTP_200_OK)
async def health_check():
    """
    Returns API status and metadata. Used for heartbeat validation.
    """
    return {
        "status": "healthy",
        "service": "AgentCourt Escrow & Arbitration Court",
        "timestamp": time.time(),
        "version": "1.0.0",
    }


@app.post("/escrow", response_model=EscrowResponse, status_code=status.HTTP_201_CREATED)
async def create_escrow(req: EscrowCreateRequest):
    """
    Creates a new escrow agreement. Buyer locks up funds/credits.
    """
    with db_lock:
        if req.buyer_id == req.seller_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Buyer ID and Seller ID must be different.",
            )
        arbitrators = req.arbitrators or []
        vote_threshold = req.vote_threshold or 3
        if arbitrators and vote_threshold > len(arbitrators):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    f"Vote threshold ({vote_threshold}) cannot exceed the "
                    f"number of designated arbitrators ({len(arbitrators)})."
                ),
            )
        escrow = Escrow(
            buyer_id=req.buyer_id,
            seller_id=req.seller_id,
            amount=req.amount,
            timeout_seconds=req.timeout_seconds or 3600.0,
            arbitrators=arbitrators,
            vote_threshold=vote_threshold,
        )
        escrow_db[escrow.id] = escrow
        logger.info(
            f"Created Escrow {escrow.id}: Buyer={escrow.buyer_id}, "
            f"Seller={escrow.seller_id}, Amount={escrow.amount}"
        )
        return escrow.to_response()


@app.get("/escrow/{escrow_id}", response_model=EscrowResponse)
async def get_escrow(escrow_id: str):
    """
    Retrieves the status of an escrow contract.
    """
    with db_lock:
        if escrow_id not in escrow_db:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail=f"Escrow ID {escrow_id} not found."
            )
        return escrow_db[escrow_id].to_response()


@app.post("/escrow/{escrow_id}/release", response_model=EscrowResponse)
async def release_escrow(escrow_id: str, req: EscrowActionRequest):
    """
    Initiated by the buyer to release escrowed funds directly to the seller.
    """
    with db_lock:
        if escrow_id not in escrow_db:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail=f"Escrow ID {escrow_id} not found."
            )
        escrow = escrow_db[escrow_id]

        # Verify dynamic timeout
        if escrow.status == EscrowStatus.HELD and time.time() > escrow.expires_at:
            escrow.status = EscrowStatus.REFUNDED

        if escrow.status != EscrowStatus.HELD:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Escrow is not in HELD status. Current status: {escrow.status.value}",
            )
        if req.agent_id != escrow.buyer_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only the buyer can release the escrow funds.",
            )

        escrow.status = EscrowStatus.RELEASED
        logger.info(f"Escrow {escrow_id} successfully RELEASED to Seller={escrow.seller_id}")
        return escrow.to_response()


@app.post("/escrow/{escrow_id}/refund", response_model=EscrowResponse)
async def refund_escrow(escrow_id: str, req: EscrowActionRequest):
    """
    Initiated by the seller (to refund the buyer) OR by the buyer after timeout has expired.
    """
    with db_lock:
        if escrow_id not in escrow_db:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail=f"Escrow ID {escrow_id} not found."
            )
        escrow = escrow_db[escrow_id]

        # Check timeout expiration
        is_expired = time.time() > escrow.expires_at

        if escrow.status != EscrowStatus.HELD:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Escrow is not in HELD status. Current status: {escrow.status.value}",
            )

        # Refunder must be the seller, OR the buyer AFTER expiration
        if req.agent_id == escrow.seller_id:
            escrow.status = EscrowStatus.REFUNDED
            logger.info(f"Escrow {escrow_id} REFUNDED to Buyer by Seller choice.")
        elif req.agent_id == escrow.buyer_id and is_expired:
            escrow.status = EscrowStatus.REFUNDED
            logger.info(f"Escrow {escrow_id} REFUNDED to Buyer due to timeout expiration.")
        else:
            detail_msg = "Only the seller can issue a refund, or buyer after timeout."
            if req.agent_id == escrow.buyer_id and not is_expired:
                detail_msg = "Escrow has not expired yet. Buyer cannot claim refund before timeout."
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=detail_msg)

        return escrow.to_response()


@app.post("/escrow/{escrow_id}/dispute", response_model=EscrowResponse)
async def dispute_escrow(escrow_id: str, req: EscrowDisputeRequest):
    """
    Triggered by either the buyer or seller to freeze escrow and request arbitration.
    """
    with db_lock:
        if escrow_id not in escrow_db:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail=f"Escrow ID {escrow_id} not found."
            )
        escrow = escrow_db[escrow_id]

        # Verify dynamic timeout
        if escrow.status == EscrowStatus.HELD and time.time() > escrow.expires_at:
            escrow.status = EscrowStatus.REFUNDED

        if escrow.status != EscrowStatus.HELD:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Escrow cannot be disputed. Current status: {escrow.status.value}",
            )
        if req.agent_id not in (escrow.buyer_id, escrow.seller_id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only the buyer or seller involved in the escrow can raise a dispute.",
            )

        escrow.status = EscrowStatus.IN_DISPUTE
        escrow.evidence_url = req.evidence_url
        escrow.evidence_hash = req.evidence_hash

        # Initialize dispute record
        dispute_db[escrow_id] = Dispute(escrow_id)
        logger.info(f"Escrow {escrow_id} marked IN_DISPUTE by agent {req.agent_id}.")
        return escrow.to_response()


@app.get("/disputes", response_model=list[EscrowResponse])
async def list_disputes():
    """
    Lists all active escrow contracts in dispute that need juror arbitration.
    """
    with db_lock:
        active_disputes: list[EscrowResponse] = []
        for escrow in escrow_db.values():
            # Trigger expiration check if applicable
            escrow_res = escrow.to_response()
            if escrow_res.status == EscrowStatus.IN_DISPUTE:
                active_disputes.append(escrow_res)
        return active_disputes


@app.post("/disputes/{escrow_id}/vote", response_model=DisputeResponse)
async def vote_on_dispute(escrow_id: str, req: JurorVoteRequest):
    """
    Submits a juror's decision (vote) on an active dispute.
    Resolves the dispute and releases/refunds funds once threshold is met.
    """
    with db_lock:
        if escrow_id not in escrow_db:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail=f"Escrow ID {escrow_id} not found."
            )
        escrow = escrow_db[escrow_id]

        if escrow.status != EscrowStatus.IN_DISPUTE:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Escrow is not active in dispute. Current status: {escrow.status.value}",
            )

        dispute = dispute_db.get(escrow_id)
        if not dispute:
            # Fallback initialization in case DB got out of sync
            dispute = Dispute(escrow_id)
            dispute_db[escrow_id] = dispute

        if dispute.status != DisputeStatus.PENDING:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Dispute is already resolved."
            )

        # Verify juror eligibility if designated arbitrators list is set
        if escrow.arbitrators and req.juror_id not in escrow.arbitrators:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Juror {req.juror_id} is not an authorized arbitrator for this escrow.",
            )

        # Reject self-arbitration / conflict of interest (buyer/seller cannot vote)
        if req.juror_id in (escrow.buyer_id, escrow.seller_id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="The buyer or seller of this escrow cannot act as a juror.",
            )

        # Ensure juror cannot vote twice
        if req.juror_id in dispute.votes:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Juror {req.juror_id} has already cast a vote for this dispute.",
            )

        # Process vote
        vote_type = req.vote.upper().strip()
        if vote_type not in ("RELEASE", "REFUND"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Vote must be 'RELEASE' or 'REFUND'.",
            )

        dispute.votes[req.juror_id] = vote_type
        if vote_type == "RELEASE":
            dispute.seller_votes += 1
        else:
            dispute.buyer_votes += 1

        logger.info(
            f"Juror {req.juror_id} voted {vote_type} on Escrow {escrow_id}. "
            f"Rationale: {req.rationale}"
        )

        # Check if resolution threshold has been met
        if dispute.seller_votes >= escrow.vote_threshold:
            dispute.status = DisputeStatus.RELEASED_BY_VOTE
            dispute.resolved_at = time.time()
            escrow.status = EscrowStatus.RELEASED
            logger.info(
                f"Dispute on Escrow {escrow_id} resolved as RELEASED to seller by juror majority."
            )
        elif dispute.buyer_votes >= escrow.vote_threshold:
            dispute.status = DisputeStatus.REFUNDED_BY_VOTE
            dispute.resolved_at = time.time()
            escrow.status = EscrowStatus.REFUNDED
            logger.info(
                f"Dispute on Escrow {escrow_id} resolved as REFUNDED to buyer by juror majority."
            )

        return dispute.to_response()


@app.get("/skill.md", response_class=PlainTextResponse)
async def serve_skill_md():
    """
    Serves the SKILL.md documentation directly.
    This allows agents to fetch the documentation dynamically at runtime.
    """
    skill_path = os.path.join(os.path.dirname(__file__), "SKILL.md")
    if os.path.exists(skill_path):
        with open(skill_path, encoding="utf-8") as f:
            return f.read()
    # In-code fallback if file is somehow missing
    return "# AgentCourt\nBase URL: https://nandatown.onrender.com\n"
