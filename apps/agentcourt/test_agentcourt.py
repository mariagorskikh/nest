# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nanda Town Authors

"""
Automated unit and integration tests for the AgentCourt service.
"""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from .main import app, dispute_db, escrow_db

client = TestClient(app)


@pytest.fixture(autouse=True)
def clear_db():
    """Clears databases between tests."""
    escrow_db.clear()
    dispute_db.clear()


def test_health_check():
    """Verify the health check endpoint returns 200 and correct structure."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "version" in data


def test_escrow_happy_path():
    """Verify creation, retrieval, and buyer-release of funds."""
    # 1. Create Escrow
    create_req = {
        "buyer_id": "buyer-1",
        "seller_id": "seller-1",
        "amount": 100.0,
        "timeout_seconds": 120.0,
        "arbitrators": ["j-1", "j-2"],
        "vote_threshold": 2,
    }
    response = client.post("/escrow", json=create_req)
    assert response.status_code == 201
    escrow = response.json()
    escrow_id = escrow["id"]
    assert escrow_id is not None
    assert escrow["status"] == "HELD"
    assert escrow["buyer_id"] == "buyer-1"
    assert escrow["amount"] == 100.0

    # 2. Get Escrow
    response = client.get(f"/escrow/{escrow_id}")
    assert response.status_code == 200
    assert response.json()["id"] == escrow_id

    # 3. Release Escrow
    release_req = {"agent_id": "buyer-1"}
    response = client.post(f"/escrow/{escrow_id}/release", json=release_req)
    assert response.status_code == 200
    assert response.json()["status"] == "RELEASED"

    # 4. Fail double-release
    response = client.post(f"/escrow/{escrow_id}/release", json=release_req)
    assert response.status_code == 400


def test_escrow_seller_refund():
    """Verify creation and direct refund by the seller."""
    create_req = {
        "buyer_id": "buyer-1",
        "seller_id": "seller-1",
        "amount": 50.0,
    }
    response = client.post("/escrow", json=create_req)
    escrow_id = response.json()["id"]

    # Refund by seller
    refund_req = {"agent_id": "seller-1"}
    response = client.post(f"/escrow/{escrow_id}/refund", json=refund_req)
    assert response.status_code == 200
    assert response.json()["status"] == "REFUNDED"


def test_escrow_buyer_refund_expiration():
    """Verify buyer can only refund after expiration timer completes."""
    create_req = {
        "buyer_id": "buyer-1",
        "seller_id": "seller-1",
        "amount": 150.0,
        "timeout_seconds": 1.0,  # 1 second timeout
    }
    response = client.post("/escrow", json=create_req)
    escrow_id = response.json()["id"]

    # Try to refund immediately (before expiration) - should fail
    refund_req = {"agent_id": "buyer-1"}
    response = client.post(f"/escrow/{escrow_id}/refund", json=refund_req)
    assert response.status_code == 403

    # Wait for expiration
    time.sleep(1.1)

    # Try again - should succeed
    response = client.post(f"/escrow/{escrow_id}/refund", json=refund_req)
    assert response.status_code == 200
    assert response.json()["status"] == "REFUNDED"


def test_escrow_dispute_and_arbitration():
    """Verify raising a dispute and resolving it via juror votes."""
    create_req = {
        "buyer_id": "buyer-1",
        "seller_id": "seller-1",
        "amount": 300.0,
        "timeout_seconds": 60.0,
        "arbitrators": ["j-1", "j-2", "j-3"],
        "vote_threshold": 2,
    }
    response = client.post("/escrow", json=create_req)
    escrow_id = response.json()["id"]

    # 1. Raise dispute
    dispute_req = {"agent_id": "buyer-1", "evidence_url": "http://logs", "evidence_hash": "hash"}
    response = client.post(f"/escrow/{escrow_id}/dispute", json=dispute_req)
    assert response.status_code == 200
    assert response.json()["status"] == "IN_DISPUTE"

    # 2. Verify in disputes list
    response = client.get("/disputes")
    assert response.status_code == 200
    disputes = response.json()
    assert len(disputes) == 1
    assert disputes[0]["id"] == escrow_id

    # 3. Unauthorized juror vote - should fail
    vote_req = {
        "juror_id": "unauthorized-agent",
        "vote": "RELEASE",
        "rationale": "I think the seller did a good job overall.",
    }
    response = client.post(f"/disputes/{escrow_id}/vote", json=vote_req)
    assert response.status_code == 403

    # 4. Valid juror vote 1 (Seller Release)
    vote_req["juror_id"] = "j-1"
    response = client.post(f"/disputes/{escrow_id}/vote", json=vote_req)
    assert response.status_code == 200
    assert response.json()["seller_votes"] == 1
    assert response.json()["status"] == "PENDING"

    # 5. Prevent double voting
    response = client.post(f"/disputes/{escrow_id}/vote", json=vote_req)
    assert response.status_code == 400

    # 6. Valid juror vote 2 (Seller Release) -> triggers resolution
    vote_req["juror_id"] = "j-2"
    response = client.post(f"/disputes/{escrow_id}/vote", json=vote_req)
    assert response.status_code == 200
    dispute_info = response.json()
    assert dispute_info["seller_votes"] == 2
    assert dispute_info["status"] == "RELEASED_BY_VOTE"

    # 7. Check escrow status updated to RELEASED
    response = client.get(f"/escrow/{escrow_id}")
    assert response.json()["status"] == "RELEASED"


def test_serve_skill_md():
    """Verify the skill.md server returns the content of the documentation."""
    # Write a mock SKILL.md locally in the test if needed, but since it's already there:
    response = client.get("/skill.md")
    assert response.status_code == 200
    assert "AgentCourt" in response.text
