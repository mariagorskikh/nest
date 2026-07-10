# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nanda Town Authors

"""
AgentCourt Demo Script.
Spins up a local uvicorn server and runs through the complete happy path
as well as all security validation checks.
"""

from __future__ import annotations

import subprocess
import time
import sys
import httpx


def log_step(name: str):
    print(f"\n==================================================")
    print(f"** [DEMO STEP] {name}")
    print(f"==================================================")


def main():
    print("STARTING AgentCourt demo server...")
    
    # Start uvicorn server on port 8080
    cmd = [
        sys.executable,
        "-m",
        "uvicorn",
        "apps.agentcourt.main:app",
        "--host",
        "127.0.0.1",
        "--port",
        "8080",
        "--log-level",
        "warning",
    ]
    
    server_process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    
    # Wait for server to start
    client = httpx.Client(base_url="http://127.0.0.1:8080")
    retries = 10
    started = False
    while retries > 0:
        try:
            res = client.get("/health")
            if res.status_code == 200:
                started = True
                print("[OK] AgentCourt server is online!")
                break
        except Exception:
            pass
        time.sleep(0.5)
        retries -= 1
        
    if not started:
        print("[FAIL] Failed to start AgentCourt server. Exiting.")
        server_process.terminate()
        sys.exit(1)
        
    try:
        # STEP 1: Self-Trade Prevention
        log_step("Testing Self-Trade Prevention")
        payload_self_trade = {
            "buyer_id": "buyer-agent-99",
            "seller_id": "buyer-agent-99", # Same ID
            "amount": 250.0,
            "timeout_seconds": 3600.0,
        }
        res = client.post("/escrow", json=payload_self_trade)
        print(f"Request: POST /escrow (buyer_id == seller_id)")
        print(f"Response Status: {res.status_code}")
        print(f"Response Detail: {res.json()}")
        assert res.status_code == 400
        print("[OK] Correctly rejected self-trade with 400 Bad Request.")

        # STEP 2: Negative/Zero Timeout Prevention
        log_step("Testing Negative Timeout Prevention")
        payload_neg_timeout = {
            "buyer_id": "buyer-agent-99",
            "seller_id": "seller-agent-42",
            "amount": 250.0,
            "timeout_seconds": -10.0, # Negative timeout
        }
        res = client.post("/escrow", json=payload_neg_timeout)
        print(f"Request: POST /escrow (timeout_seconds = -10.0)")
        print(f"Response Status: {res.status_code}")
        print(f"Response Detail: {res.json()}")
        assert res.status_code == 422
        print("[OK] Correctly rejected negative timeout with 422 Validation Error.")

        # STEP 3: Creating a Valid Escrow
        log_step("Creating a Valid Escrow Agreement")
        payload_valid = {
            "buyer_id": "buyer-agent-99",
            "seller_id": "seller-agent-42",
            "amount": 250.0,
            "timeout_seconds": 120.0,
            "arbitrators": ["juror-agent-1", "juror-agent-2", "juror-agent-3"],
            "vote_threshold": 2,
        }
        res = client.post("/escrow", json=payload_valid)
        print(f"Request: POST /escrow (valid payload)")
        print(f"Response Status: {res.status_code}")
        escrow = res.json()
        escrow_id = escrow["id"]
        print(f"Response Escrow ID: {escrow_id}")
        print(f"Response Escrow Status: {escrow['status']}")
        assert res.status_code == 201
        assert escrow["status"] == "HELD"
        print("[OK] Successfully created valid escrow contract.")

        # STEP 4: Raising a Dispute
        log_step("Raising a Dispute on the Escrow")
        dispute_payload = {
            "agent_id": "buyer-agent-99",
            "evidence_url": "https://pastebin.com/raw/evidence",
            "evidence_hash": "sha256-e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        }
        res = client.post(f"/escrow/{escrow_id}/dispute", json=dispute_payload)
        print(f"Request: POST /escrow/{escrow_id}/dispute")
        print(f"Response Status: {res.status_code}")
        escrow_disputed = res.json()
        print(f"Escrow Status: {escrow_disputed['status']}")
        assert res.status_code == 200
        assert escrow_disputed["status"] == "IN_DISPUTE"
        print("[OK] Successfully froze escrow and put into IN_DISPUTE.")

        # STEP 5: Self-Arbitration / Conflict of Interest Rejection
        log_step("Testing Self-Arbitration Rejection")
        
        # Buyer tries to vote
        buyer_vote = {
            "juror_id": "buyer-agent-99",
            "vote": "REFUND",
            "rationale": "I am the buyer and I deserve my money back.",
        }
        res = client.post(f"/disputes/{escrow_id}/vote", json=buyer_vote)
        print(f"Request: POST /disputes/{escrow_id}/vote (buyer tries to vote)")
        print(f"Response Status: {res.status_code}")
        print(f"Response Detail: {res.json()}")
        assert res.status_code == 403
        
        # Seller tries to vote
        seller_vote = {
            "juror_id": "seller-agent-42",
            "vote": "RELEASE",
            "rationale": "I am the seller and I completed the job.",
        }
        res = client.post(f"/disputes/{escrow_id}/vote", json=seller_vote)
        print(f"Request: POST /disputes/{escrow_id}/vote (seller tries to vote)")
        print(f"Response Status: {res.status_code}")
        print(f"Response Detail: {res.json()}")
        assert res.status_code == 403
        print("[OK] Correctly rejected both Buyer and Seller from acting as jurors.")

        # STEP 6: Voting by Eligible Jurors
        log_step("Submitting Votes by Designated Arbitrators")
        
        # Juror 1 votes REFUND
        vote_1 = {
            "juror_id": "juror-agent-1",
            "vote": "REFUND",
            "rationale": "The buyer provided solid transport and logs showing delivery failure.",
        }
        res = client.post(f"/disputes/{escrow_id}/vote", json=vote_1)
        print(f"Request: Juror 1 votes REFUND")
        print(f"Response Status: {res.status_code}")
        print(f"Response Vote Info: {res.json()}")
        assert res.status_code == 200
        assert res.json()["status"] == "PENDING"

        # Juror 2 votes REFUND (Reaches vote_threshold of 2)
        vote_2 = {
            "juror_id": "juror-agent-2",
            "vote": "REFUND",
            "rationale": "I agree with Juror 1. Packet logs confirm non-delivery.",
        }
        res = client.post(f"/disputes/{escrow_id}/vote", json=vote_2)
        print(f"Request: Juror 2 votes REFUND (Threshold Met)")
        print(f"Response Status: {res.status_code}")
        dispute_final = res.json()
        print(f"Dispute Status: {dispute_final['status']}")
        assert res.status_code == 200
        assert dispute_final["status"] == "REFUNDED_BY_VOTE"

        # Check Escrow Status is now REFUNDED
        res = client.get(f"/escrow/{escrow_id}")
        escrow_final = res.json()
        print(f"Final Escrow Status: {escrow_final['status']}")
        assert escrow_final["status"] == "REFUNDED"
        print("[OK] Dispute resolved and escrow refunded successfully!")

        print("\nALL DEMO FLOWS AND SECURITY CHECKS PASSED SUCCESSFULLY!")

    finally:
        print("\nStopping AgentCourt demo server...")
        server_process.terminate()
        server_process.wait()


if __name__ == "__main__":
    main()
