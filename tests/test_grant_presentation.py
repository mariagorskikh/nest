"""A grant needs session-key proof for this participant in this run.

Retains legacy PR #156's absent/wrong-presenter requirement on current
Run Grants. This does not add delegated-token or cascading-revocation policy.
Removing the session-proof check, or skipping it for an empty proof, must
break these tests. A rejected attempt must leave the real join available.
"""

from contextlib import closing
import sqlite3

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from nandatown.coordinator import build_app
from nandatown.identity_portable import IdentityError, Keystore, verify_grant
from nandatown.profiles import PROFILES
from nandatown.records import canonical_json


def _proof(private_hex, run_id, name):
    # Sign explicit presentation fields independently of session_proof(), so
    # changing both the producer and verifier cannot erase the tested binding.
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_hex))
    payload = {"purpose": "join", "run_id": run_id, "name": name}
    return key.sign(canonical_json(payload).encode()).hex()


def _invalid_proof(bundle, run_id, case):
    if case in ("empty", "omitted"):
        return ""
    if case == "other-role":
        return _proof(bundle["session_private"], run_id, "seller")
    assert case == "other-run"
    return _proof(bundle["session_private"], "different-run", "buyer")


@pytest.mark.parametrize("case", ["empty", "other-role", "other-run"])
def test_grant_requires_proof_for_the_presented_context(tmp_path, case):
    keystore = Keystore(str(tmp_path / "keys"))
    identity = keystore.new_identity("buyer")
    bundle = keystore.make_grant("buyer", "run-1", now=100)

    with pytest.raises(IdentityError, match="session proof"):
        verify_grant(
            bundle["grant"], bundle["grant_signature"],
            identity["controller_public"], "run-1", "buyer",
            _invalid_proof(bundle, "run-1", case), now=100,
        )

    verify_grant(
        bundle["grant"], bundle["grant_signature"],
        identity["controller_public"], "run-1", "buyer",
        _proof(bundle["session_private"], "run-1", "buyer"), now=100,
    )


@pytest.mark.parametrize("case", ["omitted", "empty", "other-role", "other-run"])
def test_invalid_presentation_creates_no_session_and_allows_valid_join(
        tmp_path, case):
    keystore = Keystore(str(tmp_path / "keys"))
    identity = keystore.new_identity("buyer")
    db_path = str(tmp_path / "town.db")
    admin = {"X-Town-Admin": "test-admin"}
    with TestClient(build_app(db_path, admin_token="test-admin")) as client:
        created = client.post("/runs", headers=admin, json={
            "profile": PROFILES["quote-clean"].model_dump(),
            "identities": {"buyer": identity},
        })
        assert created.status_code == 200, created.text
        run_id = created.json()["run_id"]
        bundle = keystore.make_grant("buyer", run_id)
        body = {"name": "buyer", "grant": bundle["grant"],
                "grant_signature": bundle["grant_signature"]}
        if case != "omitted":
            body["session_proof"] = _invalid_proof(bundle, run_id, case)

        rejected = client.post(f"/runs/{run_id}/join", json=body)
        assert rejected.status_code == 403, rejected.text
        with closing(sqlite3.connect(db_path)) as connection:
            row = connection.execute(
                "SELECT session, permissions_json FROM participants"
                " WHERE run_id=? AND name=?", (run_id, "buyer")).fetchone()
        assert row == (None, None)
        events = client.get(f"/runs/{run_id}/events", headers=admin)
        assert events.status_code == 200, events.text
        kinds = [event["kind"] for event in events.json()["events"]]
        assert kinds.count("grant_rejected") == 1
        assert "participant_joined" not in kinds
        assert "portable_identity_verified" not in kinds

        body["session_proof"] = _proof(
            bundle["session_private"], run_id, "buyer")
        accepted = client.post(f"/runs/{run_id}/join", json=body)
        assert accepted.status_code == 200, accepted.text
        session = accepted.json()["session"]
        assert session
        directory = client.get(f"/runs/{run_id}/participants",
                               headers={"X-Town-Session": session})
        assert directory.status_code == 200, directory.text
