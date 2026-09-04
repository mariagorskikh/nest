"""A controller's real grant cannot authorize an unrelated session key.

Regression requirements from legacy PR #172, exercised against current
Run Grants rather than the retired attested-peering protocol.
"""

from contextlib import closing
import sqlite3

import pytest
from fastapi.testclient import TestClient

from nandatown.coordinator import build_app
from nandatown.identity_portable import (
    IdentityError,
    Keystore,
    session_proof,
    verify_grant,
)
from nandatown.profiles import PROFILES


def _candidate(keystore, run_id, replace_public):
    genuine = keystore.make_grant("buyer", run_id)
    other = keystore.make_grant("other", run_id)
    assert genuine["grant"]["session_public"] != other["grant"]["session_public"]
    grant = dict(genuine["grant"])
    if replace_public:
        grant["session_public"] = other["grant"]["session_public"]
    proof = session_proof(other["session_private"], run_id, "buyer")
    return genuine, grant, proof


@pytest.mark.parametrize("replace_public,reason", [
    (False, "session proof"),
    (True, "pinned controller key"),
], ids=["copied-grant", "altered-session-key"])
def test_grant_rejects_a_different_session_key(tmp_path, replace_public, reason):
    keystore = Keystore(str(tmp_path / "keys"))
    identity = keystore.new_identity("buyer")
    keystore.new_identity("other")
    genuine, grant, proof = _candidate(keystore, "run-1", replace_public)

    with pytest.raises(IdentityError, match=reason):
        verify_grant(grant, genuine["grant_signature"],
                     identity["controller_public"], "run-1", "buyer", proof)

    # The same genuine grant remains usable by its authorized session key.
    verify_grant(genuine["grant"], genuine["grant_signature"],
                 identity["controller_public"], "run-1", "buyer",
                 session_proof(genuine["session_private"], "run-1", "buyer"))


@pytest.mark.parametrize("replace_public", [False, True],
                         ids=["copied-grant", "altered-session-key"])
def test_rejected_key_substitution_leaves_join_unclaimed(tmp_path, replace_public):
    keystore = Keystore(str(tmp_path / "keys"))
    identity = keystore.new_identity("buyer")
    keystore.new_identity("other")
    db_path = str(tmp_path / "town.db")
    admin = {"X-Town-Admin": "test-admin"}
    with TestClient(build_app(db_path, admin_token="test-admin")) as client:
        created = client.post("/runs", headers=admin, json={
            "profile": PROFILES["quote-clean"].model_dump(),
            "identities": {"buyer": identity},
        })
        assert created.status_code == 200, created.text
        run_id = created.json()["run_id"]
        genuine, grant, proof = _candidate(keystore, run_id, replace_public)
        rejected = client.post(f"/runs/{run_id}/join", json={
            "name": "buyer", "grant": grant,
            "grant_signature": genuine["grant_signature"],
            "session_proof": proof,
        })
        assert rejected.status_code == 403, rejected.text
        with closing(sqlite3.connect(db_path)) as connection:
            row = connection.execute(
                "SELECT session, permissions_json FROM participants"
                " WHERE run_id=? AND name=?", (run_id, "buyer")).fetchone()
        assert row == (None, None), "a rejected key cannot obtain a session"
        events = client.get(f"/runs/{run_id}/events", headers=admin)
        assert events.status_code == 200, events.text
        kinds = [event["kind"] for event in events.json()["events"]]
        assert kinds.count("grant_rejected") == 1
        assert "participant_joined" not in kinds
        assert "portable_identity_verified" not in kinds

        accepted = client.post(f"/runs/{run_id}/join", json={
            "name": "buyer", "grant": genuine["grant"],
            "grant_signature": genuine["grant_signature"],
            "session_proof": session_proof(
                genuine["session_private"], run_id, "buyer"),
        })
        assert accepted.status_code == 200, accepted.text
        assert accepted.json()["session"]
