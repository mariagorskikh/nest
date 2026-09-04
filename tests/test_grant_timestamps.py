"""Run-grant timestamps must be safe without changing their signed bytes."""

from contextlib import closing
from copy import deepcopy
import sqlite3

import pytest
from fastapi.testclient import TestClient

import nandatown.identity_portable as identity_portable
from nandatown.coordinator import build_app
from nandatown.identity_portable import (
    IdentityError,
    Keystore,
    session_proof,
    verify_grant,
)
from nandatown.profiles import PROFILES
from nandatown.records import canonical_json


INVALID_TIMESTAMPS = [
    ("missing", None),
    ("null", None),
    ("bool", True),
    ("numeric-string", "100"),
    ("container", []),
    ("nan", float("nan")),
    ("positive-infinity", float("inf")),
    ("negative-infinity", float("-inf")),
    ("oversized-integer", 10 ** 1000),
]


def _signed_grant(keystore, field, case, value):
    bundle = keystore.make_grant("buyer", "run-1", now=100, ttl=10)
    grant = dict(bundle["grant"])
    if case == "missing":
        grant.pop(field)
    else:
        grant[field] = value
    return bundle, grant, keystore.sign("buyer", grant)


@pytest.mark.parametrize("field", ["issued_at", "expires_at"])
@pytest.mark.parametrize("case,value", INVALID_TIMESTAMPS,
                         ids=[case for case, _ in INVALID_TIMESTAMPS])
def test_signed_malformed_timestamps_are_rejected(field, case, value, tmp_path):
    """Removing finite type validation must let one signed bad timestamp in."""
    keystore = Keystore(str(tmp_path / "keys"))
    identity = keystore.new_identity("buyer")
    bundle, grant, signature = _signed_grant(keystore, field, case, value)

    with pytest.raises(IdentityError,
                       match=rf"grant {field} must be a timestamp"):
        verify_grant(
            grant, signature, identity["controller_public"], "run-1", "buyer",
            session_proof(bundle["session_private"], "run-1", "buyer"),
            now=100,
        )


@pytest.mark.parametrize("issued_at,expires_at", [(100, 110), (100.25, 110.5)])
def test_finite_grant_timestamps_keep_signed_payload_and_expiry_boundary(
        issued_at, expires_at, tmp_path):
    """Changing a verifier-side normalization must not change signed values."""
    keystore = Keystore(str(tmp_path / "keys"))
    identity = keystore.new_identity("buyer")
    bundle = keystore.make_grant("buyer", "run-1", now=100, ttl=10)
    grant = {**bundle["grant"], "issued_at": issued_at,
             "expires_at": expires_at}
    signature = keystore.sign("buyer", grant)
    original = deepcopy(grant)
    original_bytes = canonical_json(grant).encode()
    proof = session_proof(bundle["session_private"], "run-1", "buyer")

    verify_grant(grant, signature, identity["controller_public"], "run-1",
                 "buyer", proof, now=expires_at)
    assert grant == original
    assert canonical_json(grant).encode() == original_bytes

    with pytest.raises(IdentityError, match="grant expired"):
        verify_grant(grant, signature, identity["controller_public"], "run-1",
                     "buyer", proof, now=expires_at + 0.001)


def test_expired_fixture_creation_remains_supported(tmp_path):
    keystore = Keystore(str(tmp_path / "keys"))
    identity = keystore.new_identity("buyer")
    bundle = keystore.make_grant("buyer", "run-1", now=101, ttl=-1)
    proof = session_proof(bundle["session_private"], "run-1", "buyer")

    assert bundle["grant"]["expires_at"] == 100
    with pytest.raises(IdentityError, match="grant expired"):
        verify_grant(bundle["grant"], bundle["grant_signature"],
                     identity["controller_public"], "run-1", "buyer", proof,
                     now=101)


@pytest.mark.parametrize("clock", [True, "100", [], float("nan"),
                                   float("inf"), float("-inf"), 10 ** 1000],
                         ids=["bool", "numeric-string", "container", "nan",
                              "positive-infinity", "negative-infinity",
                              "oversized-integer"])
def test_invalid_explicit_verifier_clock_is_rejected(clock, tmp_path):
    """Without clock validation some non-finite clocks accept a live grant."""
    keystore = Keystore(str(tmp_path / "keys"))
    identity = keystore.new_identity("buyer")
    bundle = keystore.make_grant("buyer", "run-1", now=100, ttl=10)

    with pytest.raises(IdentityError, match="verifier clock must be a timestamp"):
        verify_grant(
            bundle["grant"], bundle["grant_signature"],
            identity["controller_public"], "run-1", "buyer",
            session_proof(bundle["session_private"], "run-1", "buyer"),
            now=clock,
        )


@pytest.mark.parametrize("clock", [True, "100", [], float("nan"),
                                   float("inf"), float("-inf"), 10 ** 1000],
                         ids=["bool", "numeric-string", "container", "nan",
                              "positive-infinity", "negative-infinity",
                              "oversized-integer"])
def test_invalid_default_verifier_clock_is_rejected(clock, monkeypatch, tmp_path):
    keystore = Keystore(str(tmp_path / "keys"))
    identity = keystore.new_identity("buyer")
    bundle = keystore.make_grant("buyer", "run-1", now=100, ttl=10)
    monkeypatch.setattr(identity_portable.time, "time", lambda: clock)

    with pytest.raises(IdentityError, match="verifier clock must be a timestamp"):
        verify_grant(
            bundle["grant"], bundle["grant_signature"],
            identity["controller_public"], "run-1", "buyer",
            session_proof(bundle["session_private"], "run-1", "buyer"),
        )


@pytest.mark.parametrize("clock_source", ["explicit", "default"])
def test_large_integer_clock_keeps_exact_expiry_boundary(
        clock_source, monkeypatch, tmp_path):
    """Rounding a valid clock must not make a just-expired grant live."""
    boundary = 2 ** 53
    keystore = Keystore(str(tmp_path / "keys"))
    identity = keystore.new_identity("buyer")
    bundle = keystore.make_grant("buyer", "run-1", now=boundary, ttl=0)
    proof = session_proof(bundle["session_private"], "run-1", "buyer")

    if clock_source == "explicit":
        verify_grant(bundle["grant"], bundle["grant_signature"],
                     identity["controller_public"], "run-1", "buyer", proof,
                     now=boundary)
        with pytest.raises(IdentityError, match="grant expired"):
            verify_grant(bundle["grant"], bundle["grant_signature"],
                         identity["controller_public"], "run-1", "buyer", proof,
                         now=boundary + 1)
    else:
        monkeypatch.setattr(identity_portable.time, "time", lambda: boundary)
        verify_grant(bundle["grant"], bundle["grant_signature"],
                     identity["controller_public"], "run-1", "buyer", proof)
        monkeypatch.setattr(identity_portable.time, "time",
                            lambda: boundary + 1)
        with pytest.raises(IdentityError, match="grant expired"):
            verify_grant(bundle["grant"], bundle["grant_signature"],
                         identity["controller_public"], "run-1", "buyer", proof)


def _create_pinned_run(client, keystore):
    identity = keystore.new_identity("buyer")
    created = client.post("/runs", headers={"X-Town-Admin": "test-admin"},
                          json={"profile": PROFILES["quote-clean"].model_dump(),
                                "identities": {"buyer": identity}})
    assert created.status_code == 200, created.text
    return identity, created.json()["run_id"]


def _participant_row(db_path, run_id):
    with closing(sqlite3.connect(db_path)) as connection:
        return connection.execute(
            "SELECT session, permissions_json FROM participants "
            "WHERE run_id=? AND name=?", (run_id, "buyer")).fetchone()


def test_malformed_signed_grant_join_is_rejected_without_a_session(tmp_path):
    keystore = Keystore(str(tmp_path / "keys"))
    db_path = str(tmp_path / "town.db")
    with TestClient(build_app(db_path, admin_token="test-admin")) as client:
        _, run_id = _create_pinned_run(client, keystore)
        bundle = keystore.make_grant("buyer", run_id)
        grant = {**bundle["grant"], "expires_at": "never"}
        rejected = client.post(f"/runs/{run_id}/join", json={
            "name": "buyer", "grant": grant,
            "grant_signature": keystore.sign("buyer", grant),
            "session_proof": session_proof(bundle["session_private"], run_id,
                                           "buyer"),
        })

        assert rejected.status_code == 403, rejected.text
        assert "grant rejected" in rejected.json()["detail"]
        assert _participant_row(db_path, run_id) == (None, None)
        events = client.get(f"/runs/{run_id}/events",
                            headers={"X-Town-Admin": "test-admin"})
        assert events.status_code == 200, events.text
        assert [event["kind"] for event in events.json()["events"]].count(
            "grant_rejected") == 1


def test_malformed_rejoin_preserves_existing_session_and_permissions(tmp_path):
    keystore = Keystore(str(tmp_path / "keys"))
    db_path = str(tmp_path / "town.db")
    with TestClient(build_app(db_path, admin_token="test-admin")) as client:
        _, run_id = _create_pinned_run(client, keystore)
        bundle = keystore.make_grant("buyer", run_id, permissions=["join"])
        proof = session_proof(bundle["session_private"], run_id, "buyer")
        accepted = client.post(f"/runs/{run_id}/join", json={
            "name": "buyer", "grant": bundle["grant"],
            "grant_signature": bundle["grant_signature"], "session_proof": proof,
        })
        assert accepted.status_code == 200, accepted.text
        before = _participant_row(db_path, run_id)

        malformed = {**bundle["grant"], "issued_at": "not-a-time"}
        rejected = client.post(f"/runs/{run_id}/join", json={
            "name": "buyer", "grant": malformed,
            "grant_signature": keystore.sign("buyer", malformed),
            "session_proof": proof,
        })

        assert rejected.status_code == 403, rejected.text
        assert _participant_row(db_path, run_id) == before
        events = client.get(f"/runs/{run_id}/events",
                            headers={"X-Town-Admin": "test-admin"})
        assert events.status_code == 200, events.text
        assert [event["kind"] for event in events.json()["events"]].count(
            "grant_rejected") == 1
