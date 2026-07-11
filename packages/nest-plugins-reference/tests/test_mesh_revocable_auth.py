# SPDX-License-Identifier: Apache-2.0
"""Tests for the mesh-revocable auth plugin.

Covers base ``Auth`` protocol conformance, inherited delegatable behavior
(the subclass must not disturb attenuation / cascade semantics), the
two-replica revoke -> gossip -> deny flow, G-Set algebra at the plugin
surface (idempotent re-merge, grow-only, empty merge), the malformed-state
hardening matrix, and a deep-chain cross-replica stress case.
"""

from __future__ import annotations

import pytest
from nest_core.layers.auth import Auth
from nest_core.types import AgentId
from nest_plugins_reference.auth.delegatable import (
    RevokedAncestorError,
    ScopeEscalationError,
)
from nest_plugins_reference.auth.mesh_revocable import (
    CRDT_KIND,
    MeshRevocableAuth,
    RevocationStateError,
)

ROOT = AgentId("coordinator")
MID = AgentId("intermediary")
LEAF = AgentId("leaf")

_SECRET = b"test-secret"


def _replica(clock: float = 0.0) -> MeshRevocableAuth:
    return MeshRevocableAuth(secret=_SECRET, clock=clock)


@pytest.mark.asyncio
async def test_satisfies_auth_protocol() -> None:
    assert isinstance(_replica(), Auth)


# -- Inherited delegatable behavior (regression against upstream drift) ----


@pytest.mark.asyncio
async def test_inherited_attenuation_still_enforced() -> None:
    auth = _replica()
    root = await auth.issue(ROOT, ["read"])
    with pytest.raises(ScopeEscalationError):
        await auth.delegate(root, MID, ["read", "admin"], ttl=60.0)


@pytest.mark.asyncio
async def test_inherited_local_cascade_still_works() -> None:
    auth = _replica()
    root = await auth.issue(ROOT, ["read", "write"])
    child = await auth.delegate(root, MID, ["read"], ttl=60.0)
    grandchild = await auth.delegate(child, LEAF, ["read"], ttl=30.0)
    await auth.revoke(root)
    with pytest.raises(RevokedAncestorError):
        await auth.verify(grandchild)


# -- Cross-replica flow ----------------------------------------------------


@pytest.mark.asyncio
async def test_any_replica_verifies_tokens_minted_elsewhere() -> None:
    issuer = _replica()
    gateway = _replica()
    root = await issuer.issue(ROOT, ["read", "write"])
    child = await issuer.delegate(root, MID, ["read"], ttl=60.0)
    ctx = await gateway.verify(child)
    assert ctx.scopes == ["read"]


@pytest.mark.asyncio
async def test_revocation_reaches_peer_only_after_merge() -> None:
    issuer = _replica()
    gateway = _replica()
    root = await issuer.issue(ROOT, ["read", "write"])
    child = await issuer.delegate(root, MID, ["read"], ttl=60.0)

    await issuer.revoke(root)
    # Not yet gossiped: the gateway honestly still accepts.
    await gateway.verify(child)

    changed = gateway.merge_revocations(issuer.export_revocations())
    assert changed is True
    with pytest.raises(RevokedAncestorError):
        await gateway.verify(child)


@pytest.mark.asyncio
async def test_revocation_propagates_transitively_via_intermediate() -> None:
    a, b, c = _replica(), _replica(), _replica()
    root = await a.issue(ROOT, ["read"])
    child = await a.delegate(root, MID, ["read"], ttl=60.0)
    await a.revoke(root)
    # a -> b -> c; c never talks to a directly.
    b.merge_revocations(a.export_revocations())
    c.merge_revocations(b.export_revocations())
    with pytest.raises(RevokedAncestorError):
        await c.verify(child)


@pytest.mark.asyncio
async def test_deep_chain_cross_replica_cascade() -> None:
    issuer = _replica()
    verifier = _replica()
    tokens = [await issuer.issue(AgentId("agent-0"), ["read"])]
    for depth in range(1, 21):
        tokens.append(
            await issuer.delegate(tokens[-1], AgentId(f"agent-{depth}"), ["read"], ttl=600.0)
        )
    await verifier.verify(tokens[-1])
    await issuer.revoke(tokens[3])
    verifier.merge_revocations(issuer.export_revocations())
    with pytest.raises(RevokedAncestorError):
        await verifier.verify(tokens[-1])
    # Above the cut survives.
    await verifier.verify(tokens[2])


# -- G-Set algebra at the plugin surface ------------------------------------


@pytest.mark.asyncio
async def test_remerge_is_idempotent_and_reports_no_change() -> None:
    a, b = _replica(), _replica()
    root = await a.issue(ROOT, ["read"])
    await a.revoke(root)
    state = a.export_revocations()
    assert b.merge_revocations(state) is True
    before = b.export_revocations()
    assert b.merge_revocations(state) is False
    assert b.export_revocations() == before


@pytest.mark.asyncio
async def test_merging_empty_state_removes_nothing() -> None:
    a = _replica()
    root = await a.issue(ROOT, ["read"])
    await a.revoke(root)
    before = a.export_revocations()
    assert a.merge_revocations(_replica().export_revocations()) is False
    assert a.export_revocations() == before


def test_export_is_deterministic_bytes() -> None:
    a, b = _replica(), _replica()
    for tid in ("cc", "aa", "bb"):
        a.merge_revocations(f'{{"crdt": "{CRDT_KIND}", "revoked": ["{tid}"]}}'.encode())
    b.merge_revocations(f'{{"crdt": "{CRDT_KIND}", "revoked": ["bb", "aa", "cc"]}}'.encode())
    assert a.export_revocations() == b.export_revocations()


# -- Hardening ---------------------------------------------------------------


@pytest.mark.parametrize(
    "state",
    [
        b"",
        b"not json",
        b"\xff\xfe",
        b"[]",
        b'"revoked"',
        b"{}",
        b'{"crdt": "lww_register", "revoked": []}',
        b'{"crdt": "revocation_gset", "revoked": "ab"}',
        b'{"crdt": "revocation_gset", "revoked": [1, 2]}',
        b'{"crdt": "revocation_gset", "revoked": [["ab"]]}',
    ],
)
def test_malformed_state_rejected_and_replica_untouched(state: bytes) -> None:
    auth = _replica()
    auth.merge_revocations(b'{"crdt": "revocation_gset", "revoked": ["keep"]}')
    before = auth.export_revocations()
    with pytest.raises(RevocationStateError):
        auth.merge_revocations(state)
    assert auth.export_revocations() == before


def test_revocation_state_error_is_a_value_error() -> None:
    assert issubclass(RevocationStateError, ValueError)
