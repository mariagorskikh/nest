# SPDX-License-Identifier: Apache-2.0
"""Noop privacy plugin — transparent passthrough, no actual encryption.

Example::

    priv = NoopPrivacy()
    ct = await priv.encrypt(b"data", [AgentId("a1")])
    assert ct == b"data"
"""

from __future__ import annotations

from nest_core.types import AgentId, Proof, Statement, Witness

from nest_plugins_reference._simulation_warning import warn_simulation_only


class NoopPrivacy:
    """Transparent passthrough — no encryption, mock proofs always valid.

    Example::

        priv = NoopPrivacy()
        ct = await priv.encrypt(b"data", [AgentId("a1")])
    """

    def __init__(self) -> None:
        warn_simulation_only(
            "NoopPrivacy",
            "no encryption; data passes through unchanged",
        )

    async def encrypt(self, data: bytes, audience: list[AgentId]) -> bytes:
        """Return data unchanged (no encryption).

        Example::

            ct = await priv.encrypt(b"secret", [AgentId("a1")])
        """
        return data

    async def decrypt(self, data: bytes) -> bytes:
        """Return data unchanged (no decryption).

        Example::

            pt = await priv.decrypt(ct)
        """
        return data

    async def prove(self, statement: Statement, witness: Witness) -> Proof:
        """Generate a mock proof (always valid).

        Example::

            proof = await priv.prove(stmt, witness)
        """
        return Proof(statement=statement, data=b"mock-proof", scheme="noop")

    async def verify_proof(self, statement: Statement, proof: Proof) -> bool:
        """Verify a mock proof (always True).

        Example::

            ok = await priv.verify_proof(stmt, proof)
        """
        return True
