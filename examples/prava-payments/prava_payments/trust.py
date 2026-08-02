# SPDX-License-Identifier: Apache-2.0
"""Senso-backed trust gate for the Prava payments layer.

Refuses payments to unverified agents. The gate is OPEN by default (every agent
trusted) so baseline scenarios run unchanged; pass an allowlist -- or a real Senso
client -- to enforce verification and demonstrate the failure case.

``SensoClient`` here is a deterministic stand-in keyed by an allowlist. In the
companion Vendable platform the same interface is backed by live Senso grounded
verification; kept deterministic here for Tier-1 reproducibility.

Example::

    gate = TrustGate(verified={"did:printsmith:store"})
    gate.is_verified("did:unknown:scammer")  # -> False
"""

from __future__ import annotations

import os


class TrustRefusedError(ValueError):
    """Raised when a payee fails verification and the Prava token is refused.

    Example::

        raise TrustRefusedError("Payee did:x failed Senso verification; refused")
    """


class SensoClient:
    """Deterministic Senso stand-in: verified only for allowlisted agents.

    Example::

        SensoClient(verified={"a"}).is_verified("a")  # -> True
    """

    def __init__(self, verified: set[str] | None = None, api_key: str | None = None) -> None:
        self._verified = verified or set()
        self._api_key = api_key if api_key is not None else os.environ.get("SENSO_API_KEY", "")

    def is_verified(self, agent_id: str) -> bool:
        """Return whether an agent is in the verified set.

        Example::

            SensoClient({"a"}).is_verified("a")  # -> True
        """
        return agent_id in self._verified


class TrustGate:
    """Decide whether a counterparty is trustworthy enough to be paid.

    - ``verified=None`` (default): open -- every agent is trusted (baseline runs).
    - ``verified={...}``: allowlist -- only listed agents are trusted.
    - ``senso=SensoClient(...)``: delegate the decision to Senso.

    Example::

        TrustGate(verified={"merchant"}).is_verified("scammer")  # -> False
    """

    def __init__(self, verified: set[str] | None = None, senso: SensoClient | None = None) -> None:
        self._verified = verified
        self._senso = senso

    def is_verified(self, agent_id: object) -> bool:
        """Return whether ``agent_id`` is trusted under the configured policy.

        Example::

            TrustGate().is_verified("anyone")  # -> True (open by default)
        """
        aid = str(agent_id)
        if self._senso is not None:
            return self._senso.is_verified(aid)
        if self._verified is None:
            return True
        return aid in self._verified
