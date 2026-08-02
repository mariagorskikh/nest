# SPDX-License-Identifier: Apache-2.0
"""Thin client for the Prava payment rail, with a deterministic offline mock.

By default the client returns a deterministic mock result so ``nest run`` and the
test suite stay offline and reproducible (Tier-1 determinism). Set ``PRAVA_API_KEY``
and ``PRAVA_LIVE=1`` to settle against the real Prava sandbox instead.

The full live integration (real Prava mandates + charge) lives in the companion
Vendable platform; this client keeps only what the simulation needs.

Example::

    client = PravaClient()
    result = await client.settle(payer="a", payee="b", amount=399, currency="INR", ref="r1")
"""

from __future__ import annotations

import json
import os
import urllib.request


class PravaClient:
    """Settle and refund over Prava, mock-by-default for deterministic sims.

    Example::

        client = PravaClient()
        await client.refund("r1")
    """

    def __init__(self, api_key: str | None = None, base_url: str | None = None) -> None:
        self.api_key = api_key if api_key is not None else os.environ.get("PRAVA_API_KEY", "")
        self.base_url = base_url or os.environ.get(
            "PRAVA_BASE_URL", "https://sandbox.api.prava.space"
        )
        # Only hit the network when explicitly enabled; keeps the sim deterministic.
        self.live = bool(self.api_key) and os.environ.get("PRAVA_LIVE") == "1"

    async def settle(
        self, *, payer: str, payee: str, amount: int, currency: str, ref: str
    ) -> dict[str, object]:
        """Settle a payment; returns a deterministic mock unless live.

        Example::

            await client.settle(payer="a", payee="b", amount=399, currency="INR", ref="r1")
        """
        if not self.live:
            return {"ref": ref, "status": "settled", "mock": True}
        body = {"payer": payer, "payee": payee, "amount": amount, "currency": currency, "ref": ref}
        return self._post("/v1/payments", body)

    async def refund(self, ref: str) -> dict[str, object]:
        """Refund a payment; returns a deterministic mock unless live.

        Example::

            await client.refund("r1")
        """
        if not self.live:
            return {"ref": ref, "status": "refunded", "mock": True}
        return self._post(f"/v1/payments/{ref}/refund", {})

    def _post(self, path: str, body: dict[str, object]) -> dict[str, object]:
        """POST JSON to the Prava sandbox and return the decoded response.

        Example::

            client._post("/v1/payments", {"ref": "r1"})
        """
        data = json.dumps(body).encode()
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        req = urllib.request.Request(
            self.base_url + path, data=data, headers=headers, method="POST"
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            decoded: dict[str, object] = json.loads(resp.read().decode())
            return decoded
