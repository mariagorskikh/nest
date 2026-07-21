# SPDX-License-Identifier: Apache-2.0
"""Out-of-band pre-anchor: register scenario receipt digests with the ACL ledger.

THE ONLY PLACE NETWORK IS ALLOWED in the anchoring design. This setup script
runs the deterministic ``receipt_reputation_capsule`` scenario, appends each
sealed receipt's JCS digest as a ledger entry to the Azure Confidential
Ledger, waits for commit, fetches the CCF write receipt (with application
claims, which bind the digest), verifies it locally against the pinned
service identity, and commits it as a fixture keyed by receipt digest::

    packages/nest-plugins-reference/nest_plugins_reference/trust/ccf_receipts/
        <digest>.receipt.json

The graded run then replays these fixtures onto the trace and the validator
verifies them OFFLINE — zero network, filesystem, environment, or clock in
the verdict path. Once fixtures are committed the ledger itself can be torn
down.

Auth inherits the operator's ``az login`` session. Usage::

    uv run python scripts/preanchor_acl_receipts.py \
        --ledger-uri https://<ledger>.confidential-ledger.azure.com \
        --cacert /path/to/acl-service-identity.pem
"""

from __future__ import annotations

import argparse
import asyncio
import json
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Any, cast

_API_VERSION = "2023-01-18-preview"  # the first data-plane version that returns applicationClaims
_FIXTURE_DIR = (
    Path(__file__).parent.parent
    / "packages/nest-plugins-reference/nest_plugins_reference/trust/ccf_receipts"
)
_SCENARIO_YAML = Path(__file__).parent.parent / "scenarios/receipt_reputation_capsule.yaml"


def _access_token() -> str:
    """Bearer token for the confidential-ledger data plane via the az CLI session."""
    out = subprocess.run(
        [
            "az",
            "account",
            "get-access-token",
            "--resource",
            "https://confidential-ledger.azure.com",
            "--query",
            "accessToken",
            "-o",
            "tsv",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return out.stdout.strip()


def _scenario_digests() -> list[str]:
    """Run the deterministic capsule scenario; return its sealed receipt digests.

    The receipt set is a pure function of the scenario roster (agent-derived
    keys), independent of the RNG seed — verified by the e2e determinism test.
    """
    from nest_core.runner import ScenarioRunner
    from nest_core.scenario import ScenarioConfig

    with tempfile.TemporaryDirectory() as td:
        trace = Path(td) / "trace.jsonl"
        config = ScenarioConfig.from_yaml(_SCENARIO_YAML)
        config.output.trace = str(trace)
        asyncio.run(ScenarioRunner(config).run())

        digests: list[str] = []
        seen: set[str] = set()
        for line in trace.read_text().splitlines():
            msg = json.loads(line).get("msg", "")
            if isinstance(msg, str) and msg.startswith("seal:"):
                digest = msg.split(":")[2]
                if digest not in seen:
                    seen.add(digest)
                    digests.append(digest)
        return digests


class _Ledger:
    """Minimal data-plane client; TLS-verifies with the pinned PEM as the CA."""

    def __init__(self, ledger_uri: str, cacert: Path, token: str) -> None:
        self._uri = ledger_uri.rstrip("/")
        self._token = token
        self._ssl = ssl.create_default_context(cafile=str(cacert))

    def _request(
        self, method: str, path: str, body: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        req = urllib.request.Request(
            f"{self._uri}{path}",
            method=method,
            data=json.dumps(body).encode("utf-8") if body is not None else None,
            headers={
                "Authorization": f"Bearer {self._token}",
                "Content-Type": "application/json",
            },
        )
        with urllib.request.urlopen(req, context=self._ssl) as resp:
            payload = resp.read()
            tx_id = resp.headers.get("x-ms-ccf-transaction-id")
            parsed: dict[str, Any] = cast("dict[str, Any]", json.loads(payload)) if payload else {}
            if tx_id:
                parsed["_transactionId"] = tx_id
            return parsed

    def append(self, contents: str) -> str:
        result = self._request(
            "POST", f"/app/transactions?api-version={_API_VERSION}", {"contents": contents}
        )
        tx_id = result.get("_transactionId")
        if not isinstance(tx_id, str) or not tx_id:
            raise RuntimeError(f"no transaction id returned for entry {contents[:16]}…")
        return tx_id

    def wait_committed(self, tx_id: str, attempts: int = 30) -> None:
        for _ in range(attempts):
            status = self._request(
                "GET", f"/app/transactions/{tx_id}/status?api-version={_API_VERSION}"
            )
            if status.get("state") == "Committed":
                return
            time.sleep(1)
        raise RuntimeError(f"transaction {tx_id} did not commit in time")

    def receipt(self, tx_id: str, attempts: int = 30) -> dict[str, Any]:
        for _ in range(attempts):
            result = self._request(
                "GET", f"/app/transactions/{tx_id}/receipt?api-version={_API_VERSION}"
            )
            if result.get("state") == "Ready":
                return result
            time.sleep(1)
        raise RuntimeError(f"receipt for {tx_id} not ready in time")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger-uri", required=True)
    parser.add_argument("--cacert", required=True, type=Path)
    parser.add_argument("--out-dir", type=Path, default=_FIXTURE_DIR)
    args = parser.parse_args()

    from nest_core.ccf_receipt import verify_ccf_write_receipt

    service_identity_pem = args.cacert.read_text()
    digests = _scenario_digests()
    print(f"scenario yields {len(digests)} receipt digests to anchor")

    ledger = _Ledger(args.ledger_uri, args.cacert, _access_token())
    args.out_dir.mkdir(parents=True, exist_ok=True)

    for n, digest in enumerate(digests, 1):
        out_path = args.out_dir / f"{digest}.receipt.json"
        if out_path.exists():
            print(f"[{n}/{len(digests)}] {digest[:16]}… already anchored, skipping")
            continue
        tx_id = ledger.append(digest)
        ledger.wait_committed(tx_id)
        response = ledger.receipt(tx_id)
        fixture: dict[str, Any] = {
            "receipt": response["receipt"],
            "applicationClaims": response["applicationClaims"],
            "transactionId": response.get("transactionId", tx_id),
        }
        # Belt and braces: the fixture must verify OFFLINE against the pinned
        # identity before it is ever committed.
        if not verify_ccf_write_receipt(fixture, bytes.fromhex(digest), service_identity_pem):
            raise RuntimeError(f"fetched receipt for {digest[:16]}… does not verify — aborting")
        out_path.write_text(json.dumps(fixture, sort_keys=True, separators=(",", ":")) + "\n")
        print(f"[{n}/{len(digests)}] {digest[:16]}… anchored at {tx_id}, receipt verified + saved")

    print("done — fixtures written to", args.out_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
