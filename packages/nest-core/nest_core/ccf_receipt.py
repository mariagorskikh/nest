# SPDX-License-Identifier: Apache-2.0
"""Vendored, pure-Python CCF write-receipt verifier — the anchoring root of trust.

The anchoring gate's evidence is a **verifiable CCF / Azure Confidential
Ledger (ACL) write receipt**: a Merkle inclusion proof from the transaction's
leaf to the ledger's tree head, plus an ECDSA signature over that head made by
a node whose certificate the ledger's **service identity** endorses — an
independent transparency service whose private key the participant does NOT
hold. The validator verifies the receipt OFFLINE against the *pinned*
service-identity certificate; forging one requires the ledger's signing key,
so the evidence cannot be fabricated from plaintext trace content.

The statement (a receipt JCS digest) is bound through the ledger's
**application claims** (protocol ``LedgerEntryV1``): the claim's ``contents``
must equal the statement, the claims digest recomputed from the claim (the
exact HMAC construction ACL documents) must equal the receipt's
``claimsDigest`` leaf component, and that leaf folds through the inclusion
proof to the signed head. Change any link and the signature dies.

(Precision note: this is the CCF-native write-receipt format ACL emits at its
data-plane ``ledgerUri`` — deliberately NOT an RFC 9942 / SCITT COSE receipt
parser. We claim exactly what we verify. The verification algorithm mirrors
Microsoft's published ``azure-confidentialledger`` receipt-verification
reference, ported here so the verdict path stays vendored and dependency-free
beyond ``cryptography``.)

Everything here is vendored and fail-closed, in the same discipline as
``nest_core.canonical``: no network, no filesystem, no environment, no clock.
Certificate *time* validity is deliberately not evaluated — this is offline
replay of already-captured receipts against a pinned key; the pin itself is
the root of trust, established once at the operator-gated setup step.

Fixture / trace shape (the object the auditor hex-encodes onto the trace)::

    {
      "receipt": {
        "cert": "<PEM: the signing node's certificate>",
        "leafComponents": {
          "claimsDigest": "<hex sha-256>",
          "commitEvidence": "<string>",
          "writeSetDigest": "<hex sha-256>"
        },
        "nodeId": "<hex sha-256 of the node's DER SPKI>",
        "proof": [{"left": "<hex>"} | {"right": "<hex>"}, ...],
        "signature": "<base64 DER ECDSA over the tree head>"
      },
      "applicationClaims": [
        {"kind": "LedgerEntry",
         "ledgerEntry": {"collectionId": "...", "contents": "<statement hex>",
                          "protocol": "LedgerEntryV1", "secretKey": "<base64>"}}
      ]
    }
"""

from __future__ import annotations

import base64
import hashlib
import hmac
from typing import Any, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509 import Certificate, load_pem_x509_certificate

#: The pinned service identity of the production transparency service — the
#: Azure Confidential Ledger instance ``AAC`` in resource group ``asg-scitt``
#: at ``https://aac.confidential-ledger.azure.com`` (``CN=CCF Service``,
#: self-signed as Azure ACL produces), fetched on 2026-07-14 (transactions
#: ``2.47``–``2.103``, api-version ``2023-01-18-preview``) and pinned here as
#: the root of trust. The committed write-receipt fixtures under
#: ``nest_plugins_reference/trust/ccf_receipts/`` verify against exactly this
#: certificate; nothing else is trusted.
#:
#: **Provenance / independent verification:** this is a genuine Microsoft Azure
#: Confidential Ledger cert, not a local CCF instance. Verify with:
#:
#: .. code-block:: bash
#:
#:     curl -s https://identity.confidential-ledger.core.azure.com/ledgerIdentity/aac \
#:       | python3 -c "import sys,json; print(json.load(sys.stdin)['ledgerTlsCertificate'])"
#:
#: Expected SHA-256 of PEM bytes:
#: ``905da11bf6bfa02195d8db52e4d128bc2df128d32d54be74a5dc49c85504facf``
PINNED_ACL_SERVICE_IDENTITY_PEM: str | None = """-----BEGIN CERTIFICATE-----
MIIBkTCCATegAwIBAgIRAP1MNpdTmVTsufP3qgQ9O6wwCgYIKoZIzj0EAwIwFjEU
MBIGA1UEAwwLQ0NGIFNlcnZpY2UwHhcNMjYwNzE0MTYyMjM0WhcNMjYxMDEyMTYy
MjMzWjAWMRQwEgYDVQQDDAtDQ0YgU2VydmljZTBZMBMGByqGSM49AgEGCCqGSM49
AwEHA0IABH4qWu1RtUTRxZE4/jwHOnku8sazhLQYL6hdqBcx1fIpVlP2DADaAB0v
yT2YDTltwl4KFffQ7W5hVT8FRiVCeaqjZjBkMBIGA1UdEwEB/wQIMAYBAf8CAQEw
DgYDVR0PAQH/BAQDAgKEMB0GA1UdDgQWBBQ6dIqOUFEdRE/jZnJGjT1995yt8DAf
BgNVHSMEGDAWgBQ6dIqOUFEdRE/jZnJGjT1995yt8DAKBggqhkjOPQQDAgNIADBF
AiEA1Pq+5/il1Vpdzm8zbd6MEnymDrUTj9RHkyECVOkN/OkCIC5xZE7Rc87XIcDP
qNsKXd+nSmUbjxpRUdDT8YUkPAAC
-----END CERTIFICATE-----
"""

_LEDGER_ENTRY_V1 = "LedgerEntryV1"


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _hex32(value: Any) -> bytes:
    """Decode a 64-char hex SHA-256 string; raise ``ValueError`` otherwise."""
    if not isinstance(value, str) or len(value) != 64:
        raise ValueError("expected a 64-character hex digest")
    return bytes.fromhex(value)


def compute_claims_digest(application_claims: Any, statement: bytes) -> bytes:
    """Recompute the ACL claims digest, requiring ``statement`` to be bound.

    Implements exactly the documented ACL construction: for the (single)
    ``LedgerEntryV1`` claim, ``HMAC(secretKey, collectionId)`` and
    ``HMAC(secretKey, contents)`` are hashed together, prefixed by the
    protocol name, then the claim digests are concatenated behind a
    little-endian count and hashed once more. The claim's ``contents`` MUST
    equal ``statement`` hex — that is the statement binding — and exactly one
    claim is accepted (ACL emits one per write). Raises ``ValueError`` on any
    deviation.

    Example::

        digest = compute_claims_digest(fixture["applicationClaims"], stmt)
    """
    if not isinstance(application_claims, list):
        raise ValueError("application claims must be a list")
    claims_list = cast("list[Any]", application_claims)
    if len(claims_list) != 1:
        raise ValueError("expected exactly one application claim")
    claim = claims_list[0]
    if not isinstance(claim, dict):
        raise ValueError("application claim must be an object")
    claim_map = cast("dict[str, Any]", claim)
    if claim_map.get("kind") != "LedgerEntry":
        raise ValueError("expected a LedgerEntry application claim")
    entry = claim_map.get("ledgerEntry")
    if not isinstance(entry, dict):
        raise ValueError("ledgerEntry claim must be an object")
    entry_map = cast("dict[str, Any]", entry)
    if entry_map.get("protocol") != _LEDGER_ENTRY_V1:
        raise ValueError("unsupported ledger-entry claim protocol")
    collection_id = entry_map.get("collectionId")
    contents = entry_map.get("contents")
    secret_key_b64 = entry_map.get("secretKey")
    if (
        not isinstance(collection_id, str)
        or not isinstance(contents, str)
        or not isinstance(secret_key_b64, str)
    ):
        raise ValueError("ledgerEntry claim fields must be strings")
    if contents != statement.hex():
        raise ValueError("claim contents do not bind the statement")

    secret_key = base64.b64decode(secret_key_b64, validate=True)
    collection_hmac = hmac.new(secret_key, collection_id.encode("utf-8"), hashlib.sha256)
    contents_hmac = hmac.new(secret_key, contents.encode("utf-8"), hashlib.sha256)
    ledger_entry_digest = _sha256(collection_hmac.digest() + contents_hmac.digest())
    claim_digest = _sha256(_LEDGER_ENTRY_V1.encode("utf-8") + ledger_entry_digest)
    return _sha256((1).to_bytes(4, "little") + claim_digest)


def _leaf_from_components(components: Any, claims_digest: bytes) -> bytes:
    """CCF leaf: ``SHA-256(writeSetDigest ‖ SHA-256(commitEvidence) ‖ claimsDigest)``.

    ``claims_digest`` is the value recomputed from the application claims; it
    must equal the receipt's own ``claimsDigest`` component, or the leaf (and
    therefore the signed head) cannot be reproduced.
    """
    if not isinstance(components, dict):
        raise ValueError("leafComponents must be an object")
    comp = cast("dict[str, Any]", components)
    if _hex32(comp.get("claimsDigest")) != claims_digest:
        raise ValueError("receipt claimsDigest does not match the recomputed claims digest")
    write_set_digest = _hex32(comp.get("writeSetDigest"))
    commit_evidence = comp.get("commitEvidence")
    if not isinstance(commit_evidence, str) or not commit_evidence:
        raise ValueError("commitEvidence must be a non-empty string")
    return _sha256(write_set_digest + _sha256(commit_evidence.encode("utf-8")) + claims_digest)


def _root_from_proof(leaf: bytes, proof: Any) -> bytes:
    """Fold the CCF inclusion proof from ``leaf`` to the signed tree head."""
    if not isinstance(proof, list):
        raise ValueError("proof must be a list")
    acc = leaf
    for step in cast("list[Any]", proof):
        if not isinstance(step, dict) or len(cast("dict[str, Any]", step)) != 1:
            raise ValueError("each proof step must be a single left/right object")
        step_map = cast("dict[str, Any]", step)
        if "left" in step_map:
            acc = _sha256(_hex32(step_map["left"]) + acc)
        elif "right" in step_map:
            acc = _sha256(acc + _hex32(step_map["right"]))
        else:
            raise ValueError("proof step is neither left nor right")
    return acc


def _endorsed_node_certificate(receipt: dict[str, Any], service_identity_pem: str) -> Certificate:
    """Return the signing node cert iff the pinned service identity endorses it.

    Requires the node certificate to be directly issued *and signed* by the
    pinned service-identity certificate (or to be that certificate itself),
    and — when the receipt carries a ``nodeId`` — that it equals the SHA-256
    of the node public key's DER SPKI, as ACL receipts stamp it. Certificate
    *rotation* endorsement chains (``serviceEndorsements``) are not accepted:
    the fixtures were captured under exactly the pinned identity.
    """
    if receipt.get("serviceEndorsements") not in (None, []):
        raise ValueError("service endorsement chains are not supported; re-pin instead")
    cert_pem = receipt.get("cert")
    if not isinstance(cert_pem, str):
        raise ValueError("receipt cert must be a PEM string")
    node_cert = load_pem_x509_certificate(cert_pem.encode("utf-8"))
    service_cert = load_pem_x509_certificate(service_identity_pem.encode("utf-8"))
    if node_cert != service_cert:
        # Issuer/subject linkage + the service identity's signature over it.
        node_cert.verify_directly_issued_by(service_cert)

    node_id = receipt.get("nodeId")
    if node_id is not None:
        spki = node_cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        if _hex32(node_id) != _sha256(spki):
            raise ValueError("nodeId does not match the node certificate's public key")
    return node_cert


def verify_ccf_write_receipt(
    evidence: dict[str, Any], statement: bytes, service_identity_pem: str
) -> bool:
    """Verify an ACL write receipt binds ``statement`` under the pinned identity.

    ``evidence`` is the ``{"receipt": …, "applicationClaims": …}`` object (the
    fixture / trace-line payload). ``True`` only when every layer checks out:
    the application claim binds the statement, the recomputed claims digest
    matches the receipt's leaf component, the Merkle proof folds to the tree
    head, the signing node certificate is endorsed by the pinned service
    identity (with a matching ``nodeId``), and the node's ECDSA signature
    verifies over that head. Never raises. Zero network, filesystem,
    environment, or clock access.

    Example::

        ok = verify_ccf_write_receipt(fixture, bytes.fromhex(digest), pinned_pem)
    """
    try:
        receipt = evidence.get("receipt")
        if not isinstance(receipt, dict):
            return False
        receipt_map = cast("dict[str, Any]", receipt)

        claims_digest = compute_claims_digest(evidence.get("applicationClaims"), statement)
        leaf = _leaf_from_components(receipt_map.get("leafComponents"), claims_digest)
        root = _root_from_proof(leaf, receipt_map.get("proof"))

        signature_b64 = receipt_map.get("signature")
        if not isinstance(signature_b64, str):
            return False
        signature = base64.b64decode(signature_b64, validate=True)

        node_cert = _endorsed_node_certificate(receipt_map, service_identity_pem)
        public_key = node_cert.public_key()
        if not isinstance(public_key, EllipticCurvePublicKey):
            return False
        # The ledger signs the 32-byte tree head directly (the head is already
        # a SHA-256 digest), so the ECDSA verification is prehashed.
        public_key.verify(signature, root, ECDSA(Prehashed(SHA256())))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
