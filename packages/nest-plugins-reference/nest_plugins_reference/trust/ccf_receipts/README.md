# Pre-obtained confidential-ledger write receipts (committed fixtures)

This directory holds the anchoring evidence the `capsule_emit` trust plugin
replays onto the trace: one `<receipt_jcs_digest>.receipt.json` file per
scenario receipt, each a **verifiable CCF / Azure Confidential Ledger write
receipt** — a `LedgerEntryV1` application claim binding the digest, a Merkle
inclusion proof to the ledger's tree head, and a node signature endorsed by
the ledger's service identity — issued by the independent ledger whose
service identity is pinned in
`nest_core.ccf_receipt.PINNED_ACL_SERVICE_IDENTITY_PEM`.

## Root-of-trust provenance

The pinned cert was obtained from a real **Microsoft Azure Confidential Ledger**
(not a local CCF instance). Provenance:

| Field | Value |
|---|---|
| Ledger name | `AAC` |
| Resource group | `asg-scitt` |
| Ledger URI | `https://aac.confidential-ledger.azure.com` |
| Transactions | `2.47`–`2.103` (29 entries; api-version `2023-01-18-preview`) |
| Date registered | 2026-07-14 |

**To verify the pin independently** (confirm it matches genuine Azure ACL):

```bash
curl -s https://identity.confidential-ledger.core.azure.com/ledgerIdentity/aac \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['ledgerTlsCertificate'])"
```

Expected SHA-256 of PEM bytes:
`905da11bf6bfa02195d8db52e4d128bc2df128d32d54be74a5dc49c85504facf`

The Azure identity service endpoint is independent of the ledger's operational
state; it returns the service cert even after the ledger is decommissioned.

How they got here (operator-gated, out of band — network is allowed only in
this setup step, never in a graded run): `scripts/preanchor_acl_receipts.py`
ran the deterministic `receipt_reputation_capsule` scenario, appended each
sealed receipt's JCS digest as a ledger entry (data-plane
`/app/transactions`, api-version `2023-01-18-preview` so the receipt carries
`applicationClaims`), waited for commit, fetched each write receipt, verified
it offline against the pinned identity, and wrote it here (2026-07-14, 29
receipts). `test_committed_production_fixtures_verify_against_pinned_identity`
re-proves every committed fixture on every test run. Once captured, the
ledger itself is no longer needed — verification is fully offline.

To re-anchor (e.g. after a scenario change or a service-identity rotation):

```bash
uv run python scripts/preanchor_acl_receipts.py \
    --ledger-uri https://<ledger>.confidential-ledger.azure.com \
    --cacert /path/to/acl-service-identity.pem
```

then re-pin `PINNED_ACL_SERVICE_IDENTITY_PEM` if the identity changed.

**Never** commit receipts minted by `nest_mocks.ccf_ledger` (the LOCAL
TEST-ONLY ledger) here — its private keys are publicly derivable by design,
so its output is not evidence. Tests inject its service identity explicitly
and nothing else trusts it.
