---
title: Hybrid encryption with selective disclosure and broadcast revocation
layer: privacy
difficulty: hard
status: solved
---
> **Status: SOLVED** — implemented in `scenarios/sealed_bid_with_privacy.yaml` with the `hybrid_x25519` privacy plugin.
# Hybrid encryption with selective disclosure and broadcast revocation
## Motivation
The default privacy plugin
[`nest_plugins_reference/privacy/noop.py`](../../../packages/nest-plugins-reference/nest_plugins_reference/privacy/noop.py)
is 60 lines of **literally returning the input unchanged**.
`encrypt(data, audience)` (line 25) returns `data`. `prove(statement,
witness)` (line 43) returns a proof with payload `b"mock-proof"`.
`verify_proof` (line 52) unconditionally returns `True`. The README
limitation note at
[README.md line 308-310](../../../README.md) calls this out
explicitly: "no-op privacy."
That is fine when scenarios don't care about confidentiality, but it
means **every Nanda Town scenario that simulates a sensitive workflow is
silently leaking everything to every observer**, and the trace cannot
even tell you it would have leaked in production. Zero PRs touched
privacy. The
[`docs/layers/privacy.md`](../../../docs/layers/privacy.md) wishlist
calls out "hybrid encryption (X25519 + ChaCha20-Poly1305), group key
exchange, zk-SNARK / zk-STARK / Bulletproofs adapters, selective
disclosure of credentials."
This problem is **hard on purpose**: it requires real crypto, a clean
group-key story, and a credible threat model. The reward is that
every other Nanda Town scenario can now plug your privacy layer in and get
a believable confidentiality story for free.
Anyone running Nanda Town as a model of a real multi-party workflow —
medical-data swaps, sealed-bid auctions where bids must stay sealed,
attestations carrying selective fields — benefits.
## Success criteria
- Ship a privacy plugin (suggested name: `hybrid_x25519`) registered
  as `(\"privacy\", \"<your_name>\")` in
  [`nest_core/plugins.py`](../../../packages/nest-core/nest_core/plugins.py).
- **Real hybrid encryption**: per-message X25519 ephemeral key
  agreement + ChaCha20-Poly1305 (or AES-GCM) data encapsulation.
  Use the `cryptography` library; declare the new dependency in the
  `[plugins]` extra in
  [`pyproject.toml`](../../../pyproject.toml).
- `encrypt(data, audience)` produces ciphertext that **only** members
  of `audience` can decrypt. Use a simple group-key scheme (one
  symmetric key per ciphertext, wrapped once per recipient pubkey).
- `prove(statement, witness)` and `verify_proof(statement, proof)`
  implement at least one *real* selective-disclosure flow — e.g., a
  credential with multiple fields, where the holder reveals a subset
  and proves the rest are well-formed without revealing them. A
  hash-tree (Merkle) approach is acceptable; you do not need a full
  SNARK.
- **Revocation broadcast**: an audience member can be removed from
  future encryptions without rotating every other member's key.
  Document the forward-secrecy properties — what does revocation
  guarantee about *past* messages?
- Ship an adversarial validator that catches **four attacks**:
  1. *Eavesdropper*: a non-audience agent intercepts the ciphertext
     in the trace. It must not be decryptable by any non-audience key.
  2. *Replay*: a recorded ciphertext is replayed to a third party.
     Must not authenticate.
  3. *Field-injection*: an attacker tampers with the unrevealed
     fields of a selective-disclosure proof. Verification must fail.
  4. *Stale-revocation*: a revoked member tries to decrypt a
     message issued *after* their revocation. Must fail.
- Validator FAILS against `noop` (trivially — there's no actual
  encryption) and PASSES against yours.
- Ship `scenarios/sealed_bid_with_privacy.yaml` combining PR #5's
  sealed-bid coordination plugin with your privacy plugin so bids
  stay sealed *on the wire*, not just in the auction logic.
## Suggested approach pointers
- HPKE (RFC 9180) is the standard for this exact shape. The
  `cryptography` library doesn't ship it directly but it's a few
  hundred lines on top of X25519 + HKDF + ChaCha20-Poly1305.
- For selective disclosure, a binary Merkle tree over field hashes is
  simplest: reveal selected fields + the path; verifier reconstructs
  the root.
- Revocation under hybrid encryption is fundamentally about *not
  including* a recipient in the next key-wrap step. Forward secrecy
  requires per-epoch keys — be explicit about your epoch policy.
- The plugin can take an `Identity` instance via its constructor so
  signatures bind to existing agent identities.
- Run your test suite with `pytest -p no:randomly` if randomness
  ever creeps in — Tier 1 determinism demands it.
## Anti-patterns
- Don't ship symmetric-only encryption claiming to be hybrid.
- Don't ship "selective disclosure" as just JSON omission — the
  unrevealed fields must be cryptographically committed.
- Don't claim forward secrecy without an explicit epoch story.
- Don't reuse the same nonce twice (test for it).
- Don't break the `noop` plugin's existing callers.
## Out of scope
- Full zk-SNARK / zk-STARK implementation. Merkle-tree selective
  disclosure is sufficient.
- Post-quantum primitives.
- TLS/QUIC interop.
- Hardware enclave attestation (SGX, TDX).
