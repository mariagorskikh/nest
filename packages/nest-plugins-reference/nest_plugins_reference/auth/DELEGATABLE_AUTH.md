# Delegatable Capability Auth Plugin

**Layer:** 2 (Auth)  
**Author:** anilchowdary07 (Hackathon Submission)  

This plugin introduces **offline, delegatable capability tokens** to Nanda Town, solving one of the most critical security bottlenecks in multi-agent orchestration: **The Confused Deputy & Secrets Sprawl Problem.**

## 🌟 The Problem We Solve
In standard multi-agent systems, when a "Coordinator Agent" needs 50 "Worker Agents" to read a database, it usually shares a static API key or an overarching JWT token. 

This creates massive security vulnerabilities:
1. **Secrets Sprawl:** If a single worker goes rogue or gets compromised, the attacker has full access.
2. **Revocation Nightmare:** To stop the rogue worker, you must rotate the global API key, instantly crashing the Coordinator and the other 49 innocent workers.
3. **The Confused Deputy:** A malicious worker could trick a downstream service into executing actions on behalf of the Coordinator.

## 🚀 Our Solution: Macaroon-Inspired Capability Tokens
We engineered a cryptographic token system that allows agents to safely delegate permissions *offline*, without ever talking to a central auth server. 

### Key Capabilities
* **Offline Attenuation:** A Coordinator agent can take its `["read", "write"]` token and locally derive a new token for a Worker that *only* has `["read"]` access, bound to a specific `resource_id`, with a shorter Time-To-Live (TTL).
* **Domain-Separated HKDF Key Derivation:** We utilize strict `HKDF-Expand` logic. A child token's signature key is cryptographically derived from the parent's signature mixed with a 128-bit random nonce (`cap/v1/delegate/{nonce}`). This mathematically prevents key-coupling attacks.
* **O(1) Transitive Revocation (Epoch Fencing):** If the Coordinator's token is revoked, our verifier doesn't need to traverse a massive database to find and revoke the 50 child tokens. Because every child is cryptographically anchored to its parent's chain hash, revoking the parent **instantly and mathematically invalidates all descendants in $O(1)$ time.**
* **Strict Resource Binding:** Tokens can be pinned to exact `resource_id`s (e.g., `urn:data:climate`). Once pinned, no downstream agent can ever broaden or alter that resource boundary.

---

## 🛡️ Defeating Adversarial Attacks
This plugin was built with a paranoid security mindset. We implemented strict invariants to automatically defeat common attack vectors:

| Attack Vector | Our Mitigation |
| :--- | :--- |
| **Scope Escalation** | `verify()` forces strict subset constraints. A child trying to add a `"write"` scope to a `"read"` parent token is mathematically rejected. |
| **Depth Tampering** | Every token payload carries an immutable `depth` integer. Tampering with a mid-chain depth instantly fails signature validation. |
| **Replay & Splice Attacks** | Signatures are strictly bound to a `chain_hash`. You cannot splice a child token onto a different parent token. |
| **Stale Epoch (Partition) Fencing** | If a verifier node loses connection and its clock/epoch falls behind the global `min_required_epoch`, it **fails closed**. This prevents attackers from exploiting stale nodes to use revoked tokens. |

---

## 💻 How It Works (Usage)

### 1. Issuing a Root Token
The central server issues a root token to the Coordinator Agent.
```python
auth = DelegatableAuth(secret=b"super-secret-root-key")
root_token = await auth.issue(subject=AgentId("coordinator"), scopes=["read", "write", "execute"])
```

### 2. Offline Delegation (Coordinator -> Worker)
The Coordinator wants a Worker to read a specific database, but only for the next 60 seconds. The Coordinator does this *offline*, without needing the `super-secret-root-key`.
```python
child_token = await auth.delegate(
    parent_token=root_token, 
    audience=AgentId("worker-1"), 
    scopes=["read"],                  # Attenuated scope
    ttl=60.0,                         # Attenuated TTL (60 seconds)
    resource="urn:data:climate"       # Strict resource binding
)
```

### 3. Verification at the Resource Server
When the Worker tries to access the database, the Resource Server verifies the token.
```python
# The verifier checks the cryptographic chain, TTLs, and exact resource match
await auth.authorize(
    token=child_token, 
    presenter=AgentId("worker-1"), 
    required_scope="read", 
    resource_id="urn:data:climate"
)
# Success! Access granted.
```

## 🧪 Enterprise-Grade Testing
We didn't just write the code; we proved it works. Our submission includes rigorous, deterministic adversarial tests:
* Boundary TTL testing down to the exact millisecond (Testing `now == expires_at - 1ms` vs `now == expires_at`).
* Simulating multi-hop delegation chains (Root -> A -> B -> C) and attempting to tamper with B's depth to trick C.
* 100% pass rate in the NandaTown CI pipeline, including strict Pyright type-checking and Ruff linting.
