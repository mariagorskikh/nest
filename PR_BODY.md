# [Hackathon] trust-security-engineer: attested_peering operator delegation is not key-bound — trusted-operator impersonation

## TL;DR

The attested-peering trust plugin gates reputation on a "who do you work for?"
operator delegation. But the bytes the operator signed — `_delegation_msg` —
covered only `operator_id | agent_id | label`, **not the delegated agent's
public key**. A delegation was therefore a bearer token for a *string* id, not
a *keypair*. An attacker copies a genuine operator delegation off an honest
card, keeps the victim's `agent_id`, swaps in **its own** key, self-signs, and
is admitted **as the victim** with a trusted operator's authority — identity
impersonation that turns straight into reputation poisoning. The fix binds the
agent public key into the delegation message (v2), so a delegation authorises
exactly one keypair and is non-transferable. This PR ships the fix plus an
adversarial validator, a scenario attack role, and RED→GREEN + property +
unit tests.

## Persona: trust-security engineer

I read an operator delegation as a **capability bound to a principal's key**,
not a label. The moment a signed grant names only `agent_id` (a string an
attacker fully controls on its own card) and omits the key, the grant becomes
transferable: possession of the *ciphertext* confers the *authority*. The
attacker never breaks Ed25519, never steals a private key, never forges a
signature — it **replays a valid one onto a different subject**. That is the
classic key-substitution / unknown-key-share failure mode, and it is exactly
what a delegation must not permit.

## The vulnerability

The plugin's own docstrings advertised the safety property it did not have:

- Module docstring: *"a named operator delegated authority to **this agent** …
  via a signed delegation embedded in its passport."* — but the signature did
  not bind "this agent" to a key.
- Constructor comment (injection path): *"a peer that claims a delegation it was
  never granted produces a self-consistent card with an **invalid
  delegation_signature**."* — false under v1: a *copied* (not forged) signature
  verified fine, because the signed bytes never mentioned the agent's key.

**Attack.** Given any honest card `H` delegated by trusted operator `Op`:

1. Take `H.operator_id`, `H.operator_public_key`, `H.delegation_signature`
   verbatim (all public, on the wire in every hail).
2. Build a card that keeps `agent_id = "honest-0"` and `label`, but sets
   `public_key` = the **attacker's** key.
3. Self-sign the body with the attacker's key (valid — it is the card's key).
4. Complete the handshake signing the live transcript with the attacker's key.

Under v1: key possession passes (card key == attacker key, attacker signs the
transcript), the self-signature is valid, the copied delegation verifies
(`Op` did sign `delegation-v1|Op|honest-0|label`), and `Op` is on the roster.
Verdict **ALLOW** — the attacker is admitted **as `honest-0`**, and every
`report()` it files counts under the victim's identity.

## Root cause

`packages/nest-plugins-reference/nest_plugins_reference/trust/attested_peering.py`

```python
# v1 (vulnerable): signs only the id triple — transferable to ANY key
return DELEGATION_TAG + f"|{operator_id}|{agent_id}|{label}".encode()
```

`_verify_card` recomputed the same key-free message, so a copied signature over
a *different* card's key still verified. The delegation authorised a name, not a
keypair.

## The fix

Bind the agent public key into the signed delegation (v2), and pass it at both
call sites — `_verify_card` passes `card.public_key`, the sign path passes
`self._pub`. Tag bumped `nest-attest-delegation-v1` → `-v2` so a v1 signature
can never be reinterpreted as v2.

```python
DELEGATION_TAG = b"nest-attest-delegation-v2"

def _delegation_msg(operator_id, agent_id, label, agent_public_key) -> bytes:
    return (
        DELEGATION_TAG
        + f"|{operator_id}|{agent_id}|{label}|".encode()
        + _b64(agent_public_key).encode()
    )

# _verify_card:
msg = _delegation_msg(card.operator_id, card.agent_id, card.label, card.public_key)
```

Now a delegation issued for the honest key does not verify over the attacker's
key: the copied-delegation card dies at **friend-or-foe** with
`operator delegation signature invalid (agent not authorised)`. Verdict DENY.

## Why the existing tests and validators missed it

- **`test_impostor_signature_denied`** presents a stolen passport but signs the
  transcript with its own key → it dies earlier, at **key possession**, so it
  never exercises the delegation-binding path.
- **`test_forged_operator_delegation_denied`** uses a *bogus* delegation
  signature (`b"not-a-real-signature"`) → dies because the signature is invalid,
  which says nothing about a *genuine* signature being transferable.
- **No test copied a real, valid delegation onto a foreign key** — the exact
  gap this PR closes.
- **`validate_attested_no_denied_admitted`** parses verdicts via
  `_attested_verdicts`, which **drops `peer_id`** and keys purely on the
  transport `sender`. An attacker admitted under a *claimed* identity different
  from its transport id is invisible to it.

## Adversarial validator + scenario (what they catch)

**Validator** — `validate_attested_no_identity_substitution`
(`packages/nest-core/nest_core/validators.py`). The observer emits
`verdict:<sender>:<peer_id>:<decision>:<foe>:<data>:<work>` where `sender` is the
transport agent and `peer_id` is the identity the presented card *claims*.
Invariant: **every `ALLOW` must have `peer_id == sender`** — an admitted peer
must control the identity it claims. It FAILs on any `ALLOW` where a peer is
admitted under a foreign claimed id (the substitution), and passes vacuously on
baseline traces with no verdict lines. It is deliberately the complement of the
`sender`-keyed sibling validator that cannot see this.

**Scenario role** — `delegation_thief`
(`packages/nest-core/nest_core/scenarios_builtin/attested_peering.py`,
`scenarios/attested_peering.yaml`). Presents a card claiming `honest-0` with the
victim's copied operator delegation but the attacker's own key, self-signed by
the attacker. Under the fixed plugin its verdict is
`verdict:delegation_thief-0:honest-0:DENY:0:1:1` — DENY at friend-or-foe — so
`peer_id != sender` never coincides with `ALLOW` and the validator PASSes. Under
the pre-fix message format it would ALLOW as `honest-0`, and the validator
FAILs. Determinism is preserved (seeded key derivation only, no wall clock, no
`os.urandom`).

## Verify

```bash
# 1) Run the attack at the plugin API + the new validator/property tests
uv run pytest packages/nest-plugins-reference/tests/test_attested_peering.py \
  -k "copied_delegation or identity_substitution or validator_" -v

# 2) Run the full scenario and print the thief verdict + all three validators
uv run python -c "
import asyncio, tempfile, json
from pathlib import Path
from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig
from nest_core.plugins import PluginRegistry
from nest_core.validators import validate_trace
cfg = ScenarioConfig.from_yaml('scenarios/attested_peering.yaml')
with tempfile.TemporaryDirectory() as t:
    tp = Path(t)/'x.jsonl'
    cfg = cfg.model_copy(update={'output': cfg.output.model_copy(update={'trace': str(tp)})})
    asyncio.run(ScenarioRunner(cfg, registry=PluginRegistry()).run())
    for line in tp.read_text().splitlines():
        d = json.loads(line)
        if d.get('kind')=='send' and d.get('agent')=='observer' and 'delegation_thief' in d['msg'] and d['msg'].startswith('verdict'):
            print('THIEF:', d['msg'])
    for r in validate_trace(tp, 'attested_peering'):
        print(('PASS' if r.passed else 'FAIL'), r.name)
"
```

Expected output of step 2:

```
THIEF: verdict:delegation_thief-0:honest-0:DENY:0:1:1
PASS attested_no_denied_admitted
PASS attested_no_identity_substitution
PASS attested_sybil_quarantined
```

RED→GREEN evidence: with `_delegation_msg` reverted to the v1 (key-free) form,
`test_copied_delegation_on_foreign_key_denied` and
`test_property_copied_delegation_always_denied` both fail with
`assert 'ALLOW' == 'DENY'` (attacker admitted as `honest-0`); with the v2 fix
both pass.

## Limitations / Scope

- **Secondary hardening taken (defence in depth).** `evaluate_peer`'s
  "who do you work for?" check previously tested only `op_id in
  policy.trusted_operators` — membership by the **16-hex (64-bit) operator
  fingerprint**. This PR now also asserts
  `policy.trusted_operators[op_id] == peer_facts.operator_public_key` (full-key
  equality), so a 64-bit fingerprint second-preimage that presented a different
  operator key under a trusted id is rejected. Combined with the key-bound
  delegation, the operator identity is now pinned end-to-end. Covered by
  `test_operator_fingerprint_collision_rejected`.
- The fix is a **breaking wire change** (v1 delegations no longer verify). That
  is intentional: v1 delegations are exactly the transferable tokens being
  retired. Any deployment must re-issue delegations under v2.
- Scope is limited to the trust layer; no other layers or plugins are touched.
  The safety validator, Sybil-quarantine validator, and byte-determinism test
  all remain green.

---

🤖 Generated with [Claude Code](https://claude.com/claude-code)

https://claude.ai/code/session_0137ni2yk8VAh26RD6PBWThu
