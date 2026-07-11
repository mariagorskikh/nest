# Delegatable capability tokens with cascading revocation

Hackathon submission for problem
[`04-auth-capability-delegation`](../../../../docs/hackathon/problems/04-auth-capability-delegation.md)
(difficulty: easy).

Named with an `_hmac` suffix (plugin key `delegatable_hmac`, scenario
`delegated_auth_hmac`) because another already-merged submission to the same
problem claimed the unsuffixed `delegatable` / `delegated_auth` names first;
this avoids colliding with it.

## The problem

The default auth plugin, [`jwt_auth.py`](jwt_auth.py), issues flat,
single-level tokens: `_revoked` tracks exact token strings with no notion of
a parent/child relationship. There is no way for an agent holding a token to
mint a narrower, time-boxed sub-token for another agent without going back
to the issuer, and no way for revoking one token to automatically invalidate
anything delegated from it.

## What I built

[`delegatable_hmac.py`](delegatable_hmac.py) — a new auth plugin, `DelegatableAuth`,
registered as `("auth", "delegatable_hmac")` in
[`nest_core/plugins.py`](../../../nest-core/nest_core/plugins.py). It adds a
single new method, `delegate(parent_token, audience, scopes_subset, ttl)`, on
top of the existing `issue`/`verify`/`revoke` surface, plus an optional
`presented_by` keyword on `verify`.

- **Delegation narrows, it doesn't reissue.** `delegate()` checks the
  child's scopes are a subset of the parent's and the child's expiry does
  not outlive the parent's, at mint time — the delegating agent does this
  itself, in-process, without the root issuer's involvement.
- **The chain is self-authenticating.** Each link's signature is an
  HMAC-SHA256 keyed on the *previous* link's signature (the root link is
  keyed on the shared secret). A link can only be produced by someone who
  already holds the entire preceding chain.
- **Revocation cascades by construction.** Revoking a token records only
  that token's own id in a single in-memory set. Every descendant carries
  its full ancestor-id chain in its own signed claims, so `verify` rejects a
  descendant the moment *any* id in its chain — not just its own — turns up
  revoked. No per-descendant bookkeeping.
- Four typed exceptions, all subclassing `ValueError` so existing
  `except ValueError` guards keep working: `ScopeEscalationError`,
  `ExcessiveTtlError`, `RevokedAncestorError`, `AudienceMismatchError`.

To satisfy the charter's "adversarial validator + scenario" requirement, I
also added:

- [`scenarios/delegated_auth_hmac.yaml`](../../../../scenarios/delegated_auth_hmac.yaml)
  and its factory,
  [`nest_core/scenarios_builtin/delegated_auth_hmac.py`](../../../nest-core/nest_core/scenarios_builtin/delegated_auth_hmac.py):
  a coordinator delegates to 3 intermediaries, each delegating further to 4
  leaves (12 total), then revokes one intermediary's token partway through.
  Every leaf verifies its token with a shared auditor both before and after
  that revocation. One designated leaf also probes audience confusion, and
  the coordinator separately attempts a scope-escalation delegation against
  its own root.
- Four validators in
  [`nest_core/validators.py`](../../../nest-core/nest_core/validators.py),
  registered under the scenario key `"delegated_auth_hmac"`:
  `auth_delegation_occurred`, `auth_scope_escalation_blocked`,
  `auth_cascading_revocation`, `auth_audience_confusion_blocked`.

## Commands to run it

```bash
uv sync

# Plugin unit tests (issue/delegate/verify/revoke, the three named attacks)
uv run pytest packages/nest-plugins-reference/tests/test_delegatable_hmac_auth.py -v

# Scenario + validator tests (synthetic-trace unit tests + real end-to-end runs)
uv run pytest packages/nest-core/tests/test_delegated_auth_hmac.py -v

# Full CI gate (what the charter requires before opening a PR)
uv run ruff check .
uv run ruff format --check .
uv run pyright
uv run pytest -v

# Run the scenario directly and validate the trace it produces
uv run nest run scenarios/delegated_auth_hmac.yaml
uv run python -c "from pathlib import Path; from nest_core.validators import validate_trace; \
    [print('PASS' if r.passed else 'FAIL', r.name, '-', r.detail) \
     for r in validate_trace(Path('traces/delegated_auth_hmac.jsonl'), 'delegated_auth_hmac')]"
```

## Before / after

Same scenario, same validators, only `layers.auth` changed.

**Before** (`auth: jwt`, the existing default — no code changes, this is
what ships on `main` today):

```
FAIL auth_delegation_occurred - no root token issued (auth plugin cannot delegate)
FAIL auth_scope_escalation_blocked - no scope-escalation attempt observed/blocked
FAIL auth_cascading_revocation - no revocation observed
FAIL auth_audience_confusion_blocked - no audience-confusion attempt observed
```

`jwt` has no `delegate` method at all. The scenario's coordinator
capability-gates on `hasattr(auth, "delegate")`, so nothing downstream ever
happens — that silence is itself the honest evidence of the gap, not a
crash.

**After** (`auth: delegatable_hmac`, this PR):

```
PASS auth_delegation_occurred - 15 delegations observed
PASS auth_scope_escalation_blocked - 1 scope-escalation attempt(s) correctly blocked
PASS auth_cascading_revocation - revoked subtree blocked; unrelated sibling subtree unaffected
PASS auth_audience_confusion_blocked - 1 audience-confusion attempt(s) correctly rejected
```

Full local CI gate as of this writing: `ruff check` clean, `ruff format
--check` clean, `pyright` 0 errors, `pytest` 770 passed / 1 pre-existing
unrelated skip / 1 deselected (`live` marker). Scenario trace verified
byte-identical across seeds 42, 7, 1337.

## Limits and honest caveats

- **Delegation is a strict tree**, not a DAG — one parent per token, per the
  problem brief's explicit suggestion. Multi-parent delegation is out of
  scope.
- **One shared auth-plugin instance per scenario, not per-agent.**
  Revocation state and the HMAC secret have to be shared for verification
  across agents to mean anything, so the scenario factory instantiates a
  single `DelegatableAuth` and injects it into every agent's constructor.
  This is different from per-agent layers like identity, and is a design
  choice specific to how this plugin is used in the scenario, not something
  enforced by the plugin itself.
- **The scenario uses a fixed simulated clock (`clock=0.0`)** for
  determinism. Tokens never naturally expire during the run, so "stale
  parent via natural expiry" is exercised only by a plugin unit test
  (`test_expired_parent_child_still_within_ttl_is_rejected`), not by the
  scenario/validator path. The scenario's "stale parent" coverage is the
  *explicit revocation* case specifically.
- **No hardware-backed key attestation, no OAuth2 server endpoints, no
  network token introspection** — this is pure in-process Python, matching
  `jwt_auth.py`'s scope.
- **`duration: "ticks: N"` in the scenario YAML is an event-processing
  budget, not virtual simulation time** (each popped queue event, including
  agent `start` events, consumes one tick regardless of its timestamp). I
  hit this directly: an initial `ticks: 50` silently truncated the run
  before most verify replies were ever processed, with no error — the
  scenario now uses `ticks: 5000`, which is comfortably sufficient for this
  agent/message count but is a real footgun worth knowing about if you
  scale the tree up.
- **Scope of changes**: confined to the new plugin file, its registry entry,
  the new scenario/factory/validators, and their tests. The only edit to a
  file outside that surface is a one-line addition to
  `test_validators.py::test_all_scenario_types_registered`, a pre-existing
  test that hand-enumerates every `VALIDATORS` key and needed updating for
  the new `"delegated_auth_hmac"` entry.
- **Not independently reviewed.** This has been tested by me (unit tests,
  scenario end-to-end runs, manual red/green verification, full CI gate)
  but not yet reviewed by anyone else.
