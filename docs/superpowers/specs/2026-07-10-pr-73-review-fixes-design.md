# PR #73 Review Fixes Design

## Goal

Make the capability-token submission mergeable and satisfy every actionable maintainer request without changing its security model or the public `Auth.verify(token)` protocol.

## Rebase and Conflict Resolution

Rebase `hackathon/capsec-engineer-offline-attenuation` onto the latest upstream `main`. Resolve shared-registry conflicts additively in `plugins.py`, `scenarios.py`, and `validators.py`: retain all registrations already present on `main` and restore the capability-token plugin, delegated-auth scenario, and delegated-auth validator registrations exactly once. If upstream has merged another `delegated_auth` scenario, preserve it unchanged and register this submission's scenario under the unique `capability_tokens_delegated_auth` name.

The existing untracked `PR_BODY.md` and `report.html` files are user-owned and must remain untouched.

## Trace Evidence Format

Replace the ambiguous `auth:<kind>:key=value:key=value` encoding with:

```text
auth:<kind>|key=value|key=value
```

The colon remains only between the `auth` namespace and event kind. A pipe separates fields, so scope values such as `admin:all`, `alpha:read`, and `payments:read` survive parsing unchanged. The emitter and parser change together; no capability-token cryptography or runtime authorization behavior changes.

## Validator Coverage

Strengthen `validate_delegated_auth_scope_escalation_blocked` so a passing result requires trace evidence with all three facts on the same row:

- `requested == "admin:all"`
- `rejected == "1"`
- `error == "ScopeEscalationError"`

This makes the separator fix load-bearing: truncating the scope value causes the validator to fail. Existing end-to-end scenario tests exercise the assertion with the capability-token plugin and continue proving that the baseline JWT plugin fails the adversarial validators.

## PR Differentiation

Add a concise PR-body paragraph distinguishing the submission from a plain HMAC-chained macaroon. It will name:

- the fail-closed `stale_after` / `RevocationViewStaleError` epoch fence;
- the `authorize()` resource guard for confused-deputy prevention; and
- the scenario's partition group split and `partition_heal_at_tick: 80`, which keep the epoch fence load-bearing.

## Verification and Delivery

Run the maintainer's complete gate on the rebased branch:

```bash
uv sync
uv run ruff check .
uv run ruff format --check .
uv run pyright
uv run pytest -v
```

After all stages pass, commit the implementation, force-push the rebased branch using `--force-with-lease`, update the PR body, and verify that PR #73 is mergeable and that CI checks are reported. Do not resolve threads or post a re-review request unless explicitly authorized.
