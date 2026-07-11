# Comms replay-attack resistance (`replay_safe`)

## The problem

I originally picked problem **#01 — versioned message schemas**
([`docs/hackathon/problems/01-comms-schema-versioning.md`](../../problems/01-comms-schema-versioning.md)).
Before writing any code I checked the repo and found it was already solved
and merged: PR #18 shipped `comms/versioned.py` (forward/backward-compatible
envelopes), and a follow-on PR #105 shipped `comms/authenticated.py`
(HMAC tamper-evidence against version rollback and field-stripping).

Rather than re-solve a closed problem, I read both merged plugins looking
for a real gap. `authenticated.py`'s own docstring names one it explicitly
leaves open:

> "a *verbatim* re-send of a genuine envelope still verifies."
> "Bind a nonce/sequence into `metadata` to close that separately."

A captured, byte-identical copy of an honest, correctly-tagged envelope has
a perfectly valid HMAC tag — nothing was rewritten, so there's nothing for
the tamper check to catch. An on-path relay (or attacker) can record one
authentic envelope and re-send it, and `authenticated` accepts it again,
every time. For a non-idempotent message — a payment, a vote, a state
transition — that's a live replay/double-spend attack.

## What I built

- **`packages/nest-plugins-reference/nest_plugins_reference/comms/replay_safe.py`**
  — `ReplaySafeComms`, a subclass of `AuthenticatedComms`. It inherits all
  of `authenticated`'s version/tamper checks unchanged, and adds one thing:
  after a tag verifies, it checks whether `(sender, id)` has already been
  accepted. If so, it raises a typed `ReplayError` instead of decoding the
  envelope again. No new wire field is needed — the envelope `id` is already
  covered by the HMAC tag, so it's a free, tamper-evident nonce. The
  "already seen" set is a bounded, per-sender LRU window
  (`DEFAULT_REPLAY_WINDOW = 4096`) so a long-running agent's memory doesn't
  grow without bound.
- **Two adversarial validators** in `nest_core/validators.py`:
  `validate_comms_replay_resistance` (every delivery of an id *after* the
  first must be rejected) and `validate_comms_replay_honest_delivery` (the
  *first* delivery of every id must still be accepted — so a plugin can't
  "pass" by refusing all traffic). Both recompute ground truth from the raw
  wire deliveries in the trace, independent of whichever plugin produced
  the acks, so they can judge any comms plugin.
- **`nest_core/scenarios_builtin/comms_replay.py`** + **`scenarios/comms_replay.yaml`**
  — 8 peers each send one solo envelope (never replayed, a control) and one
  envelope that a relay captures and re-sends verbatim a second time. An
  auditor decodes everything with whichever comms plugin the scenario is
  configured to use.
- **Tests**: `packages/nest-plugins-reference/tests/test_replay_safe_comms.py`
  (plugin unit tests — replay rejection, per-sender isolation, window
  eviction, tamper-vs-replay ordering) and
  `packages/nest-core/tests/test_comms_replay.py` (validator unit tests on
  synthetic traces, plus end-to-end simulator runs).

## How to run it

```bash
uv sync

# Run the scenario (defaults to comms: replay_safe in the YAML)
uv run nest run scenarios/comms_replay.yaml

# Validate the resulting trace
uv run python -c "
from pathlib import Path
from nest_core.validators import validate_trace
for r in validate_trace(Path('traces/comms_replay.jsonl'), 'comms_replay'):
    print('PASS' if r.passed else 'FAIL', r.name, '-', r.detail)
"

# Just this feature's tests
uv run pytest packages/nest-plugins-reference/tests/test_replay_safe_comms.py \
              packages/nest-core/tests/test_comms_replay.py -v

# Full CI sequence (what actually gates a merge)
make ci-local
```

To see it fail on the pre-fix plugin, edit `scenarios/comms_replay.yaml` and
swap `comms: replay_safe` for `comms: authenticated` (or `versioned`, or
`nest_native`), then re-run the two commands above.

## Before / after (actual output)

**Before** — same scenario, `comms: authenticated` (the merged, pre-fix
plugin — no replay memory):

```
FAIL comms_replay_resistance - m-0-replayed: replay delivery #2 not rejected (got accepted); m-1-replayed: replay delivery #2 not rejected (got accepted); ... (8 total)
PASS comms_replay_honest_delivery - 16 first-time delivery(ies) correctly accepted
```

Every replayed envelope is silently accepted a second time. The tag is
valid — it's a byte-for-byte capture — so `authenticated` has nothing to
object to.

**After** — `comms: replay_safe`:

```
PASS comms_replay_resistance - 8 replayed envelope(s) correctly rejected after first delivery
PASS comms_replay_honest_delivery - 16 first-time delivery(ies) correctly accepted
```

Every replay is now rejected on the second delivery, and — the important
counter-check — every legitimate first-time delivery (solo and replayed
alike) still goes through. `replay_safe` doesn't "pass" by refusing traffic.

`make ci-local`: ruff check clean, ruff format clean, pyright 0 errors,
pytest 1177 passed / 1 skipped, deterministic under seeds 42/7/1337.

## Limits — read before relying on this

- **In-memory only.** The seen-id window lives in the `ReplaySafeComms`
  instance. If an agent process restarts, it forgets everything it had
  seen and a replay captured before the restart would go through again.
  A real deployment would need to persist the window or derive it from a
  durable monotonic counter, not the in-memory set this plugin uses.
- **Bounded window, not exact.** With `DEFAULT_REPLAY_WINDOW = 4096`, only
  the most recent 4096 ids per sender are remembered. A replay of an id
  old enough to have been evicted would be accepted as if new. The default
  is sized well above any single scenario's per-sender traffic in this
  repo, but it is a real, tunable trade-off between memory and window
  length, not a guarantee for arbitrary traffic volumes.
- **No key exchange.** Like `authenticated`, this plugin uses a fixed
  pre-shared `channel_secret` standing in for a real session key. It
  doesn't model how peers agree on that secret.
- **Doesn't detect out-of-order delivery, only exact duplicates.** This
  plugin answers "have I already accepted this exact id from this sender,"
  not "did these arrive in the order they were sent." Reordering without
  duplication is out of scope.
- **Single-process simulation.** Everything here runs inside Nanda Town's
  deterministic in-memory simulator. I have not tested this against a real
  network transport, clock skew, or genuinely concurrent processes.
