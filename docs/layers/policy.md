# Policy

The policy layer is the decision point an agent calls before it uses a tool,
publishes data, spends credits, or changes authority.  It turns a structured
`PolicyRequest` into a deterministic `PolicyDecision`: `permit`, `deny`, or
`approval_required`.

This layer is intentionally small.  It does not execute the action and it does
not replace auth, privacy, payments, or trust.  It answers one question: given
the actor, action, resource, data classes, and optional amount, may the agent
continue?

## Interface

Implementations satisfy `nest_core.layers.policy.Policy`:

```python
decision = await policy.decide(request, now=ctx.time)
```

`now` is the simulator's logical time.  Implementations should not read wall
clock time, random sources, or process-local mutable state unless that state is
derived from previous replayable observations.

## Reference Plugins

`strict_rules` is deny-by-default.  It permits declared low-risk reads, denies
sensitive public exports, requires approval for high-value transfers, and denies
unknown actions.

`allow_all` is a deliberately unsafe baseline.  The `policy_guard` scenario uses
it as the foil: the same trace validators that pass under `strict_rules` fail
under `allow_all`.

## Scenario

Run the built-in scenario:

```bash
uv run nest run scenarios/policy_guard.yaml
```

Then validate the trace:

```bash
uv run python - <<'PY'
from pathlib import Path
from nest_core.validators import validate_trace

for result in validate_trace(Path("traces/policy_guard.jsonl"), "policy_guard"):
    print(result)
PY
```

The scenario emits canonical JSON request and decision events for a safe read, a
sensitive public export, a high-value payment, and an undeclared admin action.
Validators assert that the policy permits the safe read, blocks public sensitive
data, requires approval for high-impact spend, and denies undeclared actions.
