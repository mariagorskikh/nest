# Quickstart

Get from zero to a validated trace in about a minute.

## 1. Install

```bash
pip install "nest-core[plugins]"
```

This installs the CLI, the reference plugins for all 12 layers, and the
seven built-in scenarios. No `git clone` required.

Optional extras:

```bash
pip install "nest-core[llm]"        # Tier 2 LLM agents (nest-shell)
pip install "nest-core[full]"       # plugins + llm
```

## 2. Verify

```bash
nest doctor
```

You should see `7/7 checks passed`. If you don't, the output names the
exact check that failed.

## 3. Run a built-in scenario

```bash
nest run marketplace
```

Output:

```
Running scenario: marketplace
  agents: 100  seed: 42  ticks: 10000
Trace written to: traces/marketplace.jsonl
```

Same seed → byte-identical trace, every time.

> **Don't run `nest run scenarios/marketplace.yaml`.** That only works
> inside a clone of the repo, because pip doesn't install the
> `scenarios/` directory. Use the built-in name `marketplace`, or copy a
> scenario out to edit (see step 5).

## 4. Look at the result

```bash
# Quick text summary
nest inspect ./traces/marketplace.jsonl

# HTML metrics report
nest report ./traces/marketplace.jsonl -o report.html

# Interactive dashboard (opens a browser)
nest dashboard ./traces/marketplace.jsonl
```

Property-level validation (this is where Nanda Town proves your protocol does
what you claim):

```bash
python -c "
from pathlib import Path
from nest_core.validators import validate_trace
for r in validate_trace(Path('traces/marketplace.jsonl'), 'marketplace'):
    print(('PASS' if r.passed else 'FAIL'), r.name, '-', r.detail)
"
```

> **Heads-up.** Validators check protocol invariants encoded in the trace.
> Passing validators are useful regression signals, not formal proofs of
> protocol correctness. See [README §Validators](../README.md#validators).

## 5. Edit a scenario

```bash
nest scenarios list                       # see what's bundled
nest scenarios show marketplace           # print YAML to stdout
nest scenarios cp marketplace ./my.yaml   # copy to disk for editing
nest run ./my.yaml                        # run the local copy
```

Try changing `failures.message_drop` from `0.0` to `0.05` and re-running
to see how a 5% drop rate affects `delivery_rate` and `deal_rate` in the
report.

## What's next

- **Test an existing OpenClaw agent:** [bring-your-agent.md](bring-your-agent.md)
- **Build or automate an advanced agent adapter:**
  [agent-test-adapter-reference.md](agent-test-adapter-reference.md)
- **Plug in your own layer:** [writing-a-plugin.md](writing-a-plugin.md)
- **Build a new scenario:** [writing-a-scenario.md](writing-a-scenario.md)
- **How the layers fit together:** [concepts.md](concepts.md)
