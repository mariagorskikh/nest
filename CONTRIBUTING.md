# Contributing to Nanda Town

## Definition of Done

A change is **not done** until all five of the following commands exit `0` on
your machine, in order. CI runs the exact same sequence; running it locally
first is the difference between a green PR and a red one.

```bash
uv sync
uv run ruff check .
uv run ruff format --check .
uv run pyright
uv run pytest -v
```

The single-command shortcut is:

```bash
make ci-local
```

`make ci-local` runs the five commands above in order and hard-fails on the
first red command. Run it before every `git push`.

**Windows (no `make`):**

```powershell
.\scripts\ci-local.ps1
```

This runs the same five steps as `make ci-local` and CI.

**Why each command matters:**

1. **`uv sync`** — installs/refreshes the locked dependency set. If this fails,
   nothing below it can be trusted. Always run it first so you are testing
   against the same versions CI is.
2. **`uv run ruff check .`** — lint pass (E, F, I, N, W, UP, B, A, SIM, TCH).
   Catches dead imports, undefined names, suspicious comparisons, etc. Most
   agents already run this and call it "the tests"; it is **not** the tests.
3. **`uv run ruff format --check .`** — verifies formatting **without
   modifying files**. This is the single most common reason "passing locally"
   PRs go red in CI: contributors run `ruff check` but skip the format check.
   If this fails, run `uv run ruff format .` to fix it, then re-run the check.
4. **`uv run pyright`** — strict-mode type checker (see `[tool.pyright]` in
   `pyproject.toml`). Strict mode is enforced repository-wide; new code must
   be fully annotated. This is the second most common cause of "passes
   locally" PRs failing CI.
5. **`uv run pytest -v`** — the unit + property test suite (Hypothesis is in
   use). All packages under `packages/` are collected via the workspace
   `pyproject.toml`'s `testpaths`.

If any of the five fails, fix the underlying issue. Do **not** push and rely
on CI to tell you what is wrong — CI is a backstop, not a development loop.

For an even faster feedback loop, install the pre-commit hooks so ruff and
pyright run on every `git commit`:

```bash
make hooks
```

---

Thank you for your interest in contributing to Nanda Town. This document covers development setup, coding standards, and how to add scenarios and plugins.

## Development Setup

Nanda Town uses [uv](https://docs.astral.sh/uv/) for workspace management. All packages are in `packages/` and developed together.

```bash
# Clone and install
git clone https://github.com/projnanda/nandatown.git
cd nandatown
uv sync

# Run all tests
uv run pytest -v

# Run tests for a specific package
uv run pytest packages/nest-core/tests/ -v

# Lint
uv run ruff check .
uv run ruff format --check .

# Type check
uv run pyright

# Fix lint issues automatically
uv run ruff check --fix .
uv run ruff format .
```

### Requirements

- Python 3.12+
- [uv](https://docs.astral.sh/uv/) (any recent version)

### Verify your setup

```bash
uv run nest doctor
```

This checks Python version, core imports, and plugin resolution for all 12 layers.

## Code Style

- **Formatter/linter:** [ruff](https://docs.astral.sh/ruff/), configured in `pyproject.toml`. Line length is 100. Enforced rule sets: E, F, I, N, W, UP, B, A, SIM, TCH.
- **Type checker:** [pyright](https://github.com/microsoft/pyright) in strict mode.
- **License header:** Every Python source file starts with `# SPDX-License-Identifier: Apache-2.0`.
- **Docstrings:** All public functions and classes must have docstrings with an `Example::` block.

Example of a well-documented function:

```python
def compute_metrics(
    trace_path: str | Path,
    metric_names: list[str],
) -> dict[str, float]:
    """Compute requested metrics from a JSONL trace file.

    Example::

        results = compute_metrics("trace.jsonl", ["success_rate", "message_count"])
    """
    ...
```

- **Imports:** Use `from __future__ import annotations` in all modules. ruff enforces import sorting.
- **Type annotations:** All function signatures must have complete type annotations. Use `Any` sparingly and only where structural typing is genuinely needed (e.g., plugin dictionaries).

## Adding a New Scenario

A scenario consists of:

1. **Agent classes** that subclass `StateMachineAgent` (Tier 1) or use `ShellAgent` (Tier 2).
2. **A factory function** that creates agents from a `ScenarioConfig`.
3. **A YAML file** that defines scenario parameters.

### Step 1: Write agent classes and factory

Create a new file in `packages/nest-core/nest_core/scenarios_builtin/`:

```python
# packages/nest-core/nest_core/scenarios_builtin/my_scenario.py
# SPDX-License-Identifier: Apache-2.0
"""My scenario -- brief description of what it tests.

Example::

    agents = my_scenario_factory(config, plugins)
"""

from __future__ import annotations

from typing import Any

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId


class MyAgentA(StateMachineAgent):
    """Describe this agent's role and behavior."""

    async def on_start(self, ctx: AgentContext) -> None:
        # Called once when simulation begins
        await ctx.send(AgentId("other-0"), b"hello")

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        # Called when a message arrives
        ...

    async def on_stop(self, ctx: AgentContext) -> None:
        # Called when simulation ends
        ...


def my_scenario_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
) -> dict[AgentId, StateMachineAgent]:
    """Create agents for my_scenario.

    Example::

        agents = my_scenario_factory(config, plugins)
    """
    agents: dict[AgentId, StateMachineAgent] = {}
    # Parse config.task.config for scenario-specific parameters
    # Create and register agents...
    return agents
```

### Step 2: Register the factory

Add a case to `_try_load_builtin()` in `packages/nest-core/nest_core/scenarios.py`:

```python
elif name == "my_scenario":
    from nest_core.scenarios_builtin.my_scenario import my_scenario_factory
    register_scenario("my_scenario", my_scenario_factory)
```

### Step 3: Write the scenario YAML

Create `scenarios/my_scenario.yaml`:

```yaml
# SPDX-License-Identifier: Apache-2.0
name: my_scenario
description: "Brief description of what this scenario tests."

tier: 1
seed: 42

agents:
  count: 20
  brain: state-machine
  roles:
    - name: role_a
      count: 10
    - name: role_b
      count: 10

layers:
  transport: in_memory
  comms: nest_native
  identity: did_key
  registry: in_memory
  auth: jwt
  trust: score_average
  payments: prepaid_credits
  coordination: contract_net
  negotiation: alternating_offers
  memory: blackboard
  privacy: noop
  datafacts: datafacts_v1

task:
  type: my_scenario
  config:
    rounds: 5

failures:
  message_drop: 0.0

duration: "ticks: 10000"

metrics:
  - success_rate
  - message_count

output:
  trace: ./traces/my_scenario.jsonl
```

### Step 4: Add tests

Add a test that runs the scenario end-to-end and verifies basic invariants:

```python
@pytest.mark.asyncio
async def test_my_scenario_runs() -> None:
    config = ScenarioConfig.from_yaml("scenarios/my_scenario.yaml")
    runner = ScenarioRunner(config)
    trace_path = await runner.run()
    assert trace_path.exists()
    summary = analyze_trace(trace_path)
    assert summary.total_events > 0
    assert summary.agent_count == 20
```

Consider adding property-based tests with Hypothesis for protocol invariants (see `tests/test_properties.py` for examples).

## Writing a Plugin

A plugin implements one of the 12 layer interfaces defined in `packages/nest-core/nest_core/layers/`. All interfaces use `typing.Protocol` (structural typing), so your class does not need to inherit from the interface -- it just needs to implement the same method signatures.

### Step 1: Implement the interface

```python
# my_plugin/transport.py
# SPDX-License-Identifier: Apache-2.0
"""My custom transport plugin.

Example::

    transport = MyTransport(AgentId("a1"))
    await transport.send(AgentId("a2"), b"hello")
"""

from __future__ import annotations

from nest_core.types import AgentId, TransportCapabilities


class MyTransport:
    """Custom transport implementation.

    Example::

        transport = MyTransport(AgentId("a1"))
    """

    capabilities = TransportCapabilities(
        supports_streaming=False,
        ordered=True,
        reliable=True,
    )

    async def send(self, to: AgentId, payload: bytes) -> None:
        """Send a payload to a specific agent."""
        ...

    async def receive(self) -> tuple[AgentId, bytes]:
        """Wait for the next message and return (sender, payload)."""
        ...

    async def broadcast(self, payload: bytes) -> None:
        """Broadcast to all reachable agents."""
        ...
```

### Step 2: Register via entry points

In your package's `pyproject.toml`:

```toml
[project.entry-points."nest.plugins.transport"]
my_transport = "my_plugin.transport:MyTransport"
```

The entry point group must be `nest.plugins.<layer>` where `<layer>` is one of: `transport`, `comms`, `identity`, `registry`, `auth`, `trust`, `payments`, `coordination`, `negotiation`, `memory`, `privacy`, `datafacts`.

### Step 3: Use in a scenario

```yaml
layers:
  transport: my_transport
```

The `PluginRegistry` discovers plugins via entry points at startup and falls back to built-in defaults.

## Running CI Locally

The CI pipeline (`.github/workflows/ci.yml`) runs three jobs. Replicate them locally before opening a PR:

```bash
# Lint (must pass with zero issues)
uv run ruff check .
uv run ruff format --check .

# Type check (strict mode)
uv run pyright

# Tests (including property-based tests via Hypothesis)
uv run pytest -v
```

## Pull Request Process

1. Create a branch from `main`.
2. Make your changes. Ensure all three CI checks pass locally.
3. Write or update tests for any new functionality.
4. Open a PR with a clear description of what changed and why.
5. Address review feedback.

For larger changes (new layers, architectural modifications, new fidelity tiers), please open an issue first to discuss the approach.

## Reporting Bugs

Open an issue with:
- Steps to reproduce
- Expected behavior
- Actual behavior
- Output of `nest doctor`

## License

By contributing, you agree that your contributions will be licensed under Apache 2.0.
