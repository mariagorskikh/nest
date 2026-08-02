# SPDX-License-Identifier: Apache-2.0
"""Run a Nanda Town scenario through the exact pipeline `nest run` uses.

Why this file exists instead of just `nest run town.yaml`
-----------------------------------------------------------
nest-core 0.1.4's task-type dispatch is a closed set of six hardcoded names.
Read `nest_core/scenarios.py`::

    def get_scenario_factory(name):
        if name not in _FACTORIES:
            _try_load_builtin(name)          # only knows 6 literal strings
        factory = _FACTORIES.get(name)
        if factory is None:
            raise KeyError(f"No scenario factory registered for {name!r}")
        return factory

Unlike the 12 layer plugins (`transport`, `payments`, ...), which
`nest_core.plugins.PluginRegistry` discovers via `nest.plugins.<layer>`
entry points, there is no entry-point group for scenario *task types*.
`register_scenario()` is the only way to add one, and it must run
in-process, before `ScenarioRunner` looks the name up. Verified by
actually running the bare CLI against a YAML with
`task.type: town_group_purchase`::

    $ nest run town.yaml
    ...
    KeyError: "No scenario factory registered for 'town_group_purchase'"

That is a real, reproducible finding about nest-core 0.1.4, not a guess —
see the report this scenario ships with.

This script does exactly what `nest_core.cli._run_scenario` does —
`ScenarioConfig.from_yaml(path)` then `ScenarioRunner(config).run()`, the
identical two calls the `nest` console script makes — with one addition:
importing `town_group_purchase` first, so its factory is registered before
the runner asks for it. It never calls the payments plugin directly; the
plugin is reached only from inside the scenario, through
`ctx.plugins["payments"]`, exactly like the bundled scenarios do.

Usage (no keys, no network — the plugin defaults to `simulated` mode)::

    .venv/Scripts/python.exe scenarios/run_town.py town.yaml
    .venv/Scripts/python.exe scenarios/run_town.py scenarios/town_prepaid_control.yaml
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

# So `import town_group_purchase` resolves regardless of the caller's cwd —
# the same reason nest_core.scenarios_builtin is a package next to its YAML.
sys.path.insert(0, str(Path(__file__).resolve().parent))

import town_group_purchase  # noqa: E402,F401  side effect: register_scenario()
from nest_core.runner import ScenarioRunner  # noqa: E402
from nest_core.scenario import ScenarioConfig  # noqa: E402


async def _main(path: Path) -> Path:
    config = ScenarioConfig.from_yaml(path)
    print(f"Running scenario: {config.name}")
    print(f"  agents: {config.agents.count}  seed: {config.seed}  ticks: {config.get_max_ticks()}")
    runner = ScenarioRunner(config)
    trace_path = await runner.run()
    print(f"Trace written to: {trace_path}")
    return trace_path


if __name__ == "__main__":
    default_path = Path(__file__).resolve().parent.parent / "town.yaml"
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else default_path
    if not target.exists():
        print(f"Error: no scenario file at {target}", file=sys.stderr)
        raise SystemExit(1)
    asyncio.run(_main(target))
