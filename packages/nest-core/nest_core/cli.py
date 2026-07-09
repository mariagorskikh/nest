# SPDX-License-Identifier: Apache-2.0
"""Nanda Town CLI entry point.
Example::
    nest run scenarios/marketplace.yaml
    nest doctor
    nest init my-scenario
    nest plugins list
"""

from __future__ import annotations
import asyncio
import json
import sys
from pathlib import Path
from typing import Any, cast
import typer
from pydantic import ValidationError


def _typer_argument(*args: Any, **kwargs: Any) -> Any:
    return typer.Argument(*args, **kwargs)  # pyright: ignore[reportUnknownMemberType]


def _typer_option(*args: Any, **kwargs: Any) -> Any:
    return typer.Option(*args, **kwargs)  # pyright: ignore[reportUnknownMemberType]


app = typer.Typer(
    name="nest",
    help="Nanda Town",
    no_args_is_help=True,
)
plugins_app = typer.Typer(help="Manage plugins.")
app.add_typer(plugins_app, name="plugins")
scenarios_app = typer.Typer(help="Inspect and copy built-in scenarios.")
app.add_typer(scenarios_app, name="scenarios")
templates_app = typer.Typer(help="Manage agent templates.")
app.add_typer(templates_app, name="templates")
worker_app = typer.Typer(help="Run distributed simulation workers.")
app.add_typer(worker_app, name="worker")


def _resolve_scenario_arg(scenario: str) -> Path | None:
    """Resolve a `nest run` argument to a real YAML path.
    Resolution order, first hit wins:
      1. ``scenario`` is an existing file path.
      2. ``scenario`` is the name of a built-in scenario shipped in the wheel.
      3. ``./scenarios/<scenario>.yaml`` relative to the current directory.
    Returns ``None`` if nothing resolves.
    """
    from nest_core.builtin_scenarios import builtin_path, is_builtin

    p = Path(scenario)
    if p.exists():
        return p
    if is_builtin(scenario):
        return builtin_path(scenario)
    local = Path("scenarios") / f"{scenario}.yaml"
    if local.exists():
        return local
    return None


@app.command()
def run(
    scenario: str = _typer_argument(
        help=(
            "Built-in scenario name (e.g. `marketplace`) or path to a YAML file. "
            "Run `nest scenarios list` to see what's bundled."
        ),
    ),
    seed: int | None = _typer_option(None, help="Override the scenario seed."),
    ticks: int | None = _typer_option(None, help="Override max ticks."),
    output: str | None = _typer_option(None, "-o", "--output", help="Override trace output path."),
    parallel: bool = _typer_option(
        False,
        "--parallel",
        help="Enable non-deterministic parallel agent execution (faster, not byte-identical).",
    ),
    workers: int = _typer_option(
        1,
        "--workers",
        min=1,
        help="Split agents across N worker processes (implies --parallel when N>1).",
    ),
    worker_bind: str | None = _typer_option(
        None,
        "--worker-bind",
        help="HTTP bind address for worker bridges (default 127.0.0.1; use 0.0.0.0 for LAN).",
    ),
    worker_hosts: str | None = _typer_option(
        None,
        "--worker-hosts",
        help="Comma-separated advertise hosts for each worker (multi-machine routing).",
    ),
    worker_mode: str | None = _typer_option(
        None,
        "--worker-mode",
        help="Worker launch mode: auto (spawn subprocesses) or manual (wait for remote workers).",
    ),
) -> None:
    """Run a scenario from a YAML file or a built-in scenario name."""
    from nest_core.builtin_scenarios import list_builtin
    from nest_core.scenario import ScenarioConfig

    path = _resolve_scenario_arg(scenario)
    if path is None:
        typer.echo(f"Error: no scenario named or located at {scenario!r}.", err=True)
        typer.echo("", err=True)
        typer.echo("Built-in scenarios you can run by name:", err=True)
        for name in list_builtin():
            typer.echo(f"  nest run {name}", err=True)
        typer.echo("", err=True)
        typer.echo(
            "Or pass a path to your own YAML, "
            "or copy a built-in to edit: nest scenarios cp marketplace .",
            err=True,
        )
        raise typer.Exit(1)
    try:
        config = ScenarioConfig.from_yaml(path)
    except ValidationError as e:
        typer.echo(f"Error: invalid scenario {scenario}:", err=True)
        for err in e.errors():
            loc = ".".join(str(p) for p in err["loc"])
            typer.echo(f"  {loc}: {err['msg']}", err=True)
        raise typer.Exit(1) from None
    if seed is not None:
        config.seed = seed
    if ticks is not None:
        config.duration = f"ticks: {ticks}"
    if output is not None:
        config.output.trace = output
    if parallel:
        config.parallel = True
    if workers > 1:
        config.workers = workers
        config.parallel = True
    if worker_bind is not None:
        config.worker_bind = worker_bind
    if worker_hosts is not None:
        config.worker_hosts = [h.strip() for h in worker_hosts.split(",") if h.strip()]
    if worker_mode is not None:
        config.worker_mode = worker_mode
    max_ticks = config.get_max_ticks()
    if max_ticks <= 0:
        typer.echo(
            f"Error: duration must resolve to a positive tick count (got {max_ticks}).",
            err=True,
        )
        raise typer.Exit(1)
    if config.agents.count < 0:
        typer.echo(
            f"Error: agents.count must be >= 0 (got {config.agents.count}).",
            err=True,
        )
        raise typer.Exit(1)
    typer.echo(f"Running scenario: {config.name}")
    typer.echo(f"  agents: {config.agents.count}  seed: {config.seed}  ticks: {max_ticks}")
    if config.parallel:
        typer.echo("  mode: parallel (traces may not be byte-identical)")
    if config.workers > 1:
        typer.echo(f"  workers: {config.workers} (distributed, non-deterministic)")
        if config.worker_mode == "manual":
            typer.echo("  worker mode: manual (waiting for remote workers)")
        if config.worker_hosts:
            typer.echo(f"  worker hosts: {', '.join(config.worker_hosts)}")
    trace_path = asyncio.run(_run_scenario(config))
    typer.echo(f"Trace written to: {trace_path}")


async def _run_scenario(config: Any) -> Path:
    from nest_core.runner import ScenarioRunner

    runner = ScenarioRunner(config)
    return await runner.run()


@app.command()
def init(
    name: str = _typer_argument("my-scenario", help="Name for the new scenario."),
    directory: str | None = _typer_option(
        None,
        "-d",
        "--dir",
        help="Directory to create the file in.",
    ),
) -> None:
    """Scaffold a new scenario YAML file."""
    target_dir = Path(directory) if directory else Path("scenarios")
    target_dir.mkdir(parents=True, exist_ok=True)
    filename = f"{name}.yaml"
    filepath = target_dir / filename
    if filepath.exists():
        typer.echo(f"Error: {filepath} already exists.", err=True)
        raise typer.Exit(1)
    template = f"""\
# Nanda Town scenario: {name}
name: {name}
description: "TODO: describe your scenario"
tier: 1
seed: 42
agents:
  count: 20
  brain: state-machine
  roles:
    - name: buyer
      count: 10
    - name: seller
      count: 10
layers:
  transport: in_memory
  comms: nest_native
  identity: ed25519_rotating
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
  type: marketplace
  config:
    rounds: 5
duration: "ticks: 5000"
metrics:
  - success_rate
  - mean_latency
  - message_count
output:
  trace: ./traces/{name}.jsonl
"""
    filepath.write_text(template)
    typer.echo(f"Created scenario: {filepath}")


@app.command()
def doctor(
    distributed: str | None = _typer_option(
        None,
        "--distributed",
        help="Path to worker manifest dir (contains routes.json) to verify HTTP health.",
    ),
) -> None:
    """Check installation, plugin compatibility, and system health."""
    if distributed is not None:
        _doctor_distributed(Path(distributed))
        return
    checks_passed = 0
    checks_failed = 0
    typer.echo("Nanda Town doctor")
    typer.echo("=" * 40)
    # Python version
    py = sys.version_info
    if py >= (3, 12):
        typer.echo(f"  [OK] Python {py.major}.{py.minor}.{py.micro}")
        checks_passed += 1
    else:
        typer.echo(f"  [FAIL] Python {py.major}.{py.minor} (need >= 3.12)")
        checks_failed += 1
    # Core imports
    core_modules = [
        ("nest_core", "nest-core"),
        ("nest_core.scenario", "scenario loader"),
        ("nest_core.plugins", "plugin registry"),
        ("nest_core.runner", "scenario runner"),
        ("nest_core.sim.simulator", "simulator"),
    ]
    for mod_name, label in core_modules:
        try:
            __import__(mod_name)
            typer.echo(f"  [OK] {label}")
            checks_passed += 1
        except ImportError as e:
            typer.echo(f"  [FAIL] {label}: {e}")
            checks_failed += 1
    # Plugin resolution
    try:
        from nest_core.plugins import PluginRegistry

        reg = PluginRegistry()
        layers = [
            "transport",
            "comms",
            "identity",
            "registry",
            "auth",
            "trust",
            "payments",
            "coordination",
            "negotiation",
            "memory",
            "privacy",
            "datafacts",
        ]
        plugin_ok = 0
        for layer_name in layers:
            try:
                reg.resolve(layer_name, _default_for(layer_name))
                plugin_ok += 1
            except KeyError:
                typer.echo(f"  [FAIL] plugin: {layer_name}")
                checks_failed += 1
        if plugin_ok == len(layers):
            typer.echo(f"  [OK] all {len(layers)} default plugins resolve")
            checks_passed += 1
    except Exception as e:
        typer.echo(f"  [FAIL] plugin registry: {e}")
        checks_failed += 1
    typer.echo("=" * 40)
    total = checks_passed + checks_failed
    typer.echo(f"{checks_passed}/{total} checks passed")
    if checks_failed > 0:
        raise typer.Exit(1)


def _doctor_distributed(manifest_dir: Path) -> None:
    """Verify worker HTTP health endpoints from a distributed manifest."""
    from nest_core.sim.network_runner import check_health

    routes_path = manifest_dir / "routes.json"
    if not routes_path.exists():
        typer.echo(f"Error: routes.json not found in {manifest_dir}", err=True)
        raise typer.Exit(1)
    routes = json.loads(routes_path.read_text(encoding="utf-8"))
    if not isinstance(routes, dict):
        typer.echo("Error: routes.json must be a JSON object", err=True)
        raise typer.Exit(1)
    route_map = cast("dict[str, str]", routes)
    bases = sorted({v.rstrip("/") for v in route_map.values()})
    typer.echo("Nanda Town doctor (distributed)")
    typer.echo("=" * 40)
    failed = 0
    for base in bases:
        ok = asyncio.run(check_health(base))
        if ok:
            typer.echo(f"  [OK] {base}/health")
        else:
            typer.echo(f"  [FAIL] {base}/health unreachable")
            failed += 1
    typer.echo("=" * 40)
    if failed:
        raise typer.Exit(1)


@worker_app.command("run")
def worker_run(
    spec: str = _typer_option(..., "--spec", help="Path to worker-N-spec.json manifest."),
) -> None:
    """Run a single distributed worker from a coordinator manifest spec."""
    from nest_core.sim.worker_main import run_worker_spec

    spec_path = Path(spec)
    if not spec_path.exists():
        typer.echo(f"Error: worker spec not found: {spec}", err=True)
        raise typer.Exit(1)
    exit_code = asyncio.run(run_worker_spec(spec_path))
    raise typer.Exit(exit_code)


def _default_for(layer: str) -> str:
    defaults: dict[str, str] = {
        "transport": "in_memory",
        "comms": "nest_native",
        "identity": "ed25519_rotating",
        "registry": "in_memory",
        "auth": "jwt",
        "trust": "score_average",
        "payments": "prepaid_credits",
        "coordination": "contract_net",
        "negotiation": "alternating_offers",
        "memory": "blackboard",
        "privacy": "noop",
        "datafacts": "datafacts_v1",
    }
    return defaults[layer]


@app.command()
def inspect(
    trace: str = _typer_argument(help="Path to a JSONL trace file."),
) -> None:
    """Inspect and summarize a trace file."""
    from nest_core.inspect import analyze_trace, format_summary

    path = Path(trace)
    if not path.exists():
        typer.echo(f"Error: trace file not found: {trace}", err=True)
        raise typer.Exit(1)
    summary = analyze_trace(path)
    typer.echo(format_summary(summary))


@app.command()
def report(
    trace: str = _typer_argument(help="Path to a JSONL trace file."),
    output: str | None = _typer_option(None, "-o", "--output", help="Output HTML report path."),
    metrics: str | None = _typer_option(
        None,
        "-m",
        "--metrics",
        help="Comma-separated metric names.",
    ),
) -> None:
    """Compute metrics and generate an HTML report from a trace."""
    from nest_core.metrics import ALL_METRICS, compute_metrics, generate_html_report

    path = Path(trace)
    if not path.exists():
        typer.echo(f"Error: trace file not found: {trace}", err=True)
        raise typer.Exit(1)
    metric_names = metrics.split(",") if metrics else ALL_METRICS
    results = compute_metrics(path, metric_names)
    typer.echo("Metrics:")
    for name, value in sorted(results.items()):
        typer.echo(f"  {name:20s} {value:.4f}")
    if output:
        out_path = generate_html_report(path, results, output)
        typer.echo(f"\nReport written to: {out_path}")


@app.command()
def dashboard(
    trace: str | None = _typer_argument(None, help="Optional trace file to load."),
    port: int = _typer_option(8080, help="Port to serve on."),
) -> None:
    """Open the lightweight static trace viewer in a browser.
    Serves apps/dashboard/index.html (offline, no npm required). For the full
    Next.js hackathon app with marketplace pages, run:
    cd apps/nest-dashboard && npm run dev
    """
    import functools
    import http.server
    import threading
    import webbrowser

    dashboard_html = _find_dashboard_html()
    if dashboard_html is None:
        typer.echo("Error: cannot locate apps/dashboard/index.html", err=True)
        raise typer.Exit(1)
    dashboard_dir = dashboard_html.parent
    html_content = dashboard_html.read_text(encoding="utf-8")
    if trace is not None:
        trace_path = Path(trace)
        if not trace_path.exists():
            typer.echo(f"Error: trace file not found: {trace}", err=True)
            raise typer.Exit(1)
        trace_text = trace_path.read_text(encoding="utf-8")
        # The dashboard reads the trace into a double-quoted JS string literal,
        # so we must escape backslashes, double quotes, newlines, carriage
        # returns, and the </script> sequence that would break out of the tag.
        escaped = (
            trace_text.replace("\\", "\\\\")
            .replace('"', '\\"')
            .replace("\r", "\\r")
            .replace("\n", "\\n")
            .replace("</", "<\\/")
        )
        html_content = html_content.replace("__NEST_TRACE_DATA__", escaped)
    # Serve from a temporary directory with the (possibly modified) HTML
    import tempfile

    serve_dir = tempfile.mkdtemp(prefix="nest-dashboard-")
    serve_path = Path(serve_dir) / "index.html"
    serve_path.write_text(html_content, encoding="utf-8")
    d3_src = dashboard_dir / "d3.min.js"
    if d3_src.exists():
        (Path(serve_dir) / "d3.min.js").write_bytes(d3_src.read_bytes())
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=serve_dir)
    server = http.server.HTTPServer(("127.0.0.1", port), handler)
    url = f"http://127.0.0.1:{port}"
    typer.echo(f"Serving dashboard at {url}")
    if trace is not None:
        typer.echo(f"  trace: {trace}")
    typer.echo("Press Ctrl+C to stop.\n")

    # Open browser after a short delay so the server is ready
    def _open_browser() -> None:
        import time

        time.sleep(0.4)
        webbrowser.open(url)

    t = threading.Thread(target=_open_browser, daemon=True)
    t.start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        typer.echo("\nShutting down.")
    finally:
        server.server_close()


def _find_dashboard_html() -> Path | None:
    """Locate the dashboard HTML file relative to the project root."""
    # Walk up from this file to find the repo root (contains pyproject.toml workspace)
    candidates: list[Path] = []
    # Try relative to CWD
    candidates.append(Path.cwd() / "apps" / "dashboard" / "index.html")
    # Try relative to this source file
    cli_dir = Path(__file__).resolve().parent  # nest_core/
    for ancestor in [cli_dir.parent, cli_dir.parent.parent, cli_dir.parent.parent.parent]:
        candidates.append(ancestor / "apps" / "dashboard" / "index.html")
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


@app.command()
def version() -> None:
    """Print the Nanda Town version."""
    from nest_core import __version__

    typer.echo(f"nest {__version__}")


@scenarios_app.command("list")
def scenarios_list() -> None:
    """List the built-in scenarios bundled with nest-core."""
    from nest_core.builtin_scenarios import list_builtin

    names = list_builtin()
    if not names:
        typer.echo("No built-in scenarios are bundled.")
        return
    typer.echo("Built-in scenarios (run with `nest run <name>`):")
    for name in names:
        typer.echo(f"  {name}")


@scenarios_app.command("show")
def scenarios_show(
    name: str = _typer_argument(help="Built-in scenario name."),
) -> None:
    """Print the YAML for a built-in scenario to stdout."""
    from nest_core.builtin_scenarios import builtin_text, list_builtin

    try:
        typer.echo(builtin_text(name), nl=False)
    except KeyError:
        typer.echo(f"Error: no built-in scenario named {name!r}.", err=True)
        typer.echo("Available:", err=True)
        for n in list_builtin():
            typer.echo(f"  {n}", err=True)
        raise typer.Exit(1) from None


@scenarios_app.command("cp")
def scenarios_cp(
    name: str = _typer_argument(help="Built-in scenario name to copy."),
    dest: str = _typer_argument(
        ".",
        help="Destination directory or filename. Defaults to the current directory.",
    ),
    force: bool = _typer_option(
        False,
        "--force",
        "-f",
        help="Overwrite the destination if it already exists.",
    ),
) -> None:
    """Copy a built-in scenario YAML to a local path so you can edit and re-run it."""
    from nest_core.builtin_scenarios import builtin_text, list_builtin

    if name not in list_builtin():
        typer.echo(f"Error: no built-in scenario named {name!r}.", err=True)
        typer.echo("Available:", err=True)
        for n in list_builtin():
            typer.echo(f"  {n}", err=True)
        raise typer.Exit(1)
    dest_path = Path(dest)
    if dest_path.is_dir() or (not dest_path.exists() and dest.endswith("/")):
        dest_path = dest_path / f"{name}.yaml"
    if dest_path.exists() and not force:
        typer.echo(
            f"Error: {dest_path} already exists. Pass --force to overwrite.",
            err=True,
        )
        raise typer.Exit(1)
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    dest_path.write_text(builtin_text(name), encoding="utf-8")
    typer.echo(f"Wrote {dest_path}")
    typer.echo(f"Run it: nest run {dest_path}")


@plugins_app.command("list")
def plugins_list(
    layer: str | None = _typer_argument(None, help="Filter by layer name."),
) -> None:
    """List available plugins."""
    from nest_core.plugins import PluginRegistry

    reg = PluginRegistry()
    items = reg.list_plugins(layer)
    if not items:
        if layer:
            typer.echo(f"No plugins found for layer: {layer}")
        else:
            typer.echo("No plugins found.")
        return
    current_layer = ""
    for layer_name, plugin_name in items:
        if layer_name != current_layer:
            current_layer = layer_name
            typer.echo(f"\n{layer_name}:")
        typer.echo(f"  - {plugin_name}")


def _require_shell() -> None:
    try:
        __import__("nest_shell")
    except ImportError as e:
        typer.echo(
            'Error: nest-shell is not installed. Run: pip install "nest-core[llm]"',
            err=True,
        )
        raise typer.Exit(1) from e


@templates_app.command("list")
def templates_list() -> None:
    """List available agent templates."""
    _require_shell()
    from nest_shell.templates import TemplateRegistry

    reg = TemplateRegistry()
    templates = reg.list_templates()
    if not templates:
        typer.echo("No templates found.")
        return
    for tpl in templates:
        typer.echo(f"  {tpl.name:30s} {tpl.provider:10s} {tpl.model}")


@templates_app.command("show")
def templates_show(
    name: str = _typer_argument(help="Template name to display."),
) -> None:
    """Show details of a specific agent template."""
    _require_shell()
    from nest_shell.templates import TemplateRegistry

    reg = TemplateRegistry()
    try:
        tpl = reg.get_template(name)
    except KeyError:
        typer.echo(f"Error: template not found: {name}", err=True)
        raise typer.Exit(1) from None
    typer.echo(f"Name:        {tpl.name}")
    typer.echo(f"Description: {tpl.description}")
    typer.echo(f"Provider:    {tpl.provider}")
    typer.echo(f"Model:       {tpl.model}")
    typer.echo(f"Temperature: {tpl.temperature}")
    typer.echo(f"Max tokens:  {tpl.max_tokens}")
    typer.echo(f"\nSystem prompt:\n{tpl.system_prompt}")


@templates_app.command("create")
def templates_create(
    name: str = _typer_argument(help="Name for the new template."),
    prompt: str = _typer_option(
        "You are a helpful agent.",
        "--prompt",
        "-p",
        help="System prompt for the agent.",
    ),
    provider: str = _typer_option("openai", help="LLM provider."),
    model: str = _typer_option("gpt-4o-mini", help="Model name."),
) -> None:
    """Create a new agent template."""
    _require_shell()
    from nest_shell.templates import AgentTemplate, TemplateRegistry

    reg = TemplateRegistry()
    tpl = AgentTemplate(
        name=name,
        system_prompt=prompt,
        provider=provider,
        model=model,
    )
    path = reg.save_template(tpl)
    typer.echo(f"Created template: {path}")


@templates_app.command("duplicate")
def templates_duplicate(
    name: str = _typer_argument(help="Name of the template to duplicate."),
    new_name: str = _typer_argument(help="Name for the new copy."),
) -> None:
    """Duplicate an existing template under a new name."""
    _require_shell()
    from nest_shell.templates import TemplateRegistry

    reg = TemplateRegistry()
    try:
        new_tpl = reg.duplicate_template(name, new_name)
    except KeyError:
        typer.echo(f"Error: template not found: {name}", err=True)
        raise typer.Exit(1) from None
    typer.echo(f"Duplicated '{name}' as '{new_tpl.name}'")


if __name__ == "__main__":
    app()
