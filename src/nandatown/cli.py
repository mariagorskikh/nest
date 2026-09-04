"""The nandatown command: bring, connect, attempt, disrupt, inspect, improve.

One command interface for the whole town: deterministic Lab scenarios,
real-agent Track profiles, campaigns, evidence bundles, reports,
verification, replay, visualization, skills, layers, and the standalone
coordinator for bringing your own agent.
"""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .path_profiles import DEFAULT_PATH_PROFILE


def _is_lab(name: str) -> bool:
    from .sim.scenario import bundled_scenarios
    return (name in bundled_scenarios()
            or name.endswith((".yaml", ".yml")))


def cmd_run(args: argparse.Namespace) -> int:
    from .bundle import load_bundle
    from .profiles import PROFILES
    from .report import render_report

    name = args.name
    harnesses = {}
    for spec in args.agent:
        role, _, connector = spec.partition("=")
        if not connector:
            print(f"--agent {spec!r} must look like role=harness,"
                  " e.g. seller=cmd:'python my_agent.py'")
            return 2
        harnesses[role] = connector
    layer_overrides = {}
    for spec in args.layer:
        layer, _, plugin_id = spec.partition("=")
        if not plugin_id:
            print(f"--layer {spec!r} must look like layer=plugin.id")
            return 2
        layer_overrides[layer] = plugin_id
    if name in PROFILES:
        if args.plugin or layer_overrides:
            print("--plugin and --layer apply to Lab scenarios; Track"
                  " profiles run the fixed coordinator contract")
            return 2
        from .runner import RunnerUsageError, run_town
        print(f"nandatown {__version__}: Track run of {name}"
              " (real subprocess agents)")
        identity_dir = None
        if args.identity:
            from .identity_portable import default_keystore_dir
            identity_dir = args.identity_dir or default_keystore_dir()
        try:
            bundle_dir, result = run_town(name, args.out,
                                          model=args.model,
                                          harnesses=harnesses or None,
                                          identity_dir=identity_dir)
        except RunnerUsageError as exc:
            print(exc)
            return 2
    elif _is_lab(name):
        if harnesses:
            print("--agent applies to Track profiles; Lab scenarios use"
                  " the scripted reference agents")
            return 2
        from .sim.runner import run_lab
        print(f"nandatown {__version__}: Lab run of {name}"
              " (deterministic, no model, no tokens)")
        bundle_dir, result = run_lab(name, args.out, seed=args.seed,
                                     plugins=args.plugin or None,
                                     layer_overrides=layer_overrides
                                     or None)
    else:
        from .sim.scenario import bundled_scenarios
        print(f"unknown target {name!r}")
        print(f"lab scenarios:  {', '.join(sorted(bundled_scenarios()))}")
        print(f"track profiles: {', '.join(sorted(PROFILES))}")
        return 2
    print(render_report(load_bundle(bundle_dir)))
    print(f"Evidence bundle: {bundle_dir}")
    return 0 if result.verdict == "passed" else 1


def cmd_test_agent(args: argparse.Namespace) -> int:
    import shlex

    from .bundle import load_bundle
    from .report import render_report
    from .runner import run_town

    if args.url or args.index:
        from .path_runner import run_path_test

        print(f"nandatown {__version__}: path test of"
              f" {args.url or args.agent_name} under profile"
              f" {args.path_profile}")
        bundle_dir, result = run_path_test(
            args.url, args.out, profile_ref=args.path_profile,
            pin_card_digest=args.pin_card_digest,
            index_file=args.index, agent_name=args.agent_name)
        print(render_report(load_bundle(bundle_dir)))
        applicable = [s for s in result.stages
                      if s.status != "not_tested"]
        passed = sum(1 for s in applicable if s.status == "passed")
        print(f"{passed} of {len(applicable)} path stages passed.")
        print(f"Evidence bundle: {bundle_dir}")
        return 0 if result.verdict == "passed" else 1
    if not args.cmd and not args.wait:
        print("test an already-running agent with --url <endpoint>, or"
              " give a town-joining agent with --cmd \"...\" or --wait")
        return 2
    if args.cmd:
        external = {args.role: shlex.split(args.cmd)}
        creds_cb = None
    else:
        external = {args.role: None}

        def creds_cb(role, env):
            print(f"waiting for your {role}. Start it with this"
                  " environment:")
            for k, v in env.items():
                print(f"  export {k}={v}")
            print("then join, claim, work, acknowledge. The town is"
                  " watching.")

    print(f"nandatown {__version__}: testing your {args.role} against"
          f" profile {args.profile}")
    bundle_dir, result = run_town(args.profile, args.out,
                                  external=external,
                                  wait_timeout=args.timeout,
                                  on_credentials=creds_cb)
    print(render_report(load_bundle(bundle_dir)))
    applicable = [s for s in result.stages if s.status != "not_tested"]
    passed = sum(1 for s in applicable if s.status == "passed")
    print(f"{passed} of {len(applicable)} town stages passed.")
    print(f"Evidence bundle: {bundle_dir}")
    return 0 if result.verdict == "passed" else 1


def cmd_scenarios(_args: argparse.Namespace) -> int:
    from .sim.scenario import bundled_scenarios

    entries = bundled_scenarios()
    width = max(len(n) for n in entries)
    print("Lab scenarios (deterministic, run with: nandatown run <name>):")
    for name, description in entries.items():
        print(f"  {name.ljust(width)}  {description}")
    return 0


def cmd_profiles(_args: argparse.Namespace) -> int:
    from .profiles import DEFAULT_PROFILE, FAULT_DESCRIPTIONS, PROFILES

    width = max(len(n) for n in PROFILES)
    print("Track profiles (real subprocess agents over HTTP):")
    for name in PROFILES:
        marker = " (default)" if name == DEFAULT_PROFILE else ""
        print(f"  {name.ljust(width)}  {FAULT_DESCRIPTIONS[name]}{marker}")
    return 0


def cmd_layers(_args: argparse.Namespace) -> int:
    from .layers import DEFAULT_PLUGINS, plugins

    display = {"auth": "auth (authorization)",
               "data_facts": "data_facts (data facts)"}
    print("The twelve protocol layers and their registered plugins:")
    for layer, entries in plugins().items():
        print(f"  {display.get(layer, layer)}")
        for entry in entries:
            default = (" (default)"
                       if entry["plugin_id"] == DEFAULT_PLUGINS[layer]
                       else "")
            print(f"    {entry['plugin_id']}{default}  {entry['summary']}")
    print()
    print("A scenario swaps any plugin under its layers: mapping;"
          " register your own with @register(layer, plugin_id).")
    return 0


def cmd_skills(args: argparse.Namespace) -> int:
    from .skills import builtin_skills, skill_source, validate_skill

    if args.validate:
        with open(args.validate) as f:
            problems = validate_skill(f.read())
        if not problems:
            print(f"{args.validate}: valid SkillMD")
            return 0
        for p in problems:
            print(f"problem: {p}")
        return 1
    if args.name:
        print(skill_source(args.name), end="")
        return 0
    skills = builtin_skills()
    width = max(len(n) for n in skills)
    print("Registered SkillMDs (show one with: nandatown skills <name>):")
    for name, skill in skills.items():
        print(f"  {name.ljust(width)}  v{skill.version}  {skill.summary}")
    return 0


def cmd_onramp(args: argparse.Namespace) -> int:
    import json

    from .onramp import OnrampError, onramp

    try:
        candidate_dir = onramp(args.spec, name=args.name, out_dir=args.out)
    except OnrampError as exc:
        print(f"onramp failed: {exc}")
        return 1
    print(f"candidate written to {candidate_dir}")
    with open(f"{candidate_dir}/checks.jsonl") as f:
        for line in f:
            check = json.loads(line)
            print(f"  {check['test']:<18} {check['result']:<22}"
                  f" {'; '.join(check['evidence'][:2])}")
    print("status: candidate-unclaimed. The SKILL.md is a claim, not a"
          " fact; review the open questions, then town tests and"
          " provider authorization become separate evidence.")
    return 0


def cmd_services(args: argparse.Namespace) -> int:
    from .onramp import catalog_entries

    entries = catalog_entries(args.dir)
    if not entries:
        print(f"no services in {args.dir}; onboard one with:"
              " nandatown onramp <openapi.json>")
        return 0
    if args.name:
        entry = next((e for e in entries if e["name"] == args.name), None)
        if entry is None:
            print(f"no service {args.name!r} in the catalog")
            return 1
        with open(f"{args.dir}/{args.name}/SKILL.md") as f:
            print(f.read(), end="")
        return 0
    width = max(len(e["name"]) for e in entries)
    for e in entries:
        checks = e["checks"]
        print(f"{e['name'].ljust(width)}  {e['status']}"
              f"  ops {e['operations']}"
              f"  checks passed {checks['passed']}"
              f" failed {checks['failed']} unknown {checks['unknown']}"
              f"  {e['fingerprint'][:19]}")
    return 0


def cmd_import_pr(args: argparse.Namespace) -> int:
    import json

    from .protocols import ProtocolImportError, import_pr

    try:
        protocol_dir = import_pr(args.number, repo=args.repo,
                                 out_dir=args.out)
    except ProtocolImportError as exc:
        print(f"import failed: {exc}")
        return 1
    with open(f"{protocol_dir}/metadata.json") as f:
        metadata = json.load(f)
    print(f"imported {metadata['repo']}#{metadata['number']}:"
          f" {metadata['title']} (by {metadata['author']},"
          f" head {metadata['head_sha'][:12]})")
    with open(f"{protocol_dir}/checks.jsonl") as f:
        for line in f:
            check = json.loads(line)
            print(f"  {check['test']:<20} {check['result']:<22}"
                  f" {'; '.join(check['evidence'][:2])}")
    for note in metadata["skipped"]:
        print(f"  skipped: {note}")
    print("status: imported-untrusted. Importing never ran this code;"
          " test it against the reference agents when you choose:")
    for line in metadata["usage"] or [
            "  (no plugin, scenario, or skill detected; inspect"
            f" {protocol_dir} yourself)"]:
        print(f"  {line}")
    return 0


def cmd_protocols(args: argparse.Namespace) -> int:
    import json

    from .protocols import protocol_entries

    entries = protocol_entries(args.dir)
    if not entries:
        print(f"no imported protocols in {args.dir}; pull one with:"
              " nandatown import-pr <number>")
        return 0
    if args.name:
        entry = next((e for e in entries if e["name"] == args.name), None)
        if entry is None:
            print(f"no protocol {args.name!r} in the catalog")
            return 1
        with open(f"{args.dir}/{args.name}/metadata.json") as f:
            print(json.dumps(json.load(f), indent=2))
        return 0
    width = max(len(e["name"]) for e in entries)
    for e in entries:
        checks = e["checks"]
        print(f"{e['name'].ljust(width)}  {e['status']}"
              f"  by {e['author']}"
              f"  checks passed {checks['passed']}"
              f" failed {checks['failed']} unknown {checks['unknown']}")
    return 0


def cmd_campaign(args: argparse.Namespace) -> int:
    from .campaign import run_campaign

    campaign_dir, aggregate = run_campaign(args.name, args.trials, args.out,
                                           seed_base=args.seed_base)
    with open(f"{campaign_dir}/campaign-report.md") as f:
        print(f.read())
    print(f"Campaign bundle: {campaign_dir}")
    failed = aggregate["verdicts"].get("failed", 0) \
        + aggregate["verdicts"].get("error", 0)
    return 0 if failed == 0 else 1


def cmd_pulse(args: argparse.Namespace) -> int:
    from .pulse import export_records, render_pulse_report, run_pulse

    if args.report:
        print(render_pulse_report(args.db), end="")
        return 0
    if args.records:
        for record in export_records(args.db):
            print(record.model_dump_json())
        return 0
    targets = {}
    for target in args.target:
        name, _, url = target.partition("=")
        if not url:
            print(f"target {target!r} must look like name=url")
            return 2
        targets[name] = url
    if not targets:
        print("give at least one --target name=url, or --report /"
              " --records over an existing --db")
        return 2
    run_pulse(targets, count=args.count, interval=args.interval,
              db_path=args.db,
              on_probe=lambda name, r: print(
                  f"{name}: {'up' if r['ok'] else 'DOWN'}"
                  f" ({r['latency_ms']:.0f} ms)"))
    print()
    print(render_pulse_report(args.db), end="")
    return 0


def cmd_compare(args: argparse.Namespace) -> int:
    from .compare import run_comparison

    swaps = {}
    for spec in args.swap:
        layer, _, plugin_id = spec.partition("=")
        if not plugin_id:
            print(f"--swap {spec!r} must look like layer=plugin.id")
            return 2
        swaps[layer] = plugin_id
    if not swaps:
        print("give at least one --swap layer=plugin.id to compare"
              " against the baseline")
        return 2
    compare_dir, comparison = run_comparison(
        args.target, swaps, args.out, seed=args.seed,
        plugins=args.plugin or None)
    with open(f"{compare_dir}/comparison.md") as f:
        print(f.read())
    print(f"Comparison bundle: {compare_dir}")
    return 0


def cmd_receipt(args: argparse.Namespace) -> int:
    from .receipt import make_receipt

    path = make_receipt(args.bundle_dir)
    print(f"receipt written to {path}")
    print("sanitized and signed: the claim, digests, observer, window,"
          " coverage, and limitations; nothing private leaves the"
          " bundle")
    return 0


def cmd_verify_receipt(args: argparse.Namespace) -> int:
    from .receipt import verify_receipt

    problems = verify_receipt(args.receipt, bundle_dir=args.bundle)
    if not problems:
        print("receipt verifies: the named key committed to these exact"
              " bytes" + (" and the bundle matches" if args.bundle
                          else ""))
        print("commitment is not truth, independence, or safety")
        return 0
    for p in problems:
        print(f"problem: {p}")
    return 1


def cmd_proof(args: argparse.Namespace) -> int:
    from .receipt import render_proof

    ok, text = render_proof(args.bundle_dir,
                            freshness_days=args.freshness_days)
    print(text, end="")
    return 0 if ok else 1


def cmd_mirror(args: argparse.Namespace) -> int:
    from .mirror import mirror_bundle

    destination = mirror_bundle(args.bundle_dir, args.mirror_dir)
    print(f"mirrored to {destination}")
    print("the address is the bundle fingerprint; any mirror holding it"
          " can restore the run")
    return 0


def cmd_recover(args: argparse.Namespace) -> int:
    from .mirror import MirrorError, recover_bundle

    try:
        restored = recover_bundle(args.fingerprint, args.mirror,
                                  args.out)
    except MirrorError as exc:
        print(f"recovery failed: {exc}")
        return 1
    print(f"recovered and verified: {restored}")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    from .bundle import load_bundle
    from .report import render_report

    print(render_report(load_bundle(args.bundle_dir)))
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    from .bundle import verify_bundle

    problems = verify_bundle(args.bundle_dir)
    if not problems:
        print("bundle verified: hashes match and the evaluator reproduces"
              " the recorded result")
        return 0
    for p in problems:
        print(f"problem: {p}")
    return 1


def cmd_replay(args: argparse.Namespace) -> int:
    from .bundle import load_bundle
    from .replay import render_replay

    print(render_replay(load_bundle(args.bundle_dir), start=args.start,
                        limit=args.limit, kind=args.kind))
    return 0


def cmd_visualize(args: argparse.Namespace) -> int:
    import os

    from .bundle import load_bundle
    from .visualizer import write_visualizer

    bundle = load_bundle(args.bundle_dir)
    out = args.output or os.path.join(args.bundle_dir, "town.html")
    write_visualizer(bundle, out)
    print(f"visualizer written to {out}")
    print("open it in a browser: agents on the map, messages on the"
          " timeline, the report alongside")
    return 0


def cmd_identity(args: argparse.Namespace) -> int:
    import json

    from .identity_portable import Keystore, default_keystore_dir

    keystore = Keystore(args.dir or default_keystore_dir())
    if args.action == "new":
        identity = keystore.new_identity(args.name or "agent")
        print(json.dumps(identity, indent=2))
        print("controller key stored in the keystore; it never enters a"
              " participant environment")
        return 0
    if args.action == "list":
        identities = keystore.identities()
        if not identities:
            print(f"no identities in {keystore.directory}; create one"
                  " with: nandatown identity new <name>")
            return 0
        for identity in identities:
            print(f"{identity['name']:<16} {identity['agent_id']}"
                  f"  controller {identity['controller_public'][:16]}")
        return 0
    if args.action == "grant":
        if not args.name or not args.run:
            print("grant needs a name and --run <run_id>")
            return 2
        grant = keystore.make_grant(args.name, args.run)
        print(json.dumps(grant, indent=2))
        print("hand this to the agent's environment as TOWN_GRANT; the"
              " session key inside is disposable and run-scoped")
        return 0
    print("actions: new, list, grant")
    return 2


def cmd_new(args: argparse.Namespace) -> int:
    from .new import HINTS, ScaffoldError, scaffold

    try:
        path = scaffold(args.kind, args.name, args.extra, args.dir)
    except ScaffoldError as exc:
        print(str(exc))
        return 2
    print(f"wrote {path}")
    print(HINTS[args.kind].format(path=path))
    return 0


def cmd_board(args: argparse.Namespace) -> int:
    from .board import render_board

    print(render_board(args.dir), end="")
    return 0


def cmd_schemas(args: argparse.Namespace) -> int:
    from .schemas import export_schemas

    for path in export_schemas(args.out):
        print(f"wrote {path}")
    return 0


def cmd_mcp(args: argparse.Namespace) -> int:
    import json
    import shlex

    from .mcp_adapter import MCPTownServer, probe

    if args.action == "serve":
        if not (args.url and args.run and args.name):
            print("serve needs --url, --run, and --name (plus --token"
                  " or --grant-file)")
            return 2
        grant_json = None
        if args.grant_file:
            with open(args.grant_file) as f:
                grant_json = f.read()
        MCPTownServer(args.url, args.run, args.name, args.token,
                      grant_json).serve()
        return 0
    if args.action == "test":
        if not args.cmd:
            print("test needs --cmd \"command that starts the MCP"
                  " server\"")
            return 2
        report = probe(shlex.split(args.cmd))
        print(json.dumps(report, indent=2))
        if report["ok"]:
            print("MCP handshake passed: initialize, capabilities,"
                  " tools listed with schemas")
            return 0
        return 1
    print("actions: serve, test")
    return 2


def cmd_a2a(args: argparse.Namespace) -> int:
    import json

    if args.action == "serve":
        import uvicorn

        from .a2a_adapter import build_a2a_app

        base_url = f"http://{args.host}:{args.port}"
        print(f"A2A reference seller on {base_url}"
              + (f" with planted defect {args.defect}" if args.defect
                 else ""))
        print(f"agent card: {base_url}/.well-known/agent-card.json")
        uvicorn.run(build_a2a_app(base_url, defect=args.defect),
                    host=args.host, port=args.port,
                    log_level="warning")
        return 0
    if args.action == "test":
        if not args.url:
            print("test needs a URL: nandatown a2a test <url>")
            return 2
        from .a2a_adapter import probe_endpoint

        report = probe_endpoint(args.url)
        print(json.dumps(report, indent=2))
        if report["ok"]:
            print("A2A edge passed: agent card valid, message/send"
                  " round trip completed")
            return 0
        return 1
    print("actions: serve, test")
    return 2


def cmd_coordinator(args: argparse.Namespace) -> int:
    import os
    import secrets

    import uvicorn

    from .coordinator import build_app

    admin_token = os.environ.get("TOWN_ADMIN_TOKEN") or secrets.token_hex(16)
    print(f"coordinator on http://{args.host}:{args.port}")
    print(f"admin token: {admin_token}")
    print("bring your own agent: create a run with POST /runs, join with"
          " the returned tokens; see README for the contract")
    app = build_app(args.db, admin_token=admin_token)
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    return 0


def cmd_ui(args: argparse.Namespace) -> int:
    if args.web:
        from .tui import launch_web

        launch_web(out_dir=args.out, host=args.host, port=args.port,
                   kiosk=args.kiosk)
        return 0
    from .tui import launch

    launch(out_dir=args.out, kiosk=args.kiosk)
    return 0


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if not argv:
        from .tui import launch

        launch()
        return 0
    parser = argparse.ArgumentParser(
        prog="nandatown",
        description="The open proving ground for the Internet of AI"
                    " agents. Bring an agent, give it a task, break"
                    " something on purpose, leave with evidence.",
    )
    parser.add_argument("--version", action="version",
                        version=f"nandatown {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_ui = sub.add_parser("ui", help="the interactive town (also just:"
                                     " nandatown with no arguments)")
    p_ui.add_argument("--out", default="runs")
    p_ui.add_argument("--web", action="store_true",
                      help="serve the GUI in a browser instead of this"
                           " terminal")
    import os as _os
    p_ui.add_argument("--host", default="127.0.0.1")
    p_ui.add_argument("--port", type=int,
                      default=int(_os.environ.get("PORT", "8901")))
    p_ui.add_argument("--kiosk", action="store_true",
                      help="hosted mode: disable surfaces that execute"
                           " visitor commands or read server paths")
    p_ui.set_defaults(func=cmd_ui)

    p_run = sub.add_parser("run", help="run a Lab scenario or Track"
                                       " profile and print the report")
    p_run.add_argument("name", nargs="?", default="quote-crash-restart",
                       help="scenario name, profile name, or a scenario"
                            " YAML path")
    p_run.add_argument("--seed", type=int, default=None,
                       help="override the Lab scenario seed")
    p_run.add_argument("--out", default="runs",
                       help="directory for evidence bundles")
    p_run.add_argument("--model", default=None,
                       help="model for llm profiles: mock:v1 (default),"
                            " or a name served by an OpenAI-compatible"
                            " endpoint (TOWN_MODEL_URL, default Ollama)")
    p_run.add_argument("--agent", action="append", default=[],
                       metavar="ROLE=HARNESS",
                       help="Track only: connect a harness per role:"
                            " scripted, llm, llm:MODEL, cmd:COMMAND,"
                            " or external")
    p_run.add_argument("--plugin", action="append", default=[],
                       metavar="FILE",
                       help="Lab only: load a plugin/validator file"
                            " before the run")
    p_run.add_argument("--layer", action="append", default=[],
                       metavar="LAYER=PLUGIN_ID",
                       help="Lab only: swap one layer's plugin for this"
                            " run")
    p_run.add_argument("--identity", action="store_true",
                       help="Track only: join through portable identity"
                            " run grants instead of join tokens")
    p_run.add_argument("--identity-dir", default=None)
    p_run.set_defaults(func=cmd_run)

    p_identity = sub.add_parser(
        "identity", help="portable identities: controller keys, the"
                         " town registry, run grants")
    p_identity.add_argument("action",
                            choices=["new", "list", "grant"])
    p_identity.add_argument("name", nargs="?", default=None)
    p_identity.add_argument("--run", default=None)
    p_identity.add_argument("--dir", default=None)
    p_identity.set_defaults(func=cmd_identity)

    p_test = sub.add_parser(
        "test-agent",
        help="test YOUR agent: --url path-tests an already-running"
             " external endpoint; --cmd or --wait joins one into the"
             " town")
    p_test.add_argument("--url", default=None,
                        help="an already-running external A2A endpoint;"
                             " Town acts as deterministic counterpart"
                             " and observer")
    p_test.add_argument("--path-profile",
                        default=DEFAULT_PATH_PROFILE,
                        help="the exact versioned path profile")
    p_test.add_argument("--pin-card-digest", default=None,
                        help="expected agent card fingerprint; a"
                             " mismatch fails descriptor consistency")
    p_test.add_argument("--index", default=None,
                        help="pinned local index file resolving"
                             " --agent-name to an endpoint")
    p_test.add_argument("--agent-name", default=None)
    p_test.add_argument("--role", choices=["seller", "buyer"],
                        default="seller")
    p_test.add_argument("--profile", default="quote-clean")
    p_test.add_argument("--cmd", default=None,
                        help="command that starts your agent (it receives"
                             " TOWN_URL, RUN_ID, NAME, TOKEN, STATE_DIR"
                             " in its environment)")
    p_test.add_argument("--wait", action="store_true",
                        help="print join credentials and wait for your"
                             " agent to connect from outside")
    p_test.add_argument("--timeout", type=float, default=60.0)
    p_test.add_argument("--out", default="runs")
    p_test.set_defaults(func=cmd_test_agent)

    sub.add_parser("scenarios",
                   help="list Lab scenarios").set_defaults(func=cmd_scenarios)
    sub.add_parser("profiles",
                   help="list Track profiles").set_defaults(func=cmd_profiles)
    sub.add_parser("layers",
                   help="list the twelve layers and their"
                        " plugins").set_defaults(func=cmd_layers)

    p_skills = sub.add_parser("skills", help="list, show, or validate"
                                             " SkillMDs")
    p_skills.add_argument("name", nargs="?", default=None)
    p_skills.add_argument("--validate", metavar="PATH", default=None)
    p_skills.set_defaults(func=cmd_skills)

    p_import = sub.add_parser(
        "import-pr", help="import a protocol contribution (a PR) from"
                          " the upstream nandatown repo for local"
                          " testing")
    p_import.add_argument("number", type=int)
    p_import.add_argument("--repo", default="projnanda/nandatown")
    p_import.add_argument("--out", default="protocols")
    p_import.set_defaults(func=cmd_import_pr)

    p_protocols = sub.add_parser(
        "protocols", help="list imported protocol contributions, or"
                          " show one's metadata")
    p_protocols.add_argument("name", nargs="?", default=None)
    p_protocols.add_argument("--dir", default="protocols")
    p_protocols.set_defaults(func=cmd_protocols)

    p_onramp = sub.add_parser(
        "onramp", help="turn a local OpenAPI document into a reviewable"
                       " SkillMD candidate with structural checks")
    p_onramp.add_argument("spec", help="path to a local openapi.json or"
                                       " .yaml (never fetched, never"
                                       " executed)")
    p_onramp.add_argument("--name", default=None)
    p_onramp.add_argument("--out", default="services")
    p_onramp.set_defaults(func=cmd_onramp)

    p_services = sub.add_parser("services",
                                help="list the pinned services catalog,"
                                     " or show one candidate's SKILL.md")
    p_services.add_argument("name", nargs="?", default=None)
    p_services.add_argument("--dir", default="services")
    p_services.set_defaults(func=cmd_services)

    p_campaign = sub.add_parser(
        "campaign", help="run a precommitted campaign and report the"
                         " distribution")
    p_campaign.add_argument("name")
    p_campaign.add_argument("--trials", type=int, default=10)
    p_campaign.add_argument("--seed-base", type=int, default=1000)
    p_campaign.add_argument("--out", default="runs")
    p_campaign.set_defaults(func=cmd_campaign)

    p_compare = sub.add_parser(
        "compare", help="run the same scenario twice, baseline against"
                        " swapped layer plugins, side by side")
    p_compare.add_argument("target")
    p_compare.add_argument("--swap", action="append", default=[],
                           metavar="LAYER=PLUGIN_ID")
    p_compare.add_argument("--plugin", action="append", default=[],
                           metavar="FILE")
    p_compare.add_argument("--seed", type=int, default=None)
    p_compare.add_argument("--out", default="runs")
    p_compare.set_defaults(func=cmd_compare)

    p_receipt = sub.add_parser(
        "receipt", help="write a sanitized signed receipt for a bundle")
    p_receipt.add_argument("bundle_dir")
    p_receipt.set_defaults(func=cmd_receipt)

    p_vr = sub.add_parser(
        "verify-receipt", help="verify a receipt offline (signature,"
                               " signer id, optional bundle digests)")
    p_vr.add_argument("receipt")
    p_vr.add_argument("--bundle", default=None)
    p_vr.set_defaults(func=cmd_verify_receipt)

    p_proof = sub.add_parser(
        "proof", help="render the TOWN-TESTED badge from conclusive,"
                      " fresh, verified evidence, or say why not")
    p_proof.add_argument("bundle_dir")
    p_proof.add_argument("--freshness-days", type=float, default=30.0)
    p_proof.set_defaults(func=cmd_proof)

    p_mirror = sub.add_parser(
        "mirror", help="store a content-addressed copy of a bundle in"
                       " a mirror directory")
    p_mirror.add_argument("bundle_dir")
    p_mirror.add_argument("mirror_dir")
    p_mirror.set_defaults(func=cmd_mirror)

    p_recover = sub.add_parser(
        "recover", help="restore a bundle by fingerprint from any"
                        " surviving mirror and verify it")
    p_recover.add_argument("fingerprint")
    p_recover.add_argument("--mirror", action="append", default=[],
                           required=False)
    p_recover.add_argument("--out", default="runs")
    p_recover.set_defaults(func=cmd_recover)

    p_pulse = sub.add_parser(
        "pulse", help="probe registered services on a schedule and keep"
                      " the operational history")
    p_pulse.add_argument("--target", action="append", default=[],
                         metavar="NAME=URL")
    p_pulse.add_argument("--count", type=int, default=5)
    p_pulse.add_argument("--interval", type=float, default=2.0)
    p_pulse.add_argument("--db", default="pulse.db")
    p_pulse.add_argument("--report", action="store_true",
                         help="render the availability history")
    p_pulse.add_argument("--records", action="store_true",
                         help="export operational-history evidence"
                              " records as JSONL")
    p_pulse.set_defaults(func=cmd_pulse)

    p_report = sub.add_parser("report", help="render a bundle's report")
    p_report.add_argument("bundle_dir")
    p_report.set_defaults(func=cmd_report)

    p_verify = sub.add_parser("verify",
                              help="check a bundle's integrity and replay"
                                   " the evaluator")
    p_verify.add_argument("bundle_dir")
    p_verify.set_defaults(func=cmd_verify)

    p_replay = sub.add_parser("replay", help="step through a bundle's"
                                             " events")
    p_replay.add_argument("bundle_dir")
    p_replay.add_argument("--start", type=int, default=0)
    p_replay.add_argument("--limit", type=int, default=None)
    p_replay.add_argument("--kind", default=None)
    p_replay.set_defaults(func=cmd_replay)

    p_vis = sub.add_parser("visualize", help="write the HTML visualizer"
                                             " for a bundle")
    p_vis.add_argument("bundle_dir")
    p_vis.add_argument("-o", "--output", default=None)
    p_vis.set_defaults(func=cmd_visualize)

    p_new = sub.add_parser(
        "new", help="scaffold a scenario, plugin, skill, or agent from"
                    " a working template")
    p_new.add_argument("kind",
                       choices=["scenario", "plugin", "skill", "agent"])
    p_new.add_argument("name", help="scenario/skill/agent name, or the"
                                    " LAYER for a plugin")
    p_new.add_argument("extra", nargs="?", default=None,
                       help="plugin id when kind is plugin, e.g."
                            " mytrust.v1")
    p_new.add_argument("--dir", default=".")
    p_new.set_defaults(func=cmd_new)

    p_board = sub.add_parser(
        "board", help="the local leaderboard over a runs directory")
    p_board.add_argument("dir", nargs="?", default="runs")
    p_board.set_defaults(func=cmd_board)

    p_schemas = sub.add_parser("schemas", help="export the shared JSON"
                                               " Schemas")
    p_schemas.add_argument("--out", default="schemas")
    p_schemas.set_defaults(func=cmd_schemas)

    p_mcp = sub.add_parser(
        "mcp", help="the MCP adapter: serve a town role to any MCP"
                    " host, or probe an external MCP server")
    p_mcp.add_argument("action", choices=["serve", "test"])
    p_mcp.add_argument("--url", default=None)
    p_mcp.add_argument("--run", default=None)
    p_mcp.add_argument("--name", default=None)
    p_mcp.add_argument("--token", default="")
    p_mcp.add_argument("--grant-file", default=None)
    p_mcp.add_argument("--cmd", default=None)
    p_mcp.set_defaults(func=cmd_mcp)

    p_a2a = sub.add_parser(
        "a2a", help="the A2A edge: serve the reference seller as an"
                    " Agent2Agent agent, or test an A2A endpoint")
    p_a2a.add_argument("action", choices=["serve", "test"])
    p_a2a.add_argument("url", nargs="?", default=None)
    p_a2a.add_argument("--host", default="127.0.0.1")
    p_a2a.add_argument("--port", type=int, default=8940)
    p_a2a.add_argument("--defect", default=None,
                       choices=["wrong_total", "wrong_item", "duplicate_fulfillment",
                                "card_drift"],
                       help="plant one defect in the reference seller"
                            " to demonstrate a failing path test")
    p_a2a.set_defaults(func=cmd_a2a)

    p_coord = sub.add_parser("coordinator",
                             help="run a standalone coordinator for your"
                                  " own agent")
    p_coord.add_argument("--host", default="127.0.0.1")
    p_coord.add_argument("--port", type=int, default=8477)
    p_coord.add_argument("--db", default="town.db")
    p_coord.set_defaults(func=cmd_coordinator)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
