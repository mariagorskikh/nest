"""The town's front door: a full-screen interactive terminal GUI.

Every action here is a thin shell over the same functions the plain CLI
uses, so anything you click has a scriptable equivalent. Long work runs
in background workers; the interface stays live while a run executes.
"""

from __future__ import annotations

import os
import shlex
from typing import Any

from textual import on, work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, VerticalScroll
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    RichLog,
    Select,
    Static,
    TabbedContent,
    TabPane,
)

from . import __version__

JOURNEY = (
    "bring an agent  >  connect reference peers  >  attempt a defined"
    " task  >  disrupt one named failure  >  inspect the exact evidence"
    "  >  improve and rerun"
)

HARNESS_OPTIONS = [
    ("profile default", "default"),
    ("scripted reference agent", "scripted"),
    ("model tool loop (mock brain)", "llm"),
    ("my own command", "cmd"),
]

KIOSK_HOSTED_MODEL_OPT_IN = "NANDATOWN_KIOSK_ALLOW_HOSTED_MODEL"


def _track_model(kiosk: bool) -> str | None:
    """Keep a public kiosk off operator-funded models unless opted in."""
    if kiosk and os.environ.get(KIOSK_HOSTED_MODEL_OPT_IN) != "1":
        return "mock:v1"
    return None


def _targets() -> list[tuple[str, str]]:
    from .profiles import PROFILES
    from .sim.scenario import bundled_scenarios

    options = [(f"lab: {name}", name) for name in bundled_scenarios()]
    options += [(f"track: {name}", name) for name in PROFILES]
    return options


class TownApp(App):
    TITLE = (f"NANDA Town {__version__}: the open proving ground for"
             " the Internet of AI agents")
    BINDINGS = [("q", "quit", "Quit"),
                ("w", "website", "nanda.town")]

    CSS = """
    TabbedContent { height: 1fr; }
    .pane { padding: 1 2; }
    .row { height: auto; margin-bottom: 1; }
    .hint { color: $text-muted; margin-bottom: 1; }
    Button { margin-right: 2; }
    Input { width: 60; margin-right: 2; }
    Select { width: 46; margin-right: 2; }
    DataTable { height: 12; margin-bottom: 1; }
    RichLog { height: 1fr; min-height: 8; border: solid $primary 30%; }
    #town-log { height: 14; }
    .rolelabel { width: 8; padding-top: 1; color: $text-muted; }
    """

    def __init__(self, out_dir: str = "runs", kiosk: bool = False):
        super().__init__()
        self.out_dir = out_dir
        # Kiosk mode is for hosted deployments: every surface that
        # would execute visitor-supplied commands or read server-local
        # paths is disabled; runs, evidence, imports stay available.
        self.kiosk = kiosk

    # -- layout ---------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header()
        with TabbedContent(initial="tab-town"):
            with TabPane("Town", id="tab-town"):
                with VerticalScroll(classes="pane"):
                    yield Static(JOURNEY, classes="hint")
                    yield Static(id="town-status")
                    yield Static(
                        "Site: [link='https://nanda.town']nanda.town"
                        "[/link]  ([b]w[/b] opens it)",
                        id="town-site", classes="hint")
                    with Horizontal(classes="row"):
                        yield Button("Run the default proof",
                                     id="quick-default", variant="primary")
                        yield Button("Run the marketplace",
                                     id="quick-market")
                        yield Button("Break the auth layer",
                                     id="quick-weak")
                    yield RichLog(id="town-log", wrap=True, markup=False)
            with TabPane("Run", id="tab-run"):
                with VerticalScroll(classes="pane"):
                    yield Static("Pick a target; connect a harness per"
                                 " role for Track profiles.",
                                 classes="hint")
                    with Horizontal(classes="row"):
                        yield Select(_targets(), id="run-target",
                                     value="marketplace",
                                     allow_blank=False)
                        yield Button("Run", id="run-go",
                                     variant="primary")
                    with Horizontal(classes="row"):
                        yield Label("seller", classes="rolelabel")
                        yield Select(HARNESS_OPTIONS, id="seller-harness",
                                     value="default", allow_blank=False)
                        yield Input(placeholder="seller command"
                                    " (cmd harness)", id="seller-cmd")
                    with Horizontal(classes="row"):
                        yield Label("buyer", classes="rolelabel")
                        yield Select(HARNESS_OPTIONS, id="buyer-harness",
                                     value="default", allow_blank=False)
                        yield Input(placeholder="buyer command"
                                    " (cmd harness)", id="buyer-cmd")
                    yield DataTable(id="run-stages")
                    yield RichLog(id="run-log", wrap=True, markup=False)
            with TabPane("Agents", id="tab-agents"):
                with VerticalScroll(classes="pane"):
                    if self.kiosk:
                        yield Static(
                            "Hosted mode: testing your own agent runs"
                            " your command, so it is disabled here."
                            " Run the town locally (pip install"
                            " nandatown, then nandatown) to test your"
                            " agent with test-agent or the cmd"
                            " harness.", classes="hint")
                    else:
                        yield Static(
                            "Test YOUR agent: it plays one role, the town"
                            " supplies the counterpart, the fault, and the"
                            " report. The command gets TOWN_URL, RUN_ID,"
                            " NAME, TOKEN in its environment.",
                            classes="hint")
                        with Horizontal(classes="row"):
                            yield Select([("seller", "seller"),
                                          ("buyer", "buyer")],
                                         id="agent-role", value="seller",
                                         allow_blank=False)
                            yield Input(placeholder="python my_agent.py",
                                        id="agent-cmd")
                            yield Button("Test my agent", id="agent-go",
                                         variant="primary")
                        yield RichLog(id="agent-log", wrap=True,
                                      markup=False)
            with TabPane("Protocols", id="tab-protocols"):
                with VerticalScroll(classes="pane"):
                    yield Static(
                        "Import a protocol contribution (a PR) from the"
                        " upstream repo. Importing never runs the code:"
                        " it snapshots, fingerprints, classifies, and"
                        " checks. Running it against the reference"
                        " agents is your explicit next step.",
                        classes="hint")
                    with Horizontal(classes="row"):
                        yield Input(placeholder="PR number",
                                    id="pr-number")
                        yield Input(value="projnanda/nandatown",
                                    id="pr-repo")
                        yield Button("Import", id="pr-go",
                                     variant="primary")
                    yield DataTable(id="protocol-table")
                    yield RichLog(id="protocol-log", wrap=True,
                                  markup=False)
            with TabPane("Services", id="tab-services"):
                with VerticalScroll(classes="pane"):
                    yield Static(
                        "Onboard a service from a LOCAL OpenAPI"
                        " document: a reviewable SKILL.md candidate,"
                        " structural checks, a pinned catalog entry."
                        " Nothing is fetched or executed.",
                        classes="hint")
                    if self.kiosk:
                        yield Static("Hosted mode: onboarding reads a"
                                     " local file, so it is disabled"
                                     " here; run the town locally to"
                                     " onboard a service.",
                                     classes="hint")
                    else:
                        with Horizontal(classes="row"):
                            yield Input(placeholder="path/to/openapi.json",
                                        id="svc-path")
                            yield Button("Onramp", id="svc-go",
                                         variant="primary")
                    yield DataTable(id="service-table")
                    yield RichLog(id="svc-log", wrap=True, markup=False)
            with TabPane("Evidence", id="tab-evidence"):
                with VerticalScroll(classes="pane"):
                    with Horizontal(classes="row"):
                        yield Button("Refresh", id="ev-refresh")
                        yield Button("Report", id="ev-report")
                        yield Button("Verify", id="ev-verify")
                        yield Button("Visualize", id="ev-visualize")
                    yield DataTable(id="bundle-table")
                    yield RichLog(id="ev-log", wrap=True, markup=False)
        yield Footer()

    def on_mount(self) -> None:
        stages = self.query_one("#run-stages", DataTable)
        stages.add_columns("stage", "status", "note")
        bundles = self.query_one("#bundle-table", DataTable)
        bundles.cursor_type = "row"
        bundles.add_columns("run", "profile", "mode", "verdict")
        protocols = self.query_one("#protocol-table", DataTable)
        protocols.add_columns("name", "author", "status", "checks")
        services = self.query_one("#service-table", DataTable)
        services.add_columns("name", "status", "ops", "checks")
        self._refresh_status()
        self._refresh_bundles()
        self._refresh_protocols()
        self._refresh_services()

    # -- shared helpers -------------------------------------------------

    def _log(self, log_id: str, text: str) -> None:
        self.call_from_thread(
            self.query_one(f"#{log_id}", RichLog).write, text)

    def action_website(self) -> None:
        # In a terminal this opens the local browser; under
        # textual-serve it opens in the visitor's own browser.
        self.open_url("https://nanda.town")

    def _refresh_status(self) -> None:
        from .board import scan_bundles
        from .profiles import PROFILES
        from .sim.scenario import bundled_scenarios

        rows = scan_bundles(self.out_dir)
        passed = sum(1 for r in rows if r["verdict"] == "passed")
        self.query_one("#town-status", Static).update(
            f"{len(bundled_scenarios())} lab scenarios,"
            f" {len(PROFILES)} track profiles, 12 protocol layers."
            f" Evidence here: {len(rows)} bundles, {passed} passed.")

    def _refresh_bundles(self) -> None:
        from .board import scan_bundles

        table = self.query_one("#bundle-table", DataTable)
        table.clear()
        for row in reversed(scan_bundles(self.out_dir)):
            table.add_row(row["run_id"], row["profile"], row["mode"],
                          row["verdict"], key=row["run_id"])

    def _refresh_protocols(self) -> None:
        from .protocols import protocol_entries

        table = self.query_one("#protocol-table", DataTable)
        table.clear()
        for e in protocol_entries():
            checks = e["checks"]
            table.add_row(e["name"], e["author"], e["status"],
                          f"{checks['passed']} passed,"
                          f" {checks['failed']} failed")

    def _refresh_services(self) -> None:
        from .onramp import catalog_entries

        table = self.query_one("#service-table", DataTable)
        table.clear()
        for e in catalog_entries():
            checks = e["checks"]
            table.add_row(e["name"], e["status"], str(e["operations"]),
                          f"{checks['passed']} passed,"
                          f" {checks['failed']} failed")

    def _show_result(self, bundle_dir: str, result: Any,
                     log_id: str) -> None:
        def fill():
            stages = self.query_one("#run-stages", DataTable)
            stages.clear()
            for s in result.stages:
                stages.add_row(s.name, s.status, s.note)
            self._refresh_status()
            self._refresh_bundles()
        self.call_from_thread(fill)
        self._log(log_id, f"verdict: {result.verdict.upper()}")
        self._log(log_id, f"evidence bundle: {bundle_dir}")

    # -- runs -----------------------------------------------------------

    @work(thread=True, exclusive=True)
    def _run_target(self, target: str,
                    harnesses: dict[str, str] | None) -> None:
        from .profiles import PROFILES

        try:
            if target in PROFILES:
                from .runner import run_town
                self._log("run-log",
                          f"track run of {target}"
                          + (f" with harnesses {harnesses}"
                             if harnesses else ""))
                bundle_dir, result = run_town(target, self.out_dir,
                                              harnesses=harnesses,
                                              model=_track_model(self.kiosk))
            else:
                from .sim.runner import run_lab
                self._log("run-log", f"lab run of {target}")
                bundle_dir, result = run_lab(target, self.out_dir)
            self._show_result(bundle_dir, result, "run-log")
        except Exception as exc:
            self._log("run-log", f"run failed: {type(exc).__name__}:"
                                 f" {exc}")

    @on(Button.Pressed, "#run-go")
    def _on_run(self) -> None:
        target = self.query_one("#run-target", Select).value
        harnesses: dict[str, str] = {}
        for role in ("seller", "buyer"):
            choice = self.query_one(f"#{role}-harness", Select).value
            if choice == "cmd":
                if self.kiosk:
                    self.query_one("#run-log", RichLog).write(
                        "hosted mode: the cmd harness is disabled;"
                        " run the town locally to connect your own"
                        " process")
                    continue
                command = self.query_one(f"#{role}-cmd", Input).value
                if command.strip():
                    harnesses[role] = "cmd:" + command
            elif choice in ("scripted", "llm"):
                harnesses[role] = choice
        self._run_target(str(target), harnesses or None)

    @on(Button.Pressed, "#quick-default")
    def _on_quick_default(self) -> None:
        self._quick("quote-crash-restart")

    @on(Button.Pressed, "#quick-market")
    def _on_quick_market(self) -> None:
        self._quick("marketplace")

    @on(Button.Pressed, "#quick-weak")
    def _on_quick_weak(self) -> None:
        self._quick("capability_spoofing_weak_auth")

    @work(thread=True, exclusive=True)
    def _quick(self, target: str) -> None:
        from .bundle import load_bundle
        from .profiles import PROFILES
        from .report import render_report

        try:
            if target in PROFILES:
                from .runner import run_town
                bundle_dir, result = run_town(
                    target, self.out_dir, model=_track_model(self.kiosk))
            else:
                from .sim.runner import run_lab
                bundle_dir, result = run_lab(target, self.out_dir)
            self._log("town-log",
                      render_report(load_bundle(bundle_dir)))
            self.call_from_thread(self._refresh_status)
            self.call_from_thread(self._refresh_bundles)
        except Exception as exc:
            self._log("town-log", f"run failed: {type(exc).__name__}:"
                                  f" {exc}")

    # -- agents ---------------------------------------------------------

    @on(Button.Pressed, "#agent-go")
    def _on_agent(self) -> None:
        role = str(self.query_one("#agent-role", Select).value)
        command = self.query_one("#agent-cmd", Input).value.strip()
        if not command:
            self.query_one("#agent-log", RichLog).write(
                "give the command that starts your agent")
            return
        self._test_agent(role, command)

    @work(thread=True, exclusive=True)
    def _test_agent(self, role: str, command: str) -> None:
        from .runner import run_town

        self._log("agent-log", f"your {role}: {command}")
        try:
            bundle_dir, result = run_town(
                "quote-clean", self.out_dir,
                external={role: shlex.split(command)})
            applicable = [s for s in result.stages
                          if s.status != "not_tested"]
            passed = sum(1 for s in applicable if s.status == "passed")
            for s in applicable:
                self._log("agent-log", f"  {s.name}: {s.status}")
            self._log("agent-log",
                      f"{passed} of {len(applicable)} town stages"
                      " passed.")
            self._log("agent-log", f"evidence bundle: {bundle_dir}")
            self.call_from_thread(self._refresh_bundles)
        except Exception as exc:
            self._log("agent-log", f"test failed: {type(exc).__name__}:"
                                   f" {exc}")

    # -- protocols ------------------------------------------------------

    @on(Button.Pressed, "#pr-go")
    def _on_import(self) -> None:
        number = self.query_one("#pr-number", Input).value.strip()
        repo = self.query_one("#pr-repo", Input).value.strip()
        if not number.isdigit():
            self.query_one("#protocol-log", RichLog).write(
                "give a PR number")
            return
        self._import_pr(int(number), repo)

    @work(thread=True, exclusive=True)
    def _import_pr(self, number: int, repo: str) -> None:
        import json

        from .protocols import ProtocolImportError, import_pr

        self._log("protocol-log", f"importing {repo}#{number}...")
        try:
            protocol_dir = import_pr(number, repo=repo)
        except (ProtocolImportError, Exception) as exc:
            self._log("protocol-log",
                      f"import failed: {type(exc).__name__}: {exc}")
            return
        with open(os.path.join(protocol_dir, "metadata.json")) as f:
            metadata = json.load(f)
        self._log("protocol-log",
                  f"imported: {metadata['title']} by"
                  f" {metadata['author']} at"
                  f" {metadata['head_sha'][:12]} (imported-untrusted)")
        for usage in metadata["usage"]:
            self._log("protocol-log", f"  next: {usage}")
        self.call_from_thread(self._refresh_protocols)

    # -- services -------------------------------------------------------

    @on(Button.Pressed, "#svc-go")
    def _on_onramp(self) -> None:
        path = self.query_one("#svc-path", Input).value.strip()
        if not path:
            self.query_one("#svc-log", RichLog).write(
                "give a path to a local OpenAPI document")
            return
        self._onramp(path)

    @work(thread=True, exclusive=True)
    def _onramp(self, path: str) -> None:
        import json

        from .onramp import OnrampError, onramp

        try:
            candidate = onramp(path)
        except (OnrampError, OSError) as exc:
            self._log("svc-log", f"onramp failed: {exc}")
            return
        self._log("svc-log", f"candidate written to {candidate}")
        with open(os.path.join(candidate, "checks.jsonl")) as f:
            for line in f:
                check = json.loads(line)
                self._log("svc-log",
                          f"  {check['test']}: {check['result']}")
        self.call_from_thread(self._refresh_services)

    # -- evidence -------------------------------------------------------

    def _selected_bundle(self) -> str | None:
        table = self.query_one("#bundle-table", DataTable)
        if table.row_count == 0:
            return None
        row = table.get_row_at(table.cursor_row)
        return os.path.join(self.out_dir, str(row[0]))

    @on(Button.Pressed, "#ev-refresh")
    def _on_ev_refresh(self) -> None:
        self._refresh_bundles()
        self._refresh_status()

    @on(Button.Pressed, "#ev-report")
    def _on_ev_report(self) -> None:
        bundle_dir = self._selected_bundle()
        if bundle_dir:
            from .bundle import load_bundle
            from .report import render_report
            self.query_one("#ev-log", RichLog).write(
                render_report(load_bundle(bundle_dir)))

    @on(Button.Pressed, "#ev-verify")
    def _on_ev_verify(self) -> None:
        bundle_dir = self._selected_bundle()
        if bundle_dir:
            from .bundle import verify_bundle
            problems = verify_bundle(bundle_dir)
            log = self.query_one("#ev-log", RichLog)
            if problems:
                for p in problems:
                    log.write(f"problem: {p}")
            else:
                log.write(f"{bundle_dir}: verified, hashes match and"
                          " the evaluator reproduces the result")

    @on(Button.Pressed, "#ev-visualize")
    def _on_ev_visualize(self) -> None:
        bundle_dir = self._selected_bundle()
        if bundle_dir:
            from .bundle import load_bundle
            from .visualizer import write_visualizer
            out = os.path.join(bundle_dir, "town.html")
            write_visualizer(load_bundle(bundle_dir), out)
            self.query_one("#ev-log", RichLog).write(
                f"visualizer written to {out}; open it in a browser")


def launch(out_dir: str = "runs", kiosk: bool = False) -> None:
    TownApp(out_dir=out_dir, kiosk=kiosk).run()


def build_web_server(out_dir: str = "runs", host: str = "127.0.0.1",
                     port: int = 8901, kiosk: bool = False):
    """The same GUI served over HTTP: no terminal required."""
    import sys

    from textual_serve.server import Server

    command = (f'"{sys.executable}" -m nandatown.cli ui'
               f' --out "{os.path.abspath(out_dir)}"')
    if kiosk:
        command += " --kiosk"
    return Server(command, host=host, port=port,
                  title="NANDA Town")


def launch_web(out_dir: str = "runs", host: str = "127.0.0.1",
               port: int = 8901, kiosk: bool = False) -> None:
    server = build_web_server(out_dir, host, port, kiosk=kiosk)
    print(f"NANDA Town GUI on http://{host}:{port}"
          + (" (kiosk mode)" if kiosk else ""))
    server.serve()
