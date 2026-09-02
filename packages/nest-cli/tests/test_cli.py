# SPDX-License-Identifier: Apache-2.0
"""Tests for Nanda Town CLI commands."""

from __future__ import annotations

from pathlib import Path

from nest_cli.main import app
from typer.testing import CliRunner

runner = CliRunner()


class TestVersion:
    def test_version_output(self) -> None:
        from nest_core import __version__ as core_version

        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert core_version in result.output


class TestAgentTestShim:
    def test_deprecated_shim_reexports_agent_test_help(self) -> None:
        from nest_core.cli import app as core_app

        shim = runner.invoke(app, ["test", "agent", "--help"], color=False)
        core = runner.invoke(core_app, ["test", "agent", "--help"], color=False)

        assert app is core_app
        assert shim.exit_code == 0
        assert shim.stdout == core.stdout
        assert "basic local agent test" in shim.stdout
        assert "[TARGET]" in " ".join(shim.stdout.replace("│", "").split())
        assert "OpenClaw" in shim.stdout
        assert "capability-fulfillment" not in shim.stdout
        assert "bearer" not in shim.stdout.lower()


class TestDoctor:
    def test_doctor_passes(self) -> None:
        result = runner.invoke(app, ["doctor"])
        assert result.exit_code == 0
        assert "checks passed" in result.output
        assert "[FAIL]" not in result.output


class TestRun:
    def test_run_marketplace(self, tmp_path: Path) -> None:
        yaml_path = Path(__file__).parent.parent.parent.parent / "scenarios" / "marketplace.yaml"
        if not yaml_path.exists():
            import pytest

            pytest.skip("marketplace.yaml not found")

        trace_out = tmp_path / "trace.jsonl"
        result = runner.invoke(
            app,
            [
                "run",
                str(yaml_path),
                "--ticks",
                "2000",
                "-o",
                str(trace_out),
            ],
        )
        assert result.exit_code == 0
        assert "Running scenario" in result.output
        assert "Trace written to" in result.output
        assert trace_out.exists()

    def test_run_missing_file(self) -> None:
        result = runner.invoke(app, ["run", "nonexistent.yaml"])
        assert result.exit_code == 1
        # The error mentions the bad name + lists the built-ins as a hint.
        assert "no scenario named or located at" in result.output
        assert "nest run marketplace" in result.output

    def test_run_seed_override(self, tmp_path: Path) -> None:
        yaml_path = Path(__file__).parent.parent.parent.parent / "scenarios" / "marketplace.yaml"
        if not yaml_path.exists():
            import pytest

            pytest.skip("marketplace.yaml not found")

        trace_out = tmp_path / "trace.jsonl"
        result = runner.invoke(
            app,
            [
                "run",
                str(yaml_path),
                "--seed",
                "999",
                "--ticks",
                "1000",
                "-o",
                str(trace_out),
            ],
        )
        assert result.exit_code == 0
        assert "seed: 999" in result.output

    def test_run_capability_fulfillment_builtin_uses_ordinary_interface(
        self, tmp_path: Path
    ) -> None:
        trace_out = tmp_path / "capability.jsonl"

        result = runner.invoke(
            app,
            ["run", "capability_fulfillment", "-o", str(trace_out)],
        )

        assert result.exit_code == 0
        assert "Running scenario: capability-fulfillment" in result.output
        assert f"Trace written to: {trace_out}" in result.output
        assert trace_out.exists()
        assert '"kind":"test.' not in trace_out.read_text()


class TestInit:
    def test_init_creates_file(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["init", "test-scenario", "-d", str(tmp_path)])
        assert result.exit_code == 0
        assert "Created scenario" in result.output

        created = tmp_path / "test-scenario.yaml"
        assert created.exists()
        content = created.read_text()
        assert "name: test-scenario" in content
        assert "transport: in_memory" in content

    def test_init_no_overwrite(self, tmp_path: Path) -> None:
        (tmp_path / "existing.yaml").write_text("name: existing\n")
        result = runner.invoke(app, ["init", "existing", "-d", str(tmp_path)])
        assert result.exit_code == 1
        assert "already exists" in result.output


class TestInspect:
    def test_inspect_trace(self, tmp_path: Path) -> None:
        import json

        trace = tmp_path / "test.jsonl"
        events = [
            {"ts": 0.0, "agent": "a1", "kind": "start"},
            {"ts": 1.0, "agent": "a1", "kind": "send", "to": "a2", "size": 10, "corr": "c-1"},
            {"ts": 1.0, "agent": "a2", "kind": "receive", "from": "a1", "size": 10, "corr": "c-1"},
            {"ts": 2.0, "agent": "a1", "kind": "stop"},
        ]
        trace.write_text("\n".join(json.dumps(e) for e in events))

        result = runner.invoke(app, ["inspect", str(trace)])
        assert result.exit_code == 0
        assert "Nanda Town Trace Summary" in result.output
        assert "Total events:" in result.output

    def test_inspect_missing_file(self) -> None:
        result = runner.invoke(app, ["inspect", "nonexistent.jsonl"])
        assert result.exit_code == 1
        assert "not found" in result.output


class TestReport:
    def test_report_metrics(self, tmp_path: Path) -> None:
        import json

        trace = tmp_path / "test.jsonl"
        events = [
            {"ts": 0.0, "agent": "a1", "kind": "start"},
            {"ts": 1.0, "agent": "a1", "kind": "send", "to": "a2", "size": 10, "corr": "c-1"},
            {"ts": 1.0, "agent": "a2", "kind": "receive", "from": "a1", "size": 10, "corr": "c-1"},
            {"ts": 2.0, "agent": "a1", "kind": "stop"},
        ]
        trace.write_text("\n".join(json.dumps(e) for e in events))

        result = runner.invoke(app, ["report", str(trace)])
        assert result.exit_code == 0
        assert "Metrics:" in result.output
        assert "success_rate" in result.output

    def test_report_with_html(self, tmp_path: Path) -> None:
        import json

        trace = tmp_path / "test.jsonl"
        events = [
            {"ts": 0.0, "agent": "a1", "kind": "start"},
            {"ts": 1.0, "agent": "a1", "kind": "send", "to": "a2", "size": 10, "corr": "c-1"},
            {"ts": 1.0, "agent": "a2", "kind": "receive", "from": "a1", "size": 10, "corr": "c-1"},
        ]
        trace.write_text("\n".join(json.dumps(e) for e in events))

        report_path = tmp_path / "report.html"
        result = runner.invoke(app, ["report", str(trace), "-o", str(report_path)])
        assert result.exit_code == 0
        assert "Report written to" in result.output
        assert report_path.exists()
        assert "Nanda Town Trace Report" in report_path.read_text()

    def test_report_missing_file(self) -> None:
        result = runner.invoke(app, ["report", "nonexistent.jsonl"])
        assert result.exit_code == 1


class TestPluginsList:
    def test_list_all(self) -> None:
        result = runner.invoke(app, ["plugins", "list"])
        assert result.exit_code == 0
        assert "transport" in result.output
        assert "in_memory" in result.output
        assert "payments" in result.output

    def test_list_filtered(self) -> None:
        result = runner.invoke(app, ["plugins", "list", "payments"])
        assert result.exit_code == 0
        assert "prepaid_credits" in result.output


class TestTemplatesList:
    def test_list_shows_builtins(self) -> None:
        result = runner.invoke(app, ["templates", "list"])
        assert result.exit_code == 0
        assert "marketplace-buyer" in result.output
        assert "auction-auctioneer" in result.output

    def test_show_template(self) -> None:
        result = runner.invoke(app, ["templates", "show", "marketplace-buyer"])
        assert result.exit_code == 0
        assert "marketplace-buyer" in result.output
        assert "System prompt:" in result.output

    def test_show_not_found(self) -> None:
        result = runner.invoke(app, ["templates", "show", "nonexistent"])
        assert result.exit_code == 1
        assert "not found" in result.output

    def test_create_template(self, tmp_path: Path) -> None:
        import os

        old_cwd = os.getcwd()
        try:
            os.chdir(tmp_path)
            result = runner.invoke(
                app,
                [
                    "templates",
                    "create",
                    "test-tpl",
                    "--prompt",
                    "Be a test agent.",
                ],
            )
            assert result.exit_code == 0
            assert "Created template" in result.output
        finally:
            os.chdir(old_cwd)

    def test_duplicate_template(self, tmp_path: Path) -> None:
        import os

        old_cwd = os.getcwd()
        try:
            os.chdir(tmp_path)
            result = runner.invoke(
                app,
                ["templates", "duplicate", "marketplace-buyer", "my-buyer"],
            )
            assert result.exit_code == 0
            assert "Duplicated" in result.output
        finally:
            os.chdir(old_cwd)

    def test_duplicate_not_found(self) -> None:
        result = runner.invoke(
            app,
            ["templates", "duplicate", "nonexistent", "copy"],
        )
        assert result.exit_code == 1
        assert "not found" in result.output
