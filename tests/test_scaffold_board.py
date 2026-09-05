import pytest
import json
from pathlib import Path

from nandatown.board import render_board, scan_bundles
from nandatown.cli import main
from nandatown.new import ScaffoldError, scaffold
from nandatown.sim.runner import run_lab
from nandatown.sim.scenario import load_scenario_file
from nandatown.skills import validate_skill


def test_new_scenario_loads_and_runs(tmp_path):
    path = scaffold("scenario", "my-town", None, str(tmp_path))
    spec = load_scenario_file(path)
    assert spec.name == "my-town"
    assert {a.role for a in spec.agents} == {"buyer", "seller"}
    bundle_dir, result = run_lab(path, str(tmp_path / "runs"))
    verdicts = {s.name: s.status for s in result.stages}
    assert verdicts["ledger_conserved"] == "passed"
    assert verdicts["validator"] == "not_enough_evidence"
    assert result.verdict == "incomplete"


def test_new_plugin_registers_when_loaded(tmp_path):
    path = scaffold("plugin", "trust", "mytrust.v1", str(tmp_path))
    import importlib.util

    spec = importlib.util.spec_from_file_location("user_plugin", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    from nandatown.layers import resolve
    assert resolve("trust", "mytrust.v1").plugin_id == "mytrust.v1"


def test_new_skill_validates(tmp_path):
    path = scaffold("skill", "my.skill", None, str(tmp_path))
    with open(path) as f:
        assert validate_skill(f.read()) == []


def test_new_agent_compiles(tmp_path):
    path = scaffold("agent", "my-agent", None, str(tmp_path))
    with open(path) as f:
        compile(f.read(), path, "exec")


def test_scaffold_refuses_overwrite_and_bad_layer(tmp_path):
    scaffold("skill", "twice", None, str(tmp_path))
    with pytest.raises(ScaffoldError):
        scaffold("skill", "twice", None, str(tmp_path))
    with pytest.raises(ScaffoldError):
        scaffold("plugin", "telepathy", "x.v1", str(tmp_path))
    with pytest.raises(ScaffoldError):
        scaffold("plugin", "trust", None, str(tmp_path))


def test_board_groups_and_ranks(tmp_path):
    run_lab("voting", str(tmp_path), seed=1)
    run_lab("voting", str(tmp_path), seed=2)
    run_lab("capability_spoofing_weak_auth", str(tmp_path))
    rows = scan_bundles(str(tmp_path))
    assert len(rows) == 3
    board = render_board(str(tmp_path))
    assert "voting" in board
    assert "2/2 passed" in board
    assert "0/1 passed" in board
    lines = board.splitlines()
    voting_line = next(i for i, l in enumerate(lines) if "voting" in l)
    weak_line = next(i for i, l in enumerate(lines)
                     if "weak_auth" in l)
    assert voting_line < weak_line


def test_cli_new_and_board(tmp_path, capsys):
    assert main(["new", "scenario", "demo", "--dir", str(tmp_path)]) == 0
    assert main(["board", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "no evidence bundles" in out


def test_board_excludes_tampered_results_from_rankings(tmp_path):
    directory, _ = run_lab("capability_spoofing_weak_auth", str(tmp_path))
    result_path = Path(directory) / "result.json"
    result = json.loads(result_path.read_text())
    result["verdict"] = "passed"
    result_path.write_text(json.dumps(result))
    run_lab("voting", str(tmp_path))

    rows = scan_bundles(str(tmp_path))
    bad = next(row for row in rows if row["run_id"] == Path(directory).name)
    assert bad["verified"] is False
    assert any("hash mismatch" in problem for problem in bad["problems"])
    board = render_board(str(tmp_path))
    assert board.count("1/1 passed") == 1
    assert "excluded from rankings" in board
    assert "hash mismatch" in board


def test_board_reports_malformed_bundles_without_losing_good_runs(tmp_path):
    bad = tmp_path / "broken"
    bad.mkdir()
    (bad / "manifest.json").write_text("{")
    (bad / "run.json").write_text("{")
    (bad / "result.json").write_text("{")
    run_lab("voting", str(tmp_path))

    board = render_board(str(tmp_path))

    assert "1/1 passed" in board
    assert "broken" in board
    assert "unreadable" in board


def test_board_retains_evaluator_mismatch_as_unverified(tmp_path):
    directory, _ = run_lab("voting", str(tmp_path))
    result_path = Path(directory) / "result.json"
    result = json.loads(result_path.read_text())
    result["evaluator_version"] = "historical-version"
    result_path.write_text(json.dumps(result))
    import hashlib
    from nandatown.records import fingerprint
    manifest_path = Path(directory) / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["files"]["result.json"] = "sha256:" + hashlib.sha256(result_path.read_bytes()).hexdigest()
    manifest["bundle_fingerprint"] = fingerprint(manifest["files"])
    manifest_path.write_text(json.dumps(manifest))

    board = render_board(str(tmp_path))

    assert "evaluator version differs" in board
    assert "1/1 passed" not in board


def test_unverified_bundle_remains_visible_in_terminal_browser(tmp_path):
    import asyncio
    from textual.widgets import DataTable, Static
    from nandatown.tui import TownApp

    bad = tmp_path / "broken"
    bad.mkdir()
    (bad / "manifest.json").write_text("{")

    async def browse():
        app = TownApp(out_dir=str(tmp_path))
        async with app.run_test():
            table = app.query_one("#bundle-table", DataTable)
            assert table.row_count == 1
            assert "unverified" in [str(cell) for cell in table.get_row("broken")]
            assert "0 passed" in str(app.query_one("#town-status", Static).render())

    asyncio.run(browse())


def test_duplicate_bundle_copies_count_once_and_open_the_actual_directory(tmp_path):
    import asyncio
    import shutil
    from textual.widgets import DataTable
    from nandatown.tui import TownApp

    directory, _ = run_lab("voting", str(tmp_path))
    copied = tmp_path / "a-copy-with-a-different-name"
    shutil.copytree(directory, copied)
    rows = scan_bundles(str(tmp_path))
    assert len(rows) == 1
    assert "1/1 passed" in render_board(str(tmp_path))

    async def browse():
        app = TownApp(out_dir=str(tmp_path))
        async with app.run_test():
            table = app.query_one("#bundle-table", DataTable)
            assert table.row_count == 1
            table.move_cursor(row=0)
            assert Path(app._selected_bundle()) == copied

    asyncio.run(browse())


def test_board_escapes_control_characters_in_unverified_paths(tmp_path):
    bad = tmp_path / "bad\nINJECTED\x1b[2J"
    bad.mkdir()
    (bad / "manifest.json").write_text("{")
    rendered = render_board(str(tmp_path))
    assert "\x1b" not in rendered
    assert "bad\nINJECTED" not in rendered
    assert "bad\\nINJECTED\\x1b[2J" in rendered
