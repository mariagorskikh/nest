import pytest
from fastapi.testclient import TestClient

from nandatown.a2a_adapter import build_a2a_app
from nandatown.bundle import load_bundle
from nandatown.cli import main
from nandatown.path_runner import run_path_test
from nandatown.report import render_report
from nandatown.sim.runner import run_lab


@pytest.fixture
def path_client(monkeypatch):
    with TestClient(build_a2a_app("http://testserver")) as client:
        def run(url, out, **kwargs):
            return run_path_test(url, out, http=client, **kwargs)
        monkeypatch.setattr("nandatown.path_runner.run_path_test", run)
        yield


def test_path_cli_reports_untested_stages_in_denominator(tmp_path, capsys, path_client):
    assert main(["test-agent", "--url", "http://testserver", "--out", str(tmp_path)]) == 0
    text = capsys.readouterr().out
    assert "5 of 6 path stages passed" in text
    assert "1 not tested" in text


def test_path_cli_rejects_ignored_track_profile(tmp_path, capsys, path_client):
    assert main(["test-agent", "--url", "http://testserver",
                 "--profile", "quote-clean", "--out", str(tmp_path)]) == 2
    assert "--path-profile" in capsys.readouterr().out
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("count", ["0", "-1"])
def test_pulse_cli_rejects_nonpositive_count_without_creating_db(tmp_path, capsys, count):
    database = tmp_path / "pulse.db"
    assert main(["pulse", "--target", "demo=http://invalid.test", "--count", count,
                 "--db", str(database)]) == 2
    assert "count" in capsys.readouterr().out
    assert not database.exists()


@pytest.mark.parametrize("status", ["passed", "not_tested"])
def test_report_identity_explanation_matches_observation(tmp_path, status):
    directory, _ = run_lab("voting", str(tmp_path))
    bundle = load_bundle(directory)
    bundle["result"].stages = [bundle["result"].stages[0].model_copy(
        update={"name": "portable_identity", "status": status, "note": ""})]

    report = render_report(bundle)
    line = next(line for line in report.splitlines() if "portable_identity" in line)

    if status == "passed":
        assert "not exercised" not in line
        assert "verified" in line
    else:
        assert "not exercised" in line


def test_report_untested_descriptor_does_not_claim_a_match(tmp_path, path_client):
    with TestClient(build_a2a_app("http://testserver")) as client:
        directory, _ = run_path_test("http://testserver", str(tmp_path), http=client)
    report = render_report(load_bundle(directory))
    line = next(line for line in report.splitlines() if "descriptor_consistency" in line)
    assert "matches the pinned" not in line
    assert "not exercised" in line
