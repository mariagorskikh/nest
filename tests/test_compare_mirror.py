import json
import os
import shutil
from pathlib import Path

import pytest

from nandatown.cli import main
from nandatown.compare import run_comparison
from nandatown.mirror import MirrorError, mirror_bundle, recover_bundle
from nandatown.receipt import make_receipt, verify_receipt
from nandatown.sim.runner import run_lab


def test_comparison_shows_what_the_swap_breaks(tmp_path):
    compare_dir, comparison = run_comparison(
        "capability_spoofing", {"auth": "plain.v1"}, str(tmp_path))
    assert comparison["variants"]["baseline"]["verdict"] == "passed"
    assert comparison["variants"]["swapped"]["verdict"] == "failed"
    assert "containment" in comparison["differences"]
    assert "spoof_detected" in comparison["differences"]
    with open(os.path.join(compare_dir, "comparison.md")) as f:
        text = f.read()
    assert "Same agents, same scenario, same seed" in text
    assert "<- differs" in text
    bundles = [d for d in os.listdir(compare_dir)
               if d.startswith("sim-")]
    assert len(bundles) == 2


def test_comparison_with_no_behavioral_change(tmp_path):
    _, comparison = run_comparison("voting", {"payments": "ledger.v1"},
                                   str(tmp_path))
    assert comparison["differences"] == []


def test_walk_away_recovery(tmp_path):
    bundle_dir, _ = run_lab("voting", str(tmp_path / "runs"))
    with open(os.path.join(bundle_dir, "manifest.json")) as f:
        fingerprint = json.load(f)["bundle_fingerprint"]

    mirror_a = str(tmp_path / "mirror-a")
    mirror_b = str(tmp_path / "mirror-b")
    mirror_bundle(bundle_dir, mirror_a)
    mirror_bundle(bundle_dir, mirror_b)

    # Walk away: the original database is gone, the original bundle is
    # gone, and the first mirror is gone too.
    shutil.rmtree(bundle_dir)
    shutil.rmtree(mirror_a)

    restored = recover_bundle(fingerprint, [mirror_a, mirror_b],
                              str(tmp_path / "fresh"))
    assert os.path.exists(os.path.join(restored, "events.jsonl"))

    shutil.rmtree(mirror_b)
    with pytest.raises(MirrorError):
        recover_bundle(fingerprint, [mirror_a, mirror_b],
                       str(tmp_path / "fresh2"))


def test_tampered_mirror_is_rejected(tmp_path):
    bundle_dir, _ = run_lab("voting", str(tmp_path / "runs"))
    with open(os.path.join(bundle_dir, "manifest.json")) as f:
        fingerprint = json.load(f)["bundle_fingerprint"]
    mirror = str(tmp_path / "mirror")
    stored = mirror_bundle(bundle_dir, mirror)
    events = os.path.join(stored, "events.jsonl")
    with open(events, "a") as f:
        f.write('{"forged": true}\n')
    with pytest.raises(MirrorError):
        recover_bundle(fingerprint, [mirror], str(tmp_path / "fresh"))


@pytest.mark.parametrize(
    "fingerprint",
    ["sha256:../escape", "sha256:/absolute", "sha256:" + "a" * 63,
     "a" * 64],
    ids=["traversal", "absolute", "short", "missing-prefix"],
)
def test_recovery_rejects_invalid_fingerprint_addresses(tmp_path, fingerprint):
    with pytest.raises(MirrorError, match="invalid bundle fingerprint"):
        recover_bundle(fingerprint, [str(tmp_path / "mirror")],
                       str(tmp_path / "fresh"))

    assert not (tmp_path / "fresh").exists()


def test_mirror_validates_source_before_copying(tmp_path):
    bundle_dir, _ = run_lab("voting", str(tmp_path / "runs"))
    manifest_path = os.path.join(bundle_dir, "manifest.json")
    with open(manifest_path) as f:
        manifest = json.load(f)
    manifest["bundle_fingerprint"] = "sha256:not-a-digest"
    with open(manifest_path, "w") as f:
        json.dump(manifest, f)

    mirror = tmp_path / "mirror"
    with pytest.raises(MirrorError, match="source bundle fails verification"):
        mirror_bundle(bundle_dir, str(mirror))

    assert not mirror.exists()


def test_existing_corrupt_mirror_is_not_silently_accepted(tmp_path):
    bundle_dir, _ = run_lab("voting", str(tmp_path / "runs"))
    mirror = str(tmp_path / "mirror")
    stored = mirror_bundle(bundle_dir, mirror)
    with open(os.path.join(stored, "events.jsonl"), "a") as f:
        f.write('{"forged": true}\n')

    with pytest.raises(MirrorError, match="existing mirror"):
        mirror_bundle(bundle_dir, mirror)


def test_corrupt_first_mirror_does_not_hide_valid_later_mirror(tmp_path):
    bundle_dir, _ = run_lab("voting", str(tmp_path / "runs"))
    with open(os.path.join(bundle_dir, "manifest.json")) as f:
        fingerprint = json.load(f)["bundle_fingerprint"]
    mirror_a = str(tmp_path / "mirror-a")
    mirror_b = str(tmp_path / "mirror-b")
    stored_a = mirror_bundle(bundle_dir, mirror_a)
    mirror_bundle(bundle_dir, mirror_b)
    with open(os.path.join(stored_a, "events.jsonl"), "a") as f:
        f.write('{"forged": true}\n')

    restored = recover_bundle(fingerprint, [mirror_a, mirror_b],
                              str(tmp_path / "fresh"))

    assert os.path.exists(os.path.join(restored, "events.jsonl"))


def test_recovery_rejects_unsafe_tree_before_copy_and_tries_next(tmp_path):
    bundle_dir, _ = run_lab("voting", str(tmp_path / "runs"))
    with open(os.path.join(bundle_dir, "manifest.json")) as f:
        fingerprint = json.load(f)["bundle_fingerprint"]
    mirror_a = str(tmp_path / "mirror-a")
    mirror_b = str(tmp_path / "mirror-b")
    stored_a = mirror_bundle(bundle_dir, mirror_a)
    mirror_bundle(bundle_dir, mirror_b)
    outside = tmp_path / "outside.txt"
    outside.write_text("must not be copied")
    os.symlink(outside, os.path.join(stored_a, "unsafe-link"))

    restored = recover_bundle(fingerprint, [mirror_a, mirror_b],
                              str(tmp_path / "fresh"))

    assert not os.path.lexists(os.path.join(restored, "unsafe-link"))


def test_failed_recovery_does_not_leave_a_copied_destination(tmp_path):
    bundle_dir, _ = run_lab("voting", str(tmp_path / "runs"))
    with open(os.path.join(bundle_dir, "manifest.json")) as f:
        fingerprint = json.load(f)["bundle_fingerprint"]
    mirror = str(tmp_path / "mirror")
    stored = mirror_bundle(bundle_dir, mirror)
    with open(os.path.join(stored, "events.jsonl"), "a") as f:
        f.write('{"forged": true}\n')
    destination = (tmp_path / "fresh" /
                   f"recovered-{fingerprint.removeprefix('sha256:')[:12]}")

    with pytest.raises(MirrorError):
        recover_bundle(fingerprint, [mirror], str(tmp_path / "fresh"))

    assert not destination.exists()


def test_recovery_preserves_preexisting_destination(tmp_path):
    bundle_dir, _ = run_lab("voting", str(tmp_path / "runs"))
    with open(os.path.join(bundle_dir, "manifest.json")) as f:
        fingerprint = json.load(f)["bundle_fingerprint"]
    mirror = str(tmp_path / "mirror")
    mirror_bundle(bundle_dir, mirror)
    destination = (tmp_path / "fresh" /
                   f"recovered-{fingerprint.removeprefix('sha256:')[:12]}")
    destination.mkdir(parents=True)
    marker = destination / "user-data.txt"
    marker.write_text("keep me")

    with pytest.raises(MirrorError, match="already exists"):
        recover_bundle(fingerprint, [mirror], str(tmp_path / "fresh"))

    assert marker.read_text() == "keep me"


def test_address_mismatch_does_not_hide_valid_later_mirror(tmp_path):
    bundle_dir, _ = run_lab("voting", str(tmp_path / "runs-a"))
    other_bundle, _ = run_lab("marketplace", str(tmp_path / "runs-b"))
    with open(os.path.join(bundle_dir, "manifest.json")) as f:
        fingerprint = json.load(f)["bundle_fingerprint"]
    slug = fingerprint.removeprefix("sha256:")
    bad_mirror = tmp_path / "bad-mirror"
    bad_mirror.mkdir()
    shutil.copytree(other_bundle, bad_mirror / slug)
    good_mirror = str(tmp_path / "good-mirror")
    mirror_bundle(bundle_dir, good_mirror)

    restored = recover_bundle(
        fingerprint, [str(bad_mirror), good_mirror], str(tmp_path / "fresh"))

    with open(os.path.join(restored, "manifest.json")) as f:
        assert json.load(f)["bundle_fingerprint"] == fingerprint


def test_cli_compare_and_mirror(tmp_path, capsys):
    out = str(tmp_path)
    assert main(["compare", "voting", "--swap", "trust=reputation.v1",
                 "--out", out]) == 0
    text = capsys.readouterr().out
    assert "Protocol Comparison" in text
    run_dirs = [d for d in os.listdir(out) if d.startswith("cmp-")]
    bundle = None
    for d in os.listdir(os.path.join(out, run_dirs[0])):
        if d.startswith("sim-"):
            bundle = os.path.join(out, run_dirs[0], d)
    assert main(["mirror", bundle, str(tmp_path / "m")]) == 0
    with open(os.path.join(bundle, "manifest.json")) as f:
        fingerprint = json.load(f)["bundle_fingerprint"]
    assert main(["recover", fingerprint, "--mirror",
                 str(tmp_path / "m"), "--out", out]) == 0
    assert "recovered and verified" in capsys.readouterr().out


def test_mirror_cli_reports_invalid_source_without_traceback(tmp_path, capsys):
    from nandatown.cli import main

    source = tmp_path / "broken"
    source.mkdir()
    (source / "manifest.json").write_text("{")
    assert main(["mirror", str(source), str(tmp_path / "mirror")]) == 1
    assert "mirror failed:" in capsys.readouterr().out


@pytest.mark.parametrize(
    "extra", ["unsigned.txt", "state/secret.txt", "town.html"])
def test_recovery_rejects_unsigned_mirror_payload(tmp_path, extra):
    bundle_dir, _ = run_lab("voting", str(tmp_path / "runs"))
    manifest = json.loads(Path(bundle_dir, "manifest.json").read_text())
    fingerprint = manifest["bundle_fingerprint"]
    mirror = str(tmp_path / "mirror")
    stored = Path(mirror_bundle(bundle_dir, mirror))
    extra_path = stored / extra
    extra_path.parent.mkdir(parents=True, exist_ok=True)
    extra_path.write_text("must not be recovered")

    with pytest.raises(MirrorError, match="unsupported bundle member"):
        recover_bundle(fingerprint, [mirror], str(tmp_path / "fresh"))

    assert not (tmp_path / "fresh").exists()


def test_visualized_source_mirrors_without_copying_generated_html(
        tmp_path, capsys):
    bundle_dir, _ = run_lab("voting", str(tmp_path / "runs"))
    source = Path(bundle_dir)
    source_report = source.joinpath("report.md").read_text()
    assert main(["visualize", bundle_dir]) == 0
    assert source.joinpath("town.html").is_file()
    capsys.readouterr()
    manifest = json.loads(source.joinpath("manifest.json").read_text())

    mirror = str(tmp_path / "mirror")
    stored = Path(mirror_bundle(bundle_dir, mirror))

    assert not stored.joinpath("town.html").exists()
    assert stored.joinpath("report.md").read_text() == source_report
    stored.joinpath("report.md").write_text("UNSIGNED MIRROR CLAIM")

    restored = Path(recover_bundle(
        manifest["bundle_fingerprint"], [mirror], str(tmp_path / "fresh")))

    assert not restored.joinpath("town.html").exists()
    assert restored.joinpath("report.md").read_text() == source_report


def test_recovery_regenerates_unsigned_report(tmp_path):
    bundle_dir, _ = run_lab("voting", str(tmp_path / "runs"))
    manifest = json.loads(Path(bundle_dir, "manifest.json").read_text())
    fingerprint = manifest["bundle_fingerprint"]
    mirror = str(tmp_path / "mirror")
    stored = Path(mirror_bundle(bundle_dir, mirror))
    stored.joinpath("report.md").write_text("UNSIGNED MIRROR CLAIM")

    restored = Path(recover_bundle(
        fingerprint, [mirror], str(tmp_path / "fresh")))

    report = restored.joinpath("report.md").read_text()
    assert "UNSIGNED MIRROR CLAIM" not in report
    assert "NANDA Town System Fitness Report" in report


def test_recovery_rejects_invalid_receipt_and_preserves_valid_one(tmp_path):
    bundle_dir, _ = run_lab("voting", str(tmp_path / "runs"))
    receipt_path = make_receipt(bundle_dir)
    manifest = json.loads(Path(bundle_dir, "manifest.json").read_text())
    fingerprint = manifest["bundle_fingerprint"]
    good_mirror = str(tmp_path / "good-mirror")
    mirror_bundle(bundle_dir, good_mirror)
    restored = Path(recover_bundle(
        fingerprint, [good_mirror], str(tmp_path / "fresh")))
    assert verify_receipt(str(restored / "receipt.json"), str(restored)) == []

    bad_mirror = str(tmp_path / "bad-mirror")
    stored = Path(mirror_bundle(bundle_dir, bad_mirror))
    stored.joinpath("receipt.json").write_text("{}")
    with pytest.raises(MirrorError, match="receipt"):
        recover_bundle(fingerprint, [bad_mirror], str(tmp_path / "other"))
