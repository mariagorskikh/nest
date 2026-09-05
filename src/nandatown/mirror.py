"""Walk-away mirroring: evidence that survives its origin.

A bundle is content addressed by its fingerprint. Mirror it anywhere,
lose the original, lose all but one mirror, and the run can still be
recovered and verified byte for byte. Passing the walk-away test
proves one recovery path, not truth; the verify step still judges the
evidence itself.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import tempfile

from .bundle import DIGEST_RE, RECORD_FILES, load_bundle, verify_bundle


MIRROR_COPY_FILES = frozenset(
    [*RECORD_FILES, "manifest.json", "attestation.json", "receipt.json"])
MIRROR_ALLOWED_FILES = MIRROR_COPY_FILES | {"report.md"}
SOURCE_ONLY_MEMBERS = {"state", "town.html"}


class MirrorError(Exception):
    pass


def _fingerprint_of(bundle_dir: str) -> str:
    manifest_path = os.path.join(bundle_dir, "manifest.json")
    try:
        metadata = os.lstat(manifest_path)
        if not stat.S_ISREG(metadata.st_mode):
            raise MirrorError("manifest.json is not a regular file")
        with open(manifest_path) as f:
            manifest = json.load(f)
        fingerprint = manifest["bundle_fingerprint"]
    except MirrorError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError,
            TypeError) as exc:
        raise MirrorError(f"cannot read bundle fingerprint: {exc}") from exc
    if not isinstance(fingerprint, str) or not DIGEST_RE.fullmatch(fingerprint):
        raise MirrorError("invalid bundle fingerprint in manifest")
    return fingerprint


def _tree_problem(bundle_dir: str, *, source_only: bool = False) -> str | None:
    """Reject links, special files, and unsupported top-level payloads."""
    try:
        root_metadata = os.lstat(bundle_dir)
    except OSError as exc:
        return f"bundle directory is unreadable: {exc}"
    if not stat.S_ISDIR(root_metadata.st_mode):
        return "bundle path is not a regular directory"

    try:
        with os.scandir(bundle_dir) as entries:
            for entry in entries:
                if source_only and entry.name in SOURCE_ONLY_MEMBERS:
                    continue
                if entry.name not in MIRROR_ALLOWED_FILES:
                    return f"{entry.name} is an unsupported bundle member"
                try:
                    metadata = entry.stat(follow_symlinks=False)
                except OSError as exc:
                    return f"{entry.name} is unreadable: {exc}"
                if not stat.S_ISREG(metadata.st_mode):
                    return f"{entry.name} is not a regular file"
    except OSError as exc:
        return f". is unreadable: {exc}"
    return None


def _validate_bundle(bundle_dir: str, label: str, *,
                     expected_fingerprint: str | None = None,
                     source_only: bool = False) -> str:
    tree_problem = _tree_problem(bundle_dir, source_only=source_only)
    if tree_problem:
        raise MirrorError(f"{label} has an unsafe tree: {tree_problem}")
    problems = verify_bundle(bundle_dir)
    if problems:
        raise MirrorError(f"{label} bundle fails verification: {problems}")
    receipt_path = os.path.join(bundle_dir, "receipt.json")
    if os.path.lexists(receipt_path):
        from .receipt import verify_receipt

        receipt_problems = verify_receipt(receipt_path, bundle_dir)
        if receipt_problems:
            raise MirrorError(
                f"{label} receipt fails verification: {receipt_problems}")
    fingerprint = _fingerprint_of(bundle_dir)
    if expected_fingerprint is not None \
            and fingerprint != expected_fingerprint:
        raise MirrorError(
            f"{label} manifest disagrees with its content address")
    return fingerprint


def _copy_bundle(bundle_dir: str, destination: str, fingerprint: str) -> None:
    parent = os.path.dirname(destination)
    os.makedirs(parent, exist_ok=True)
    staging_root = tempfile.mkdtemp(prefix=".nandatown-copy-", dir=parent)
    staged_bundle = os.path.join(staging_root, "bundle")
    try:
        os.mkdir(staged_bundle)
        for name in sorted(MIRROR_COPY_FILES):
            source = os.path.join(bundle_dir, name)
            if not os.path.lexists(source):
                continue
            shutil.copy2(source, os.path.join(staged_bundle, name),
                         follow_symlinks=False)
        _validate_bundle(
            staged_bundle, "copied", expected_fingerprint=fingerprint)
        from .report import render_report

        with open(os.path.join(staged_bundle, "report.md"), "w") as stream:
            stream.write(render_report(load_bundle(staged_bundle)))
        if os.path.lexists(destination):
            raise MirrorError(
                f"destination already exists and was left unchanged:"
                f" {destination}")
        os.rename(staged_bundle, destination)
    except MirrorError:
        raise
    except OSError as exc:
        raise MirrorError(f"could not copy verified bundle: {exc}") from exc
    finally:
        shutil.rmtree(staging_root, ignore_errors=True)


def mirror_bundle(bundle_dir: str, mirror_dir: str) -> str:
    fingerprint = _validate_bundle(
        bundle_dir, "source", source_only=True)
    slug = fingerprint.removeprefix("sha256:")
    destination = os.path.join(mirror_dir, slug)
    if os.path.lexists(destination):
        _validate_bundle(
            destination, "existing mirror",
            expected_fingerprint=fingerprint)
        return destination
    _copy_bundle(bundle_dir, destination, fingerprint)
    return destination


def recover_bundle(fingerprint: str, mirrors: list[str],
                   out_dir: str) -> str:
    if not isinstance(fingerprint, str) or not DIGEST_RE.fullmatch(fingerprint):
        raise MirrorError(f"invalid bundle fingerprint: {fingerprint!r}")
    slug = fingerprint.removeprefix("sha256:")
    destination = os.path.join(out_dir, f"recovered-{slug[:12]}")
    if os.path.lexists(destination):
        raise MirrorError(
            f"destination already exists and was left unchanged: {destination}")

    rejections: list[str] = []
    for mirror in mirrors:
        candidate = os.path.join(mirror, slug)
        if not os.path.lexists(candidate):
            continue
        try:
            _validate_bundle(
                candidate, f"mirror {mirror}",
                expected_fingerprint=fingerprint)
            _copy_bundle(candidate, destination, fingerprint)
            return destination
        except MirrorError as exc:
            rejections.append(str(exc))
    detail = f"; rejected: {'; '.join(rejections)}" if rejections else ""
    raise MirrorError(f"no valid surviving mirror holds {fingerprint}{detail}")
