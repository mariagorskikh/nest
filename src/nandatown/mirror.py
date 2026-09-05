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

from .bundle import DIGEST_RE, verify_bundle


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


def _tree_problem(bundle_dir: str, *, ignore_state: bool = False) -> str | None:
    """Reject links and special files without following them."""
    try:
        root_metadata = os.lstat(bundle_dir)
    except OSError as exc:
        return f"bundle directory is unreadable: {exc}"
    if not stat.S_ISDIR(root_metadata.st_mode):
        return "bundle path is not a regular directory"

    def inspect(directory: str, relative: str) -> str | None:
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    if ignore_state and entry.name == "state":
                        continue
                    entry_relative = os.path.join(relative, entry.name)
                    try:
                        metadata = entry.stat(follow_symlinks=False)
                    except OSError as exc:
                        return f"{entry_relative} is unreadable: {exc}"
                    if stat.S_ISDIR(metadata.st_mode):
                        problem = inspect(entry.path, entry_relative)
                        if problem:
                            return problem
                    elif not stat.S_ISREG(metadata.st_mode):
                        return f"{entry_relative} is not a regular file"
        except OSError as exc:
            shown = relative or "."
            return f"{shown} is unreadable: {exc}"
        return None

    return inspect(bundle_dir, "")


def _validate_bundle(bundle_dir: str, label: str, *,
                     expected_fingerprint: str | None = None,
                     ignore_state: bool = False) -> str:
    tree_problem = _tree_problem(bundle_dir, ignore_state=ignore_state)
    if tree_problem:
        raise MirrorError(f"{label} has an unsafe tree: {tree_problem}")
    problems = verify_bundle(bundle_dir)
    if problems:
        raise MirrorError(f"{label} bundle fails verification: {problems}")
    fingerprint = _fingerprint_of(bundle_dir)
    if expected_fingerprint is not None \
            and fingerprint != expected_fingerprint:
        raise MirrorError(
            f"{label} manifest disagrees with its content address")
    return fingerprint


def _copy_bundle(bundle_dir: str, destination: str, fingerprint: str,
                 *, ignore_state: bool = False) -> None:
    parent = os.path.dirname(destination)
    os.makedirs(parent, exist_ok=True)
    staging_root = tempfile.mkdtemp(prefix=".nandatown-copy-", dir=parent)
    staged_bundle = os.path.join(staging_root, "bundle")
    try:
        ignore = shutil.ignore_patterns("state") if ignore_state else None
        shutil.copytree(bundle_dir, staged_bundle, symlinks=True, ignore=ignore)
        _validate_bundle(
            staged_bundle, "copied", expected_fingerprint=fingerprint)
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
        bundle_dir, "source", ignore_state=True)
    slug = fingerprint.removeprefix("sha256:")
    destination = os.path.join(mirror_dir, slug)
    if os.path.lexists(destination):
        _validate_bundle(
            destination, "existing mirror",
            expected_fingerprint=fingerprint)
        return destination
    _copy_bundle(
        bundle_dir, destination, fingerprint, ignore_state=True)
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
