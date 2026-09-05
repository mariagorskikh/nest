"""Protocol onboarding: pull a contribution from the upstream repo.

A pull request to projnanda/nandatown usually carries a protocol (the
rules), a plugin (the code that runs those rules in one layer), and a
test. Importing one here snapshots the PR's files at its exact head
commit, fingerprints them, classifies what they are, runs the same
structural checks the On-Ramp uses, and catalogs the result as
imported-untrusted. Importing never runs the code: running it against
the reference agents is a separate, explicit choice through
`nandatown run ... --plugin ... --layer ...`.
"""

from __future__ import annotations

import base64
import json
import os
import re
import shlex
import time
from typing import Any

import httpx

from .onramp import SECRET_PATTERNS, slugify
from .records import EvidenceRecord, fingerprint

DEFAULT_REPO = "projnanda/nandatown"
API = "https://api.github.com"
MAX_FILES = 50
MAX_FILE_BYTES = 200_000
OBSERVER = "protocol-import.v1"

REGISTER_RE = re.compile(r"@register\(\s*[\"'](\w+)[\"']\s*,"
                         r"\s*[\"']([\w.-]+)[\"']")


class ProtocolImportError(Exception):
    pass


def _client(http: httpx.Client | None) -> httpx.Client:
    if http is not None:
        return http
    headers = {"Accept": "application/vnd.github+json",
               "User-Agent": "nandatown-local"}
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return httpx.Client(base_url=API, headers=headers, timeout=30.0)


def fetch_pr(repo: str, number: int,
             http: httpx.Client | None = None) -> dict[str, Any]:
    client = _client(http)
    try:
        return _fetch_pr(repo, number, client)
    finally:
        if http is None:
            client.close()


def _fetch_pr(repo: str, number: int, client: httpx.Client) -> dict[str, Any]:
    r = client.get(f"/repos/{repo}/pulls/{number}")
    if r.status_code == 404:
        raise ProtocolImportError(f"no PR #{number} in {repo}")
    r.raise_for_status()
    pr = r.json()
    head_sha = pr["head"]["sha"]
    head_repo = (pr["head"].get("repo") or {}).get("full_name", repo)

    files_response = client.get(f"/repos/{repo}/pulls/{number}/files",
                                params={"per_page": MAX_FILES + 1})
    files_response.raise_for_status()
    listed = files_response.json()
    skipped = []
    files = []
    for entry in listed[:MAX_FILES]:
        path = entry["filename"]
        if entry.get("status") == "removed":
            skipped.append(f"{path} (removed by the PR)")
            continue
        content_response = client.get(
            f"/repos/{head_repo}/contents/{path}",
            params={"ref": head_sha})
        if content_response.status_code != 200:
            skipped.append(f"{path} (unreadable at the head commit)")
            continue
        payload = content_response.json()
        if payload.get("size", 0) > MAX_FILE_BYTES:
            skipped.append(f"{path} (over {MAX_FILE_BYTES} bytes)")
            continue
        try:
            content = base64.b64decode(
                payload.get("content", "")).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            skipped.append(f"{path} (not text)")
            continue
        files.append({"path": path, "content": content})
    total = pr.get("changed_files")
    if isinstance(total, int) and not isinstance(total, bool) and total > MAX_FILES:
        skipped.append(f"{total - MAX_FILES} further files beyond"
                       f" the {MAX_FILES} file cap; snapshot is partial")
    elif len(listed) > MAX_FILES:
        skipped.append(f"additional files beyond the {MAX_FILES} file cap;"
                       " snapshot is partial")
    return {
        "repo": repo,
        "number": number,
        "title": pr["title"],
        "author": pr["user"]["login"],
        "state": pr["state"],
        "head_sha": head_sha,
        "head_repo": head_repo,
        "files": files,
        "skipped": skipped,
    }


def classify(files: list[dict[str, str]]) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {"plugins": [], "scenarios": [],
                                  "skills": [], "tests": [], "other": []}
    for f in files:
        path, content = f["path"], f["content"]
        base = os.path.basename(path)
        if base.startswith("test_") and path.endswith(".py"):
            out["tests"].append({"path": path})
        elif path.endswith(".py") and REGISTER_RE.search(content):
            registrations = [{"layer": m.group(1), "plugin_id": m.group(2)}
                             for m in REGISTER_RE.finditer(content)]
            out["plugins"].append({"path": path,
                                   "registrations": registrations})
        elif path.endswith((".yaml", ".yml")) and "agents:" in content:
            out["scenarios"].append({"path": path})
        elif base.upper() == "SKILL.MD" or (
                path.endswith(".md") and content.startswith("---")):
            out["skills"].append({"path": path})
        else:
            out["other"].append({"path": path})
    return out


def structural_checks(pr: dict[str, Any],
                      classification: dict[str, list[dict]]
                      ) -> list[EvidenceRecord]:
    subject = f"{pr['repo']}#{pr['number']}@{pr['head_sha'][:12]}"
    checks: list[EvidenceRecord] = []
    seq = 0

    def add(test: str, result: str, evidence: list[str]):
        nonlocal seq
        seq += 1
        checks.append(EvidenceRecord(
            record_id=f"pri-{seq}", observer=OBSERVER, subject=subject,
            capability="structural", test=test, result=result,
            at=time.time(), evidence=evidence[:8]))

    add("files-fetched",
        ("failed" if not pr["files"] else
         "not_enough_evidence" if pr["skipped"] else "passed"),
        [f"{len(pr['files'])} files at {pr['head_sha'][:12]}"]
        + pr["skipped"])

    interesting = (classification["plugins"] or classification["scenarios"]
                   or classification["skills"])
    add("contribution-shape",
        "passed" if interesting else "not_enough_evidence",
        [f"plugins {len(classification['plugins'])},"
         f" scenarios {len(classification['scenarios'])},"
         f" skills {len(classification['skills'])},"
         f" tests {len(classification['tests'])}"])

    add("tests-included",
        "passed" if classification["tests"] else "not_enough_evidence",
        [t["path"] for t in classification["tests"]]
        or ["the PR carries no test files"])

    hits = []
    for f in pr["files"]:
        for pattern in SECRET_PATTERNS:
            for match in pattern.finditer(f["content"]):
                hits.append(f"possible secret in {f['path']} near"
                            f" offset {match.start()}")
    add("secret-scan", "failed" if hits else "passed",
        hits or ["no embedded secrets matched"])
    return checks


def usage_recipe(protocol_dir: str,
                 classification: dict[str, list[dict]]) -> list[str]:
    lines = []
    for plugin in classification["plugins"]:
        argv = ["nandatown", "run", "marketplace", "--plugin",
                os.path.join(protocol_dir, plugin["path"])]
        for reg in plugin["registrations"]:
            argv.extend(["--layer", f"{reg['layer']}={reg['plugin_id']}"])
        lines.append(shlex.join(argv))
    for scenario in classification["scenarios"]:
        lines.append(shlex.join([
            "nandatown", "run", os.path.join(protocol_dir, scenario["path"])]))
    for skill in classification["skills"]:
        lines.append(shlex.join([
            "nandatown", "skills", "--validate",
            os.path.join(protocol_dir, skill["path"])]))
    return lines


def import_pr(number: int, repo: str = DEFAULT_REPO,
              out_dir: str = "protocols",
              http: httpx.Client | None = None) -> str:
    pr = fetch_pr(repo, number, http=http)
    name = f"{number}-{slugify(pr['title'])[:40]}"
    protocol_dir = os.path.join(out_dir, name)
    if os.path.islink(protocol_dir):
        raise ProtocolImportError("snapshot directory is a symbolic link")
    for metadata_name in ("metadata.json", "checks.jsonl"):
        if os.path.islink(os.path.join(protocol_dir, metadata_name)):
            raise ProtocolImportError("snapshot metadata is a symbolic link")
    if os.path.islink(os.path.join(out_dir, "catalog.json")):
        raise ProtocolImportError("catalog is a symbolic link")
    os.makedirs(protocol_dir, exist_ok=True)

    root = os.path.abspath(protocol_dir)
    safe_files = []
    for f in pr["files"]:
        dest = os.path.abspath(os.path.join(root, f["path"]))
        if (os.path.isabs(f["path"]) or dest == root
                or os.path.commonpath([root, dest]) != root):
            pr["skipped"].append(f"{f['path']} (path escapes the"
                                 " snapshot directory)")
            continue
        relative = os.path.relpath(dest, root)
        parts = relative.split(os.sep)
        if parts[0] in {"metadata.json", "checks.jsonl"}:
            pr["skipped"].append(f"{f['path']} (reserved snapshot metadata)")
            continue
        if any(os.path.islink(os.path.join(root, *parts[:n]))
               for n in range(1, len(parts) + 1)):
            pr["skipped"].append(f"{f['path']} (symbolic link in snapshot path)")
            continue
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest, "w") as fh:
            fh.write(f["content"])
        safe_files.append(f)
    pr["files"] = safe_files
    classification = classify(pr["files"])
    checks = structural_checks(pr, classification)

    content_fp = fingerprint([{f["path"]: f["content"]}
                              for f in pr["files"]])
    metadata = {
        "repo": pr["repo"], "number": pr["number"], "title": pr["title"],
        "author": pr["author"], "state": pr["state"],
        "head_sha": pr["head_sha"], "head_repo": pr["head_repo"],
        "fingerprint": content_fp,
        "classification": classification,
        "skipped": pr["skipped"],
        "status": "imported-untrusted",
        "imported_at": time.time(),
        "usage": usage_recipe(protocol_dir, classification),
    }
    with open(os.path.join(protocol_dir, "metadata.json"), "w") as fh:
        json.dump(metadata, fh, indent=2)
    with open(os.path.join(protocol_dir, "checks.jsonl"), "w") as fh:
        for check in checks:
            fh.write(check.model_dump_json() + "\n")

    catalog_path = os.path.join(out_dir, "catalog.json")
    catalog = []
    if os.path.exists(catalog_path):
        with open(catalog_path) as fh:
            catalog = json.load(fh)
    catalog = [e for e in catalog if e["name"] != name]
    counts = {"passed": 0, "failed": 0, "unknown": 0}
    for check in checks:
        key = ("unknown" if check.result == "not_enough_evidence"
               else check.result)
        counts[key] += 1
    catalog.append({"name": name, "repo": repo, "number": number,
                    "title": pr["title"], "author": pr["author"],
                    "head_sha": pr["head_sha"],
                    "fingerprint": content_fp,
                    "status": "imported-untrusted", "checks": counts,
                    "imported_at": time.time()})
    with open(catalog_path, "w") as fh:
        json.dump(sorted(catalog, key=lambda e: e["name"]), fh, indent=2)
    return protocol_dir


def protocol_entries(out_dir: str = "protocols") -> list[dict[str, Any]]:
    catalog_path = os.path.join(out_dir, "catalog.json")
    if not os.path.exists(catalog_path):
        return []
    with open(catalog_path) as fh:
        return json.load(fh)
