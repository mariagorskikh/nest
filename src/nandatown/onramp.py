"""The Town On-Ramp: from a provider's OpenAPI document to a reviewable
SkillMD candidate.

The stages stay distinct: a LOCAL input (never fetched from the network
here), a snapshot with a content fingerprint, a reviewable candidate
with marked unknowns, structural checks as evidence records, and a
pinned catalog entry. The generated SKILL.md and its declared
permissions are a claim, not yet a fact: town tests decide what the
evidence changes. Submitted material is data; nothing in it is ever
executed.
"""

from __future__ import annotations

import json
import os
import re
import time
from typing import Any

import yaml

from .records import EvidenceRecord, ReleaseRef, fingerprint

OBSERVER = "onramp.v1"

SECRET_PATTERNS = [
    re.compile(r"sk_(?:live|test)_[A-Za-z0-9]{8,}"),
    re.compile(r"(?i)\b(api[_-]?key|password|secret|token)\b\s*[:=]\s*"
               r"[\"'][A-Za-z0-9_\-]{12,}[\"']"),
    re.compile(r"\bBearer\s+[A-Za-z0-9_\-.]{24,}"),
]

READ_METHODS = {"get", "head", "options"}
HTTP_METHODS = {"get", "put", "post", "delete", "options", "head",
                "patch", "trace"}


class OnrampError(Exception):
    pass


def load_openapi(path: str) -> tuple[dict[str, Any], str]:
    with open(path) as f:
        raw = f.read()
    try:
        if path.endswith((".yaml", ".yml")):
            spec = yaml.safe_load(raw)
        else:
            spec = json.loads(raw)
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise OnrampError(f"could not parse {path}: {exc}")
    if not isinstance(spec, dict) or ("openapi" not in spec
                                      and "swagger" not in spec):
        raise OnrampError(f"{path} is not an OpenAPI document")
    return spec, raw


def analyze(spec: dict[str, Any]) -> dict[str, Any]:
    info = spec.get("info", {})
    servers = [s.get("url", "") for s in spec.get("servers", [])]
    schemes = {name: s.get("type", "unknown")
               for name, s in (spec.get("components", {})
                               .get("securitySchemes", {})).items()}
    operations = []
    for path, item in sorted(spec.get("paths", {}).items()):
        if not isinstance(item, dict):
            continue
        for method, op in sorted(item.items()):
            if method not in HTTP_METHODS or not isinstance(op, dict):
                continue
            operations.append({
                "operation_id": op.get("operationId",
                                       f"{method}_{path}"),
                "method": method.upper(),
                "path": path,
                "summary": op.get("summary", ""),
                "effect": ("read" if method in READ_METHODS else "write"),
            })
    unknowns = []
    if not servers:
        unknowns.append("no servers declared; the live endpoint is"
                        " unknown")
    if not schemes:
        unknowns.append("no security schemes declared; how requests"
                        " authenticate is unknown")
    for op in operations:
        if op["effect"] == "write":
            unknowns.append(
                f"{op['method']} {op['path']} is declared a write; its"
                " real side effects, costs, and permission rules are"
                " untested claims")
    return {
        "title": info.get("title", "unnamed service"),
        "version": str(info.get("version", "0")),
        "servers": servers,
        "auth_schemes": schemes,
        "operations": operations,
        "unknowns": unknowns,
    }


def _record(seq: int, subject: str, test: str, result: str,
            evidence: list[str]) -> EvidenceRecord:
    return EvidenceRecord(record_id=f"onr-{seq}", observer=OBSERVER,
                          subject=subject, capability="structural",
                          test=test, result=result, at=time.time(),
                          evidence=evidence)


def structural_checks(raw: str, analysis: dict[str, Any],
                      subject: str) -> list[EvidenceRecord]:
    checks: list[EvidenceRecord] = []
    seq = 0

    def add(test, result, evidence):
        nonlocal seq
        seq += 1
        checks.append(_record(seq, subject, test, result, evidence))

    add("spec-parsed", "passed",
        [f"title: {analysis['title']} v{analysis['version']}"])

    ops = analysis["operations"]
    add("operations-found", "passed" if ops else "failed",
        [f"{len(ops)} operations,"
         f" {sum(1 for o in ops if o['effect'] == 'write')} declared"
         " writes"])

    servers = analysis["servers"]
    if not servers:
        add("https-servers", "not_enough_evidence",
            ["no servers declared"])
    elif all(s.startswith("https://") for s in servers):
        add("https-servers", "passed", servers)
    else:
        add("https-servers", "failed",
            [s for s in servers if not s.startswith("https://")])

    schemes = analysis["auth_schemes"]
    add("auth-declared",
        "passed" if schemes else "not_enough_evidence",
        [f"{name}: {kind}" for name, kind in schemes.items()]
        or ["no security schemes declared"])

    hits = []
    for pattern in SECRET_PATTERNS:
        for match in pattern.finditer(raw):
            hits.append(f"possible embedded secret near offset"
                        f" {match.start()} (pattern {pattern.pattern[:24]})")
    add("secret-scan", "failed" if hits else "passed",
        hits or ["no embedded secrets matched"])
    return checks


def slugify(text: str) -> str:
    slug = re.sub(r"[^a-z0-9.-]+", "-", text.lower()).strip("-.")
    slug = re.sub(r"-{2,}", "-", slug) or "service"
    if not slug[0].isalpha():
        slug = "svc-" + slug
    return slug


def generate_skillmd(name: str, analysis: dict[str, Any]) -> str:
    lines = [
        "---",
        f"name: {name}",
        "version: 1",
        f"capability: service.{name}",
        "role: service",
        "protocol: hosted-api.v1",
        f"summary: Community-generated candidate for"
        f" {analysis['title']}; unclaimed, not provider-endorsed.",
        "status: candidate",
        "---",
        f"# {analysis['title']} (candidate integration)",
        "",
        "This SkillMD was generated from the provider's OpenAPI document."
        " It is a claim, not a fact: nothing here has been executed or"
        " verified against the live service. Town tests and provider"
        " authorization are separate evidence.",
        "",
        "## Operations",
        "",
    ]
    for op in analysis["operations"]:
        summary = f": {op['summary']}" if op["summary"] else ""
        lines.append(f"- {op['method']} {op['path']}"
                     f" ({op['operation_id']}){summary}"
                     f" [declared effect: {op['effect']}]")
    lines += ["", "## Authentication", ""]
    if analysis["auth_schemes"]:
        for scheme, kind in analysis["auth_schemes"].items():
            lines.append(f"- {scheme}: {kind}. Credentials come from a"
                         " secret manager at runtime, never from this"
                         " file or the repository.")
    else:
        lines.append("- Unknown. A reviewer must resolve how requests"
                     " authenticate before any live test.")
    lines += ["", "## Servers", ""]
    for server in analysis["servers"] or ["(none declared)"]:
        lines.append(f"- {server}")
    lines += ["", "## Open questions for review", ""]
    for unknown in analysis["unknowns"] or ["none recorded"]:
        lines.append(f"- {unknown}")
    return "\n".join(lines) + "\n"


def onramp(spec_path: str, name: str | None = None,
           out_dir: str = "services") -> str:
    spec, raw = load_openapi(spec_path)
    analysis = analyze(spec)
    name = slugify(name or analysis["title"])
    snapshot_fp = fingerprint(raw)
    subject = f"{name}@{snapshot_fp}"
    release = ReleaseRef(kind="service", name=name,
                         version=analysis["version"],
                         content_fingerprint=snapshot_fp)

    candidate_dir = os.path.join(out_dir, name)
    ext = "yaml" if spec_path.endswith((".yaml", ".yml")) else "json"
    if os.path.lexists(candidate_dir):
        try:
            if os.path.islink(candidate_dir) or not os.path.isdir(candidate_dir):
                raise ValueError("not a candidate directory")
            release_path = os.path.join(candidate_dir, "release.json")
            snapshot_path = os.path.join(candidate_dir, f"snapshot.{ext}")
            if os.path.islink(release_path) or os.path.islink(snapshot_path):
                raise ValueError("candidate contains a symbolic link")
            with open(release_path) as f:
                previous = ReleaseRef.model_validate_json(f.read())
            if previous.content_fingerprint != snapshot_fp:
                raise OnrampError(
                    f"{name!r} already has a different pinned snapshot;"
                    " choose a new --name or --out directory")
            if previous != release:
                raise ValueError("release does not match the requested candidate")
            with open(snapshot_path) as f:
                if f.read() != raw:
                    raise ValueError("snapshot differs from its release")
        except (OSError, ValueError) as exc:
            raise OnrampError(
                f"{candidate_dir} already exists and cannot be reused: {exc};"
                " choose a new --name or --out directory") from exc
        return candidate_dir

    skill_text = generate_skillmd(name, analysis)
    from .skills import validate_skill
    problems = validate_skill(skill_text)
    if problems:
        raise OnrampError(f"generated SKILL.md failed validation:"
                          f" {problems}")
    try:
        os.makedirs(candidate_dir, exist_ok=False)
    except FileExistsError as exc:
        raise OnrampError(f"{candidate_dir} already exists; retry with a"
                          " new --name or --out directory") from exc
    with open(os.path.join(candidate_dir, f"snapshot.{ext}"), "w") as f:
        f.write(raw)
    with open(os.path.join(candidate_dir, "SKILL.md"), "w") as f:
        f.write(skill_text)

    with open(os.path.join(candidate_dir, "release.json"), "w") as f:
        f.write(release.model_dump_json(indent=2))

    checks = structural_checks(raw, analysis, subject)
    with open(os.path.join(candidate_dir, "checks.jsonl"), "w") as f:
        for check in checks:
            f.write(check.model_dump_json() + "\n")
    with open(os.path.join(candidate_dir, "analysis.json"), "w") as f:
        json.dump(analysis, f, indent=2)

    counts = {"passed": 0, "failed": 0, "unknown": 0}
    for check in checks:
        key = ("unknown" if check.result == "not_enough_evidence"
               else check.result)
        counts[key] += 1
    catalog_path = os.path.join(out_dir, "catalog.json")
    catalog = []
    if os.path.exists(catalog_path):
        with open(catalog_path) as f:
            catalog = json.load(f)
    catalog = [e for e in catalog if e["name"] != name]
    catalog.append({
        "name": name,
        "title": analysis["title"],
        "fingerprint": snapshot_fp,
        "status": "candidate-unclaimed",
        "operations": len(analysis["operations"]),
        "checks": counts,
        "added_at": time.time(),
    })
    with open(catalog_path, "w") as f:
        json.dump(sorted(catalog, key=lambda e: e["name"]), f, indent=2)
    return candidate_dir


def catalog_entries(out_dir: str = "services") -> list[dict[str, Any]]:
    catalog_path = os.path.join(out_dir, "catalog.json")
    if not os.path.exists(catalog_path):
        return []
    with open(catalog_path) as f:
        return json.load(f)
