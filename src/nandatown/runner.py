"""Full-run orchestration: one command, one run, one evidence bundle.

The runner starts a coordinator subprocess, spawns the buyer and seller
as isolated subprocesses with their own state directories, restarts the
seller once if it crashes, finishes the run, evaluates the event log,
and writes the portable bundle. Runner observations (crash, restart,
exit) are posted as attributed events; the runner never synthesizes
participant assertions.
"""

from __future__ import annotations

import os
import secrets
import shutil
import socket
import subprocess
import sys
import time
from typing import Any

import httpx

from . import __version__
from .bundle import write_bundle
from .evaluator import EVALUATOR_VERSION, evaluate
from .records import RunRecord, TestProfile, TownEvent, fingerprint
from .profiles import PROFILES

SELLER_CRASH_EXIT = 3


class RunnerError(Exception):
    pass


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_health(http: httpx.Client, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if http.get("/health").status_code == 200:
                return
        except httpx.TransportError:
            pass
        time.sleep(0.1)
    raise RunnerError("coordinator did not become healthy")


def _spawn_participant(command: list[str], url: str, run_id: str, name: str,
                       token: str, state_dir: str, fault: str,
                       deadline: str,
                       extra_env: dict[str, str] | None = None
                       ) -> subprocess.Popen:
    os.makedirs(state_dir, exist_ok=True)
    env = dict(os.environ)
    env.update({"TOWN_URL": url, "RUN_ID": run_id, "NAME": name,
                "TOKEN": token, "STATE_DIR": state_dir, "FAULT": fault,
                "DEADLINE": deadline})
    env.update(extra_env or {})
    return subprocess.Popen(command, env=env,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)


def parse_harness(spec: str) -> dict[str, Any]:
    """A harness connector spec, the way an agent plugs into a run.

    scripted        the stock reference agent for the role
    llm             the model tool loop with the run's default model
    llm:MODEL       the model tool loop with this model
    cmd:COMMAND     your own agent process, any runtime, any language
    external        spawn nothing; hand out join credentials instead
    """
    import shlex

    if spec == "scripted":
        return {"kind": "scripted"}
    if spec == "llm":
        return {"kind": "llm", "model": None}
    if spec.startswith("llm:"):
        return {"kind": "llm", "model": spec[4:]}
    if spec.startswith("cmd:"):
        command = shlex.split(spec[4:])
        if not command:
            raise RunnerError("cmd: harness needs a command")
        return {"kind": "cmd", "command": command}
    if spec == "external":
        return {"kind": "external"}
    if spec.startswith("a2a:"):
        url = spec[4:]
        if not url:
            raise RunnerError("a2a: harness needs a URL")
        return {"kind": "a2a", "url": url}
    raise RunnerError(
        f"unknown harness {spec!r}; use scripted, llm, llm:MODEL,"
        " cmd:COMMAND, a2a:URL, or external")


def _participant_command(profile: TestProfile, role: str,
                         external: dict[str, list[str] | None] | None,
                         harnesses: dict[str, str] | None = None
                         ) -> tuple[list[str] | None, dict[str, str]]:
    """The command and extra env for one role, or (None, {}) when an
    outside agent will join with handed-out credentials."""
    if harnesses and role in harnesses:
        harness = parse_harness(harnesses[role])
    elif external and role in external:
        command = external[role]
        harness = ({"kind": "external"} if command is None
                   else {"kind": "cmd", "command": list(command)})
    else:
        runtime = profile.runtimes.get(role, "scripted")
        harness = {"kind": runtime if runtime == "llm" else "scripted",
                   "model": None}
    kind = harness["kind"]
    if kind == "external":
        return None, {}
    if kind == "cmd":
        return harness["command"], {}
    if kind == "llm":
        env = {"ROLE": role}
        if harness.get("model"):
            env["TOWN_MODEL"] = harness["model"]
        return [sys.executable, "-m", "nandatown.participants.llm"], env
    if kind == "a2a":
        return ([sys.executable, "-m",
                 "nandatown.participants.a2a_bridge"],
                {"A2A_URL": harness["url"]})
    return [sys.executable, "-m", f"nandatown.participants.{role}"], {}


def _grant_refused(events: list[dict[str, Any]]) -> str | None:
    """The first role that tried to join a pinned identity with a bare
    token, or None. Such a harness can never join, so waiting on is
    pointless."""
    for e in events:
        if e["kind"] == "grant_required":
            return e["subject"]
    return None


def _quiescent(profile: TestProfile, events: list[dict[str, Any]]) -> bool:
    """Has the seller side finished everything this profile expects?"""
    seller_acks = [e for e in events
                   if e["kind"] == "ack_recorded"
                   and e["observer"] == "seller"
                   and e["detail"].get("status") == "processed"]
    applied = [e for e in seller_acks if e["detail"]["note"].get("applied")]
    if profile.fault == "duplicate_delivery":
        duplicates = [e for e in seller_acks
                      if e["detail"]["note"].get("duplicate")]
        return bool(applied) and bool(duplicates)
    return bool(applied)


def run_town(profile_name: str, out_dir: str, port: int = 0,
             model: str | None = None,
             external: dict[str, list[str] | None] | None = None,
             harnesses: dict[str, str] | None = None,
             wait_timeout: float = 45.0,
             identity_dir: str | None = None,
             on_credentials=None) -> tuple[str, Any]:
    """Run one Track profile.

    harnesses maps a role to a connector spec (see parse_harness) and
    overrides the profile's runtimes. external is the lower-level form:
    a role mapped to a replacement command, or to None to spawn nothing
    and hand join credentials to on_credentials(role, env) so an
    outside agent can join.
    """
    if profile_name not in PROFILES:
        raise RunnerError(f"unknown profile {profile_name!r};"
                          f" choose from {sorted(PROFILES)}")
    profile = PROFILES[profile_name]
    model = model or os.environ.get("TOWN_MODEL", "mock:v1")
    admin_token = secrets.token_hex(16)
    port = port or _free_port()
    url = f"http://127.0.0.1:{port}"

    os.makedirs(out_dir, exist_ok=True)
    scratch = os.path.join(out_dir, f".scratch-{secrets.token_hex(4)}")
    os.makedirs(scratch, exist_ok=True)
    db_path = os.path.join(scratch, "town.db")

    env = dict(os.environ)
    env["TOWN_ADMIN_TOKEN"] = admin_token
    coordinator = subprocess.Popen(
        [sys.executable, "-m", "nandatown.coordinator", "--db", db_path,
         "--port", str(port)],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    procs: list[subprocess.Popen] = [coordinator]
    admin = httpx.Client(base_url=url, timeout=10.0,
                         headers={"X-Town-Admin": admin_token})
    bundle_dir: str | None = None
    try:
        _wait_health(admin)
        keystore = None
        create_body: dict[str, Any] = {"profile": profile.model_dump()}
        if identity_dir:
            from .identity_portable import Keystore

            keystore = Keystore(identity_dir)
            create_body["identities"] = {
                role: {k: v for k, v in
                       keystore.new_identity(role).items()
                       if k in ("agent_id", "controller_public")}
                for role in profile.roles}
        created = admin.post("/runs", json=create_body)
        created.raise_for_status()
        run_id = created.json()["run_id"]
        tokens = created.json()["join_tokens"]
        if keystore is not None:
            import json as _json

            grants = {role: _json.dumps(keystore.make_grant(role, run_id))
                      for role in profile.roles}
        else:
            grants = {}

        def post_event(observer: str, kind: str, subject: str,
                       detail: dict | None = None) -> None:
            admin.post(f"/runs/{run_id}/events",
                       json={"observer": observer, "kind": kind,
                             "subject": subject, "detail": detail or {}})

        def get_events() -> list[dict[str, Any]]:
            return admin.get(f"/runs/{run_id}/events").json()["events"]

        seller_state = os.path.join(scratch, "seller")
        buyer_state = os.path.join(scratch, "buyer")
        seller_cmd, seller_env = _participant_command(profile, "seller",
                                                      external, harnesses)
        buyer_cmd, buyer_env = _participant_command(profile, "buyer",
                                                    external, harnesses)
        model_env = {"TOWN_MODEL": model}
        for key in ("TOWN_MODEL_URL", "TOWN_MODEL_KEY"):
            if key in os.environ:
                model_env[key] = os.environ[key]
        # A per-role harness model outranks the run-level model.
        seller_env = {**model_env, **seller_env}
        buyer_env = {**model_env, **buyer_env}
        if "seller" in grants:
            seller_env["TOWN_GRANT"] = grants["seller"]
        if "buyer" in grants:
            buyer_env["TOWN_GRANT"] = grants["buyer"]

        seller_deadline = str(wait_timeout - 5)
        buyer_deadline = str(wait_timeout - 15)

        def hand_off(role: str, state_dir: str) -> None:
            """Credentials for an agent that joins from outside: the same
            environment a spawned participant gets. A role pinned to a
            portable identity also receives its Run Grant, which is the
            only credential the town will accept from it."""
            if on_credentials is None:
                return
            os.makedirs(state_dir, exist_ok=True)
            env = {"TOWN_URL": url, "RUN_ID": run_id, "NAME": role,
                   "TOKEN": tokens[role], "STATE_DIR": state_dir}
            if role in grants:
                env["TOWN_GRANT"] = grants[role]
            on_credentials(role, env)

        def spawn_seller() -> subprocess.Popen | None:
            if seller_cmd is None:
                hand_off("seller", seller_state)
                return None
            p = _spawn_participant(seller_cmd, url, run_id, "seller",
                                   tokens["seller"], seller_state,
                                   profile.fault, seller_deadline,
                                   extra_env=seller_env)
            procs.append(p)
            return p

        seller = spawn_seller()
        if buyer_cmd is None:
            hand_off("buyer", buyer_state)
            buyer = None
        else:
            buyer = _spawn_participant(buyer_cmd, url, run_id, "buyer",
                                       tokens["buyer"], buyer_state,
                                       profile.fault, buyer_deadline,
                                       extra_env=buyer_env)
            procs.append(buyer)

        restarted = False
        refused_role: str | None = None
        deadline = time.time() + wait_timeout
        while time.time() < deadline:
            if buyer is not None and buyer.poll() is not None:
                break
            if buyer is None and _quiescent(profile, get_events()):
                break
            if grants:
                refused_role = _grant_refused(get_events())
                if refused_role:
                    post_event("runner", "harness_refused_grant",
                               refused_role,
                               {"reason": "joined with a bare token while"
                                          " pinned to a portable identity;"
                                          " this harness must present"
                                          " TOWN_GRANT"})
                    break
            if seller is not None:
                rc = seller.poll()
                if rc is not None:
                    if rc == SELLER_CRASH_EXIT and not restarted:
                        post_event("runner", "participant_crashed",
                                   "seller", {"exit_code": rc})
                        seller = spawn_seller()
                        post_event("runner", "participant_restarted",
                                   "seller")
                        restarted = True
                    else:
                        post_event("runner", "participant_exited",
                                   "seller", {"exit_code": rc})
                        break
            time.sleep(0.1)
        if buyer is not None:
            if buyer.poll() is None:
                buyer.terminate()
            post_event("runner", "participant_exited", "buyer",
                       {"exit_code": buyer.poll()})

        quiet_deadline = time.time() + (0.0 if refused_role else 8.0)
        while time.time() < quiet_deadline:
            if _quiescent(profile, get_events()):
                break
            time.sleep(0.2)

        if seller is not None and seller.poll() is None:
            seller.terminate()
        admin.post(f"/runs/{run_id}/finish")

        raw_events = get_events()
        events = [TownEvent.model_validate(e) for e in raw_events]
        intents = admin.get(f"/runs/{run_id}/intents").json()["intents"]
        directory = [
            {"name": p["name"], "role": p["role"],
             "capabilities": p["capabilities"],
             "release": f"nandatown.participants.{p['role']} {__version__}"}
            for p in [
                {"name": "buyer", "role": "buyer", "capabilities": []},
                {"name": "seller", "role": "seller",
                 "capabilities": ["quote.read"]},
            ]
        ]
        created_at = next((e.at for e in events if e.kind == "run_created"),
                          time.time())
        from .skills import skill_source
        skill_releases = [
            {"kind": "skill", "name": name, "version": "1",
             "content_fingerprint": fingerprint(skill_source(name))}
            for name in ("town-protocol", "quote.read", "quote.request")
        ]
        uses_llm = ("llm" in profile.runtimes.values()
                    or any(spec.startswith("llm")
                           for spec in (harnesses or {}).values()))
        config: dict[str, Any] = {"port": port,
                                  "restarted_seller": restarted,
                                  "runtimes": profile.runtimes or
                                  {"buyer": "scripted",
                                   "seller": "scripted"},
                                  "skill_releases": skill_releases}
        if harnesses:
            config["harnesses"] = harnesses
        rerun = f"nandatown run {profile.name}"
        for role, spec_text in (harnesses or {}).items():
            rerun += f" --agent {role}={spec_text}"
        if identity_dir:
            rerun += " --identity"
        if uses_llm and model != "mock:v1":
            rerun += f" --model {model}"
        config["rerun_command"] = rerun
        if uses_llm:
            config["model"] = model
            if not model.startswith("mock:"):
                config["model_note"] = ("hosted model recorded as an"
                                        " observed mutable dependency;"
                                        " it can change under a pinned"
                                        " release")
        run_record = RunRecord(
            run_id=run_id,
            profile_name=profile.name,
            profile_fingerprint=fingerprint(profile.model_dump()),
            created_at=created_at,
            participants=directory,
            releases={
                "nandatown": __version__,
                "evaluator": EVALUATOR_VERSION,
                "python": sys.version.split()[0],
            },
            config=config,
        )
        result = evaluate(profile, run_id, events)
        bundle_dir = os.path.join(out_dir, run_id)
        write_bundle(bundle_dir, profile, run_record, intents, events, result)
        from .bundle import attest_bundle
        attest_bundle(bundle_dir)
        return bundle_dir, result
    finally:
        for p in procs:
            if p.poll() is None:
                p.terminate()
        for p in procs:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
        admin.close()
        # Keep the operational state (town.db, journals) inspectable
        # inside the bundle once the processes that owned it are gone.
        if bundle_dir and os.path.isdir(bundle_dir):
            shutil.move(scratch, os.path.join(bundle_dir, "state"))
