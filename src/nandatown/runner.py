"""Full-run orchestration: one command, one run, one evidence bundle.

The runner starts a coordinator subprocess, spawns the buyer and seller
as separate subprocesses with their own state directories, restarts the
seller once if it crashes, finishes the run, evaluates the event log, and
writes the portable bundle. Bundled harnesses receive a narrow environment;
an operator-supplied ``cmd:`` harness is trusted code and retains the
operator's ambient environment. This is process lifecycle containment, not a
filesystem or network sandbox. Runner observations (crash, restart, exit) are
posted as attributed events; the runner never synthesizes participant
assertions.
"""

from __future__ import annotations

import os
import secrets
import signal
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

_BUILTIN_ENV_KEYS = (
    "PATH", "PYTHONPATH", "PYTHONHOME",
    "LANG", "LC_ALL", "LC_CTYPE",
    "TMPDIR", "TMP", "TEMP",
    "SYSTEMROOT", "WINDIR",
    "SSL_CERT_FILE", "SSL_CERT_DIR",
)


class RunnerError(Exception):
    pass


class RunnerUsageError(RunnerError):
    """Invalid caller input that a command-line caller can report as usage."""


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
                       extra_env: dict[str, str] | None = None,
                       inherit_env: bool = False,
                       ) -> subprocess.Popen:
    os.makedirs(state_dir, exist_ok=True)
    env = (dict(os.environ) if inherit_env else
           {key: os.environ[key] for key in _BUILTIN_ENV_KEYS
            if key in os.environ})
    env.update({"TOWN_URL": url, "RUN_ID": run_id, "NAME": name,
                "TOKEN": token, "STATE_DIR": state_dir, "FAULT": fault,
                "DEADLINE": deadline})
    env.update(extra_env or {})
    return subprocess.Popen(command, env=env,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            start_new_session=(os.name == "posix"))


def _stop_process(process: subprocess.Popen, grace: float = 0.5) -> int | None:
    """Settle a child and, on POSIX, every descendant in its process group.

    Other platforms use a direct-child fallback; Python has no portable
    descendant-process primitive.
    """
    if getattr(process, "_town_cleanup_complete", False):
        return process.returncode
    # Reap an already-exited group leader first. Darwin reports EPERM when
    # killpg targets a group containing only an unreaped (defunct) leader.
    process.poll()
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            # Do not address this numeric PGID again: after ESRCH it could
            # belong to an unrelated group before a defensive finally pass.
            process._town_cleanup_complete = True
            return process.wait(timeout=grace)
    elif process.poll() is None:
        process.terminate()
    try:
        process.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        pass
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    elif process.poll() is None:
        process.kill()
    try:
        result = process.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        result = process.poll()
    # SIGKILL has been issued to any remaining POSIX descendants. A zombie
    # descendant may await its own parent's reap, but needs no second signal.
    if result is not None:
        process._town_cleanup_complete = True
    return result


def _participant_extra_env(kind: str, explicit: dict[str, str],
                           model: str) -> dict[str, str]:
    """Select model configuration for one harness without broad inheritance."""
    env: dict[str, str] = {}
    if kind in ("llm", "cmd"):
        effective_model = explicit.get("TOWN_MODEL", model)
        env["TOWN_MODEL"] = effective_model
        # A mock harness has no reason to receive paid credentials. Trusted
        # commands inherit ambient variables in _spawn_participant regardless.
        if kind == "cmd" or not effective_model.startswith("mock:"):
            for key in ("TOWN_MODEL_URL", "TOWN_MODEL_KEY"):
                if key in os.environ:
                    env[key] = os.environ[key]
        if kind == "llm" and not effective_model.startswith("mock:"):
            for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
                        "http_proxy", "https_proxy", "all_proxy", "no_proxy"):
                if key in os.environ:
                    env[key] = os.environ[key]
    env.update(explicit)
    return env


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
                         ) -> tuple[list[str] | None, dict[str, str], str]:
    """Return the command, explicit environment, and harness kind."""
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
        return None, {}, kind
    if kind == "cmd":
        return harness["command"], {}, kind
    if kind == "llm":
        env = {"ROLE": role}
        if harness.get("model"):
            env["TOWN_MODEL"] = harness["model"]
        return ([sys.executable, "-m", "nandatown.participants.llm"],
                env, kind)
    if kind == "a2a":
        return ([sys.executable, "-m",
                 "nandatown.participants.a2a_bridge"],
                {"A2A_URL": harness["url"]}, kind)
    return ([sys.executable, "-m", f"nandatown.participants.{role}"],
            {}, kind)


def _participant_provenance(role: str, kind: str
                            ) -> tuple[str, dict[str, Any]]:
    """Describe who supplied a harness without inventing its release.

    Town can name the bundled module bytes it launched. An operator command,
    manually connected participant, or remote A2A endpoint does not supply an
    immutable participant release through the current connector contract, so
    the record says that directly. The A2A bridge is still recorded separately
    as the adapter Town did launch.
    """
    if kind in ("scripted", "llm"):
        module = role if kind == "scripted" else "llm"
        release = f"nandatown.participants.{module} {__version__}"
        return release, {
            "kind": kind,
            "identity_basis": "bundled NANDA Town harness",
            "release_basis": release,
        }

    external = {
        "cmd": (
            "external command; immutable release not recorded",
            "operator-supplied command (command not recorded)",
        ),
        "external": (
            "external participant; immutable release not recorded",
            "operator-connected participant (software identity not supplied)",
        ),
        "a2a": (
            "external A2A participant; immutable release not recorded",
            "operator-supplied A2A endpoint (URL not recorded)",
        ),
    }
    release, identity_basis = external[kind]
    provenance: dict[str, Any] = {
        "kind": kind,
        "identity_basis": identity_basis,
        "release_basis": None,
        "release_basis_note": "immutable external release not supplied",
    }
    if kind == "a2a":
        provenance["adapter_release"] = (
            f"nandatown.participants.a2a_bridge {__version__}")
    return release, provenance


def _redacted_harness_spec(kind: str, supplied: str | None = None) -> str:
    """Return connector metadata that is safe to put in run.json."""
    if kind == "cmd":
        return "cmd:<operator-supplied-command>"
    if kind == "a2a":
        return "a2a:<operator-supplied-endpoint>"
    if kind in ("scripted", "llm", "external"):
        return supplied or kind
    raise RunnerError(f"unknown resolved harness kind {kind!r}")


def _recorded_harnesses(
        profile: TestProfile,
        participant_kinds: dict[str, str],
        harnesses: dict[str, str] | None,
        external: dict[str, list[str] | None] | None) -> dict[str, str]:
    """Record effective overrides while omitting commands and endpoints."""
    recorded: dict[str, str] = {}
    for role in profile.roles:
        if harnesses and role in harnesses:
            supplied = harnesses[role]
        elif external and role in external:
            supplied = None
        else:
            continue
        recorded[role] = _redacted_harness_spec(
            participant_kinds[role], supplied)
    return recorded


def _rerun_metadata(
        profile: TestProfile,
        recorded_harnesses: dict[str, str],
        participant_kinds: dict[str, str],
        external: dict[str, list[str] | None] | None,
        harnesses: dict[str, str] | None,
        identity_dir: str | None,
        uses_llm: bool,
        model: str) -> tuple[str, dict[str, str]]:
    """Build a non-secret rerun recipe and list inputs Town omitted."""
    import shlex

    required = {
        role: {
            "cmd": "original command (not recorded)",
            "a2a": "original A2A endpoint (URL not recorded)",
            "external": (
                "external participant must reconnect with fresh credentials"),
        }[kind]
        for role, kind in participant_kinds.items()
        if kind in ("cmd", "a2a", "external")
    }

    # This is the public CLI path used by `test-agent --cmd/--wait`. Preserve
    # it when possible instead of converting the rerun into a stock Track run.
    if external and not harnesses and len(external) == 1 and not identity_dir:
        role, command = next(iter(external.items()))
        parts = ["nandatown", "test-agent", "--profile", profile.name,
                 "--role", role]
        if command is None:
            parts.append("--wait")
        else:
            parts.extend(["--cmd", "<operator-supplied-command>"])
        rerun = " ".join(shlex.quote(part) for part in parts)
        if uses_llm and model != "mock:v1":
            rerun = f"TOWN_MODEL={shlex.quote(model)} {rerun}"
        return rerun, required

    parts = ["nandatown", "run", profile.name]
    for role, spec in recorded_harnesses.items():
        parts.extend(["--agent", f"{role}={spec}"])
    if identity_dir:
        parts.append("--identity")
    if uses_llm and model != "mock:v1":
        parts.extend(["--model", model])
    return " ".join(shlex.quote(part) for part in parts), required


def _validate_role_overrides(
        profile: TestProfile,
        harnesses: dict[str, str] | None,
        external: dict[str, list[str] | None] | None) -> None:
    """Reject override keys that cannot select a profile participant."""
    for overrides in (harnesses, external):
        for role in (overrides or {}):
            if role not in profile.roles:
                supported = ", ".join(sorted(profile.roles))
                raise RunnerUsageError(
                    f"unknown role {role!r}; supported roles: {supported}")


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
    outside agent can join. Command harnesses are trusted operator code and
    inherit the operator environment; bundled harnesses do not.
    """
    if profile_name not in PROFILES:
        raise RunnerError(f"unknown profile {profile_name!r};"
                          f" choose from {sorted(PROFILES)}")
    profile = PROFILES[profile_name]
    _validate_role_overrides(profile, harnesses, external)
    model = model or os.environ.get("TOWN_MODEL", "mock:v1")
    admin_token = secrets.token_hex(16)
    port = port or _free_port()
    url = f"http://127.0.0.1:{port}"

    os.makedirs(out_dir, exist_ok=True)
    scratch = os.path.join(out_dir, f".scratch-{secrets.token_hex(4)}")
    os.makedirs(scratch, exist_ok=True)
    db_path = os.path.join(scratch, "town.db")

    env = {key: os.environ[key] for key in _BUILTIN_ENV_KEYS
           if key in os.environ}
    env["TOWN_ADMIN_TOKEN"] = admin_token
    coordinator = subprocess.Popen(
        [sys.executable, "-m", "nandatown.coordinator", "--db", db_path,
         "--port", str(port)],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=(os.name == "posix"),
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
        seller_cmd, seller_env, seller_kind = _participant_command(
            profile, "seller", external, harnesses)
        buyer_cmd, buyer_env, buyer_kind = _participant_command(
            profile, "buyer", external, harnesses)

        # A per-role harness model outranks the run-level model.
        seller_env = _participant_extra_env(seller_kind, seller_env, model)
        buyer_env = _participant_extra_env(buyer_kind, buyer_env, model)
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
                                   extra_env=seller_env,
                                   inherit_env=(seller_kind == "cmd"))
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
                                       extra_env=buyer_env,
                                       inherit_env=(buyer_kind == "cmd"))
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
                    _stop_process(seller)
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
            buyer_exit = _stop_process(buyer)
            post_event("runner", "participant_exited", "buyer",
                       {"exit_code": buyer_exit})

        quiet_deadline = time.time() + (0.0 if refused_role else 8.0)
        while time.time() < quiet_deadline:
            if _quiescent(profile, get_events()):
                break
            time.sleep(0.2)

        if seller is not None:
            _stop_process(seller)
        finished = admin.post(f"/runs/{run_id}/finish")
        finished.raise_for_status()

        raw_events = get_events()
        events = [TownEvent.model_validate(e) for e in raw_events]
        intents = admin.get(f"/runs/{run_id}/intents").json()["intents"]
        participant_kinds = {"buyer": buyer_kind, "seller": seller_kind}
        participant_provenance: dict[str, dict[str, Any]] = {}
        directory = []
        for name, role in profile.roles.items():
            release, provenance = _participant_provenance(
                role, participant_kinds[name])
            participant_provenance[name] = provenance
            directory.append({
                "name": name,
                "role": role,
                "capabilities": profile.capabilities.get(name, []),
                "runtime": participant_kinds[name],
                "release": release,
            })
        created_at = next((e.at for e in events if e.kind == "run_created"),
                          time.time())
        from .skills import skill_source
        skill_releases = [
            {"kind": "skill", "name": name, "version": "1",
             "content_fingerprint": fingerprint(skill_source(name))}
            for name in ("town-protocol", "quote.read", "quote.request")
        ]
        uses_llm = "llm" in participant_kinds.values()
        recorded_harnesses = _recorded_harnesses(
            profile, participant_kinds, harnesses, external)
        config: dict[str, Any] = {"port": port,
                                  "restarted_seller": restarted,
                                  "runtimes": participant_kinds,
                                  "participant_provenance":
                                  participant_provenance,
                                  "skill_releases": skill_releases}
        if recorded_harnesses:
            config["harnesses"] = recorded_harnesses
        rerun, rerun_required_inputs = _rerun_metadata(
            profile, recorded_harnesses, participant_kinds, external,
            harnesses, identity_dir, uses_llm, model)
        config["rerun_command"] = rerun
        if rerun_required_inputs:
            config["rerun_required_inputs"] = rerun_required_inputs
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
            _stop_process(p)
        admin.close()
        # Keep the operational state (town.db, journals) inspectable
        # inside the bundle once the processes that owned it are gone.
        if bundle_dir and os.path.isdir(bundle_dir):
            shutil.move(scratch, os.path.join(bundle_dir, "state"))
