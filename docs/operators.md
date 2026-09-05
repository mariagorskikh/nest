# Operating a shared coordinator

Town's coordinator is a local HTTP service over SQLite. Operating it for trusted
participants on a shared network requires deliberate networking, credential and
resource controls; the default local runner does not provide a public service.

## Start locally

Install Town in a virtual environment first. Use an existing directory writable
by the service account for the database. For a terminal session:

```bash
mkdir -p town-state
export TOWN_ADMIN_TOKEN="$(openssl rand -hex 32)"
nandatown coordinator --host 127.0.0.1 --port 8477 --db town-state/town.db
```

Keep the admin token private: it authorizes run creation, fault plans, event and
intent export, and finish. Participants use per-run join credentials and receive
a session; they do not need the admin token. Store a stable admin token securely
for a managed service rather than generating a different value on every restart.

## Reach an agent on another machine

Loopback addresses refer to the machine running the command. A remote
Town-joining agent needs a tunnel to the coordinator or a reachable service
address. If Town runs on one laptop and the agent on another, arrange that route
before giving the agent `TOWN_URL`; copying `127.0.0.1` between machines is not
enough. An SSH tunnel can preserve local-only binding. If serving multiple
machines directly, put a TLS reverse proxy and access controls in front of Town.

For an agent already exposing A2A, use `nandatown test-agent --url URL` from a
machine that can reach it. This does not require exposing the Town coordinator.
See [testing an existing agent](testing-an-existing-agent.md).

## State and shutdown

The database stores accepted messages, claims, acknowledgments, sessions, intents
and events. It is not the entire system: participant journals, private keys,
exported bundles, service environment and in-memory fault controls are separate.
Use SQLite's online backup API or `.backup` command for a live database; copying
only the main file while WAL writes are active can miss committed work.

Back up journals and keys under their own access policy. A controller key must
remain outside participant environments. A run's permission checks and identity
pins survive coordinator restart; a fault schedule may not. Test the restoration
you intend to rely on instead of equating a database copy with full-run recovery.

A finished run rejects further mutations. Events, intents and existing evidence
remain readable. The local runner settles its children before final export.
Offline bundle verification and live-run reproduction are separate checks.

## Service templates

The files in `deploy/` are templates, not unattended install scripts:

- `nandatown-coordinator.service` assumes a `nandatown` user, Town installed at
  `/opt/nandatown/.venv`, a writable `/var/lib/nandatown`, and a protected
  `/etc/nandatown/coordinator.env` defining `TOWN_ADMIN_TOKEN`. Create and check
  those prerequisites before installing the unit into systemd.
- `com.nandatown.coordinator.plist` must use the installed CLI's absolute path,
  an existing writable database directory and a real token in place of
  `set-a-real-token-here`. Protect the file because it contains that credential.
  The supplied `/usr/local` paths will not suit every macOS install.

Both templates bind to loopback. Review them before enabling the service.

## Availability and resource limits

Pulse runs a finite number of probes; `--count` must be at least one:

```bash
nandatown pulse --target coordinator=http://127.0.0.1:8477/health --count 10 --interval 60 --db pulse.db
nandatown pulse --report --db pulse.db
```

Schedule finite invocations with your service scheduler for ongoing monitoring.
Pulse tests availability, not semantic correctness.

FastAPI parsing is not a request-body size limit. A shared deployment must supply
body and rate limits, connection/request deadlines, disk retention limits and an
admission policy appropriate to its users. Leases protect delivery progress;
they do not cap run count, request volume or storage. Plain HTTP is suitable for
loopback or a protected tunnel, not for sending credentials across an untrusted
network. Model-backed runs need explicit budget controls.

## Browser kiosk

`nandatown ui --web --kiosk` serves the browser TUI with visitor-supplied commands
and arbitrary server-path reads disabled. Model-backed kiosk choices use
`mock:v1` by default, even if the host has model credentials configured. Setting
`NANDATOWN_KIOSK_ALLOW_HOSTED_MODEL=1` explicitly enables the configured hosted
model and can incur provider charges; add access and budget controls first.

Kiosk mode is a restricted UI, not a hostile-code sandbox or a complete public
hosting policy. Run it behind the same network, request and resource controls
appropriate for any shared service. Keep operator secrets and private bundles
off the visitor-facing host where possible.

## What an operator signs

The operator attests to the exact bundle/result bytes under its key. Verification
checks integrity, claim agreement and replayable evaluation. It does not certify
the agent, establish operator independence, authorize side effects or endorse a
provider. Inspect bundles and receipts for sensitive data before publication.
