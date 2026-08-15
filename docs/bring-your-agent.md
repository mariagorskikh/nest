# Test an existing OpenClaw agent

Nanda Town runs one small, repeatable capability test against an existing
OpenClaw agent on the computer where Town is running. It asks the agent to declare `sell`, routes `buy:widget:2`
through Town's pinned run-local Registry and simulator, and checks for the exact
`sold:widget:2` response. This tests one bounded Town integration path; it is
not a general evaluation of the agent.

## Requirements

- The Town and OpenClaw commands must run on the same computer.
- Run Town and OpenClaw on macOS or Linux. Native Windows is not supported in
  this preview.
- Town tries the installed OpenClaw version and checks the commands and JSON
  responses needed for this test. `2026.7.1-2` is the release tested against a
  real OpenClaw installation.
- `openclaw config get gateway.mode --json` must return exactly `"local"`, and
  OpenClaw must not configure an `OPENCLAW_GATEWAY_URL` override.
- The OpenClaw Gateway must be healthy.
- The agent ID must already exist in OpenClaw, and you must trust its
  configuration and code.
- Python 3.12 or newer and
  [uv](https://docs.astral.sh/uv/getting-started/installation/) must be installed.

If OpenClaw runs on another computer, SSH into that computer and run Town there:

```bash
ssh <user>@<openclaw-host>
```

Town does not connect directly to a remote OpenClaw Gateway in this preview.
After signing in, follow the same setup and test commands below on that computer.

## Set up Town

This preview runs from a Town checkout. Clone it, install the locked workspace,
and stay in the `nandatown` repository directory for every Town command below:

```bash
git clone https://github.com/projnanda/nandatown.git
cd nandatown
uv sync --frozen
```

Do not use an older or unpinned package install to evaluate this checkout.

## Choose the OpenClaw agent

List the configured agents without changing them:

```bash
openclaw agents list
```

Choose the exact agent ID shown by OpenClaw. Town does not create, install, or
reconfigure an agent.

From the `nandatown` directory, run:

```bash
uv run nest test agent <agent-id>
```

For example only, if the listed agent ID is `everett`:

```bash
uv run nest test agent everett
```

Town auto-detects the local runtime when exactly one runtime contains that
exact target. If the message offers an explicit command, copy it exactly; for
this release that form is `uv run nest test agent <agent-id> --runtime openclaw`.

## Read the five stages

The result keeps earlier failures visible instead of collapsing everything into
one score:

1. **Agent responded** — the local driver exchange returned allowed answers.
2. **Capability registered** — Town registered the declared `sell` capability
   in its pinned run-local Registry.
3. **Agent discovered** — Town's reference requester found that run-local card.
4. **Request delivered** — Town routed the exact synthetic request through its
   simulator.
5. **Response verified** — the requester received exactly `sold:widget:2`.

`Not evaluated` means the run did not produce enough evidence for that stage.
It does not mean pass.

## Cost and safety boundary

A completed run asks the selected OpenClaw agent for two model turns: one
capability declaration and one response to the synthetic request. Each Town run
uses a fresh OpenClaw session, but OpenClaw may retain that session and its
normal transcript; Town does not delete them. The cost is whatever those two
turns cost under that agent's configured provider and model.

Town does not pass OpenClaw's delivery or local-execution flags, but **this is
not a sandbox**. OpenClaw and the selected agent still run with your user
privileges and their configured tools, hooks, and plugins. Disable anything you
do not want available before testing. With the supported envelope, an absence
of reported tool or delivery activity leaves that activity **unknown**; Town
does not claim that nothing ran. If OpenClaw explicitly reports fallback,
delivery, or tool activity, Town stops with an incomplete result instead of
scoring it as agent behavior.

## Fix common problems

- **Native Windows:** run Town and OpenClaw together on macOS or Linux. Town
  rejects this preview connector before starting an agent/model turn on native
  Windows.
- **Version or command incompatibility:** check `openclaw --version` and update
  OpenClaw if needed. Town tries the installed version, but stops clearly
  before an agent/model turn when a required command or JSON response is
  incompatible.
- **Gateway unavailable or unhealthy:** run `openclaw gateway status`, restore
  the Gateway on the computer where you are running Town, then retry.
- **Remote dispatch rejected:** run
  `openclaw config get gateway.mode --json` on the OpenClaw computer. It must
  return exactly `"local"`; remove any configured `OPENCLAW_GATEWAY_URL`
  override, then retry. Town stops before an agent/model turn in this case.
- **Target not found:** rerun `openclaw agents list` and copy the exact ID,
  including case and punctuation.
- **Several runtimes match:** use the explicit command Town prints. Do not pick
  a runtime by trial and error.
- **Model mismatch:** use the agent's configured model, or supply a deliberate
  `--model provider/model` override.
- **Fallback, activity, or timeout:** inspect the OpenClaw configuration and
  agent behavior. Town reports the run as incomplete; it does not silently
  retry the model turn.
- **Output directory rejected:** remove the explicit `--output-dir`, or choose a
  new or empty non-symlink directory.

## What PASS means

PASS means Town observed valid answers for this frozen synthetic workflow and
all five stages completed through Town's pinned local components. It does not
prove that arbitrary agents work, that the agent's own discovery or Registry
protocol works, that a model produced the response, or that the agent is safe,
trusted, reliable, production-ready, or compatible across NANDA.

For custom adapters, automation, wire details, evidence files, and maintainer
checks, see the [technical agent-test adapter reference](agent-test-adapter-reference.md).
