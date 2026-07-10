# RoboAgent Guard

RoboAgent Guard is a NANDA Town Phase 1 contribution targeting
`docs/hackathon/problems/09-privacy-hybrid-encryption-with-selective-disclosure.md`.
It adds a narrow privacy-layer differentiator for robot sensor traces:
`privacy: noop` leaks raw sensor payloads, while `privacy: sensor_redaction`
filters those payloads before they are shared.

The goal is not to duplicate the already-merged `hybrid_x25519` work. This
contribution is deliberately narrower: deterministic redaction of camera,
person-detection, private-zone, lidar, and mapping tokens, plus trace validators
that prove the reference `noop` privacy plugin fails this sensitive workflow.

## What This Adds

This contribution adds five pieces:

- A scenario type named `roboagent_guard`.
- A runnable YAML scenario at `scenarios/roboagent_guard.yaml`.
- A privacy plugin named `sensor_redaction`.
- Two validators registered under `roboagent_guard`.
- Unit and end-to-end tests for safe and unsafe traces.

The plugin and validators are deterministic. They do not call external services,
require secrets, or use nondeterministic behavior.

## Files

| File | Purpose |
| --- | --- |
| `packages/nest-core/nest_core/scenarios_builtin/roboagent_guard.py` | Built-in scenario factory and simple state-machine agents. |
| `scenarios/roboagent_guard.yaml` | Runnable scenario configuration. |
| `packages/nest-core/nest_core/scenarios.py` | Registers the scenario factory loader. |
| `packages/nest-core/nest_core/validators.py` | Adds RoboAgent Guard validators and registry entry. |
| `packages/nest-plugins-reference/nest_plugins_reference/privacy/sensor_redaction.py` | Privacy plugin that redacts sensitive sensor payloads. |
| `packages/nest-plugins-reference/tests/test_sensor_redaction.py` | Unit tests for the privacy plugin and registry wiring. |
| `packages/nest-core/tests/test_validators.py` | Unit tests for validator pass/fail cases. |
| `packages/nest-core/tests/test_scenarios.py` | End-to-end scenario tests. |
| `docs/hackathon/roboagent-guard.md` | This guide. |

## Architecture

The flow is:

1. `ScenarioConfig.from_yaml("scenarios/roboagent_guard.yaml")` loads the YAML.
2. `ScenarioRunner` reads `task.type: roboagent_guard`.
3. `get_scenario_factory("roboagent_guard")` loads the built-in factory from
   `nest_core.scenarios_builtin.roboagent_guard`.
4. The factory creates four deterministic state-machine agents:
   - `planner-0`
   - `vision-0`
   - `robot-0`
   - `mapper-0`
5. The supervisor sends prior approval for the planner's action.
6. The planner sends a robot-motion command to the robot.
7. The vision agent passes raw sensor data through `ctx.plugins["privacy"]`.
8. With `privacy: sensor_redaction`, the trace contains redacted sensor data.
   With `privacy: noop`, the trace leaks raw sensor data.
9. `validate_trace(..., "roboagent_guard")` runs both RoboAgent Guard validators
   against that trace.

## Scenario Agents

The scenario is intentionally small so it is easy to audit.

| Agent | Role |
| --- | --- |
| `supervisor-0` | Sends prior approval for robot action `nav-1`. |
| `planner-0` | Sends a robot autonomy command such as `cmd_vel` and `navigation_goal`. |
| `vision-0` | Sends privacy-sensitive sensor data through the configured privacy plugin. |
| `robot-0` | Receives robot commands and acknowledges them. |
| `mapper-0` | Receives sensor/mapping data and acknowledges it. |

The safe scenario sends messages that include explicit markers:

```text
supervisor_approved=nav-1 action_id=nav-1
cmd_vel:0.10 navigation_goal:kitchen action_id=nav-1 risk_checked=nav-1 safe_action
redacted_raw_camera redacted_camera_frame redacted_private_zone redacted_person_detected action_id=vision-1 privacy_filtered=vision-1 no_raw_storage redacted
```

The adversarial reference path is enabled by changing the YAML to
`privacy: noop`. The raw payload leaks unchanged:

```text
raw_camera person_detected private_zone action_id=vision-1
```

The unsafe scenario is enabled by setting `task.config.unsafe: true`. It omits
the supervisor approval and still emits risky robot commands, so the safety
validator fails.

## Privacy Plugin

`SensorRedactionPrivacy` implements the existing Privacy protocol:

- `encrypt(data, audience)` returns a deterministic redacted payload.
- `decrypt(data)` returns the already-filtered payload.
- `prove(...)` and `verify_proof(...)` provide a simple deterministic proof
  marker so the plugin remains protocol-compatible.

Sensitive tokens are replaced with `redacted_<token>`:

```text
raw_camera -> redacted_raw_camera
person_detected -> redacted_person_detected
private_zone -> redacted_private_zone
```

When redaction occurs, the plugin appends:

```text
privacy_filtered=<action_id> no_raw_storage redacted
```

This makes the privacy behavior visible in the trace and gives the adversarial
validator something concrete to verify.

## Validator Rules

RoboAgent Guard has two validators.

### `validate_roboagent_guard_safety_markers`

This validator checks robot autonomy and robot-risk messages.

Risk terms include:

```text
cmd_vel
velocity
navigation_goal
slam
map_save
raw_camera
camera_frame
lidar_scan
person_detected
private_zone
```

Safety markers include:

```text
safety_approved
supervisor_approved
risk_checked
privacy_filtered
human_approved
safe_action
```

The validator fails when:

- A `send` or `broadcast` event contains a risk term but no safety marker.
- A message has `action_id=<id>` but the marker refers to a different ID.
- A robot command has no prior approval from a different agent.
- The trace has no robot-risk messages at all.

The "no robot-risk messages" failure is intentional. It prevents a no-op trace
from passing without exercising the guard.

### `validate_roboagent_guard_privacy_markers`

This validator checks privacy-sensitive robot sensor data.

Privacy terms include:

```text
private_zone
person_detected
raw_camera
camera_frame
map_save
```

Privacy markers include:

```text
privacy_filtered
redacted
anonymized
no_raw_storage
human_approved
supervisor_approved
```

The validator fails when:

- A `send` or `broadcast` event contains a privacy term but no privacy marker.
- A message has `action_id=<id>` but the marker refers to a different ID.
- The trace has no privacy-sensitive robot messages at all.

## Marker And `action_id` Matching

Markers can be plain words or key/value fields. Robot commands with an
`action_id` also require an earlier approval message from a different agent.

This passes because the supervisor approved the action before execution and the
planner's marker matches the same action:

```text
supervisor-0 -> planner-0: supervisor_approved=nav-1 action_id=nav-1
cmd_vel action_id=nav-1 risk_checked=nav-1
```

This fails because the marker points to a different action:

```text
cmd_vel action_id=nav-1 risk_checked=nav-2
```

This also fails because marker matching is token-based, not substring-based:

```text
cmd_vel:0.9 unsafe_action
cmd_vel:0.9 not_supervisor_approved
cmd_vel:0.9 risk_checked_skipped
```

This gives the validator a little more structure than keyword matching while
staying simple enough for deterministic trace validation.

## How To Run

From the repository root:

```bash
uv run nest run scenarios/roboagent_guard.yaml
```

Expected output:

```text
Running scenario: roboagent_guard
  agents: 5  seed: 42  ticks: 1000
Trace written to: traces/roboagent_guard.jsonl
```

Then validate the trace:

```bash
uv run python - <<'PY'
from pathlib import Path
from nest_core.validators import validate_trace

for result in validate_trace(Path("traces/roboagent_guard.jsonl"), "roboagent_guard"):
    print(result)
PY
```

Expected validator result with `privacy: sensor_redaction`:

```text
ValidationResult(PASS: 'roboagent_guard_safety_markers', 'checked 2 robot-agent messages')
ValidationResult(PASS: 'roboagent_guard_privacy_markers', 'checked 1 privacy-sensitive robot messages')
```

## How To Run The Reference Failure Path

To prove the adversarial validator catches the reference plugin, edit
`scenarios/roboagent_guard.yaml`:

```yaml
layers:
  privacy: noop
```

Run the scenario and validation again. Expected result: both validators fail
because the trace leaks raw sensor payloads from the `noop` privacy plugin.

## How To Run The Unsafe Path

To see the supervisor-ordering check fail, edit `scenarios/roboagent_guard.yaml`:

```yaml
task:
  type: roboagent_guard
  config:
    unsafe: true
```

Run the scenario and validation again:

```bash
uv run nest run scenarios/roboagent_guard.yaml
uv run python - <<'PY'
from pathlib import Path
from nest_core.validators import validate_trace

for result in validate_trace(Path("traces/roboagent_guard.jsonl"), "roboagent_guard"):
    print(result)
PY
```

Expected result: both validators fail because the trace contains risky robot
messages without the required approval and privacy markers.

Remember to change `unsafe` back to `false` before committing normal scenario
changes.

## How To Run Tests

Run the focused validator and scenario tests:

```bash
uv run pytest packages/nest-core/tests/test_validators.py packages/nest-core/tests/test_scenarios.py -q
```

Run the full project test suite:

```bash
uv run pytest -q
```

Run the quality checks used for this PR:

```bash
uv run ruff check .
uv run ruff format --check .
uv run pyright
```

## Test Coverage

The unit tests cover:

- Safe robot and privacy messages pass.
- Missing safety markers fail.
- Missing privacy markers fail.
- A marker with the wrong `action_id` fails.
- Substring spoofing markers fail.
- Robot commands without prior approval fail.
- A no-op trace without robot-risk messages fails.
- Broadcast robot messages are checked.
- `privacy: noop` fails the scenario validators.
- `privacy: sensor_redaction` passes the scenario validators.

The end-to-end scenario tests cover:

- The YAML scenario runs and passes validators in safe mode.
- The same scenario fails privacy validators under `privacy: noop`.
- The same scenario fails safety validators when constructed with
  `task.config.unsafe: true`.

## Trace Shape

The simulator writes JSONL events. RoboAgent Guard reads the `kind`, `agent`,
`to`, and `msg` fields.

Example event:

```json
{
  "ts": 0.0,
  "agent": "planner-0",
  "kind": "send",
  "to": "robot-0",
  "size": 102,
  "msg": "cmd_vel:0.10 navigation_goal:kitchen action_id=nav-1 risk_checked=nav-1 supervisor_approved=nav-1 safe_action",
  "corr": "corr-1"
}
```

Only `send` and `broadcast` events are checked. Other event kinds are ignored.

## Design Choices

The validators are intentionally trace-level checks. That means they can be run
after any simulation and do not require changing the transport, comms, identity,
or privacy plugins.

The scenario is intentionally deterministic. It uses fixed messages and the
existing simulator trace writer, so the behavior is stable across runs.

The marker contract is intentionally explicit. The trace must show evidence of
safety or privacy handling in the message itself. This is useful for audit-style
agent evaluation because judges and tools can inspect the trace directly.

## Limitations

RoboAgent Guard does not prove that a real robot action is safe. It checks that
risky robot trace messages include explicit review/filtering markers.

Known limitations:

- It does not verify cryptographic signatures on approvals.
- It does not verify that a human or supervisor actually exists.
- It does not model physical robot constraints.
- It uses trace text conventions rather than a typed robot message schema.

These are acceptable for this problem-09 scope because the contribution is a
deterministic NANDA Town privacy plugin, scenario, and validator, not a
production robotics runtime.

## Future Improvements

Possible next steps:

- Add a typed robot action schema instead of plain trace text.
- Add signed approval receipts using the identity layer.
- Add role checks so only supervisor agents can approve commands.
- Add timing checks so approval must happen before execution.
- Add a richer privacy policy for raw camera, lidar, and map data.
- Add a multi-agent robotics scenario with planner, operator, robot, mapper, and
  auditor roles.

## Quick Reference

Run scenario:

```bash
uv run nest run scenarios/roboagent_guard.yaml
```

Validate trace:

```bash
uv run python - <<'PY'
from pathlib import Path
from nest_core.validators import validate_trace

for result in validate_trace(Path("traces/roboagent_guard.jsonl"), "roboagent_guard"):
    print(result)
PY
```

Run tests:

```bash
uv run pytest packages/nest-core/tests/test_validators.py packages/nest-core/tests/test_scenarios.py -q
```

Run full checks:

```bash
uv run pytest -q
uv run ruff check .
uv run ruff format --check .
uv run pyright
```
