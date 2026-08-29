"""Scaffolding: start a scenario, plugin, skill, or agent from a
working template.

A contribution usually carries a protocol (the rules), a plugin (the
code that runs those rules inside one layer), and a test that proves it
holds up. These templates are the first third of that journey.
"""

from __future__ import annotations

import os

from .layers import DEFAULT_PLUGINS, LAYER_NAMES

SCENARIO_TEMPLATE = """\
name: {name}
description: Describe what this scenario proves, in one sentence.
seed: 42
# Swap any of the twelve layers; unlisted layers use the defaults.
# layers:
#   trust: mytrust.v1
# Load your own plugin and validator files (paths relative to this
# file). Their @register and @validator decorators run at load time.
# plugin_files:
#   - {name}_plugin.py
# validator: {name}
agents:
  - name: seller-1
    role: seller
    config: {{sku: widget, ask_cents: 1995, floor_cents: 1700, stock: 10, balance_cents: 0}}
  - name: buyer-1
    role: buyer
    config: {{sku: widget, quantity: 2, cap_cents: 1900, balance_cents: 10000, rounds: 1}}
faults: []
#  - action: drop        # drop | duplicate | delay
#    kind: quote_response
#    nth: 1
max_time: 60
"""

PLUGIN_TEMPLATE = '''\
"""A custom {layer} plugin for NANDA Town.

Reference: the default implementation lives in
src/nandatown/layers/{module}.py. Copy its public methods here and
change the rules; the engine only cares that the methods exist.
"""

from nandatown.layers import register


@register("{layer}", "{plugin_id}")
class {class_name}:
    """{plugin_id}: say in one line what rule this plugin changes."""

    def __init__(self, engine):
        self.engine = engine

    # Implement the same methods as the default {layer} plugin.
    # Every state change should emit an attributed event:
    #   self.engine.emit(observer, kind, subject, detail_dict)


# Optional: a validator for a scenario that exercises this plugin.
# from nandatown.sim.validators import validator, _check
# @validator("my-scenario-name")
# def my_validator(spec, trace):
#     return [_check("my_stage", True, trace.ids("run_created"),
#                    "what failing means")]
'''

SKILL_TEMPLATE = """\
---
name: {name}
version: 1
capability: {name}
role: describe-the-role
protocol: town-mailbox.v1
summary: One line saying what an agent that follows this skill can do.
---
# {name}

Write the instructions an unfamiliar agent needs to use this skill
successfully without human intervention. Follow the town-protocol skill
for mailbox mechanics; state only the role rules here.

1. First rule.
2. Second rule.
"""

AGENT_TEMPLATE = '''\
#!/usr/bin/env python3
"""A bring-your-own-agent starter for NANDA Town.

Test it against the town:

    nandatown test-agent --role seller --cmd "python {name}.py"

The town passes TOWN_URL, RUN_ID, NAME, TOKEN, DEADLINE in the
environment. Claim work under a lease, apply each piece exactly once,
acknowledge honestly. See examples/byoa_seller.py in the nandatown
repository for a complete stdlib-only reference.
"""

import json
import os
import time
import urllib.request

TOWN = os.environ["TOWN_URL"]
RUN = os.environ["RUN_ID"]
session = None


def call(method, path, body=None):
    req = urllib.request.Request(
        f"{{TOWN}}/runs/{{RUN}}{{path}}",
        data=json.dumps(body).encode() if body is not None else None,
        method=method, headers={{"Content-Type": "application/json",
                                 **({{"X-Town-Session": session}}
                                    if session else {{}})}})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return None if resp.status == 204 else json.loads(resp.read())


# Joins with the run's join token. A role pinned to a portable identity
# (--identity) must present TOWN_GRANT with an Ed25519 session proof
# instead; see nandatown.client.TownClient.join_with_grant.
joined = call("POST", "/join", {{"name": os.environ["NAME"],
                                 "token": os.environ["TOKEN"]}})
session = joined["session"]
deadline = time.time() + float(os.environ.get("DEADLINE", "45"))
processed = set()

while time.time() < deadline:
    call("GET", "/inbox/notify?wait=0.4")
    claim = call("POST", "/inbox/claim")
    if claim is None:
        continue
    # Your agent's actual work goes here.
    duplicate = claim["message_id"] in processed
    processed.add(claim["message_id"])
    call("POST", "/inbox/ack",
         {{"message_id": claim["message_id"], "fence": claim["fence"],
           "status": "processed",
           "note": {{"applied": not duplicate, "duplicate": duplicate}}}})
'''


class ScaffoldError(Exception):
    pass


def _write(path: str, content: str) -> str:
    if os.path.exists(path):
        raise ScaffoldError(f"{path} already exists; not overwriting")
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)
    return path


def new_scenario(name: str, directory: str = ".") -> str:
    return _write(os.path.join(directory, f"{name}.yaml"),
                  SCENARIO_TEMPLATE.format(name=name))


def new_plugin(layer: str, plugin_id: str, directory: str = ".") -> str:
    if layer not in LAYER_NAMES:
        raise ScaffoldError(f"unknown layer {layer!r};"
                            f" choose from {LAYER_NAMES}")
    module = {"registry": "registry_layer"}.get(layer, layer)
    class_name = "".join(part.capitalize() for part in
                         plugin_id.replace(".", "-").split("-"))
    filename = f"{layer}_{plugin_id.replace('.', '_')}.py"
    return _write(os.path.join(directory, filename),
                  PLUGIN_TEMPLATE.format(layer=layer, module=module,
                                         plugin_id=plugin_id,
                                         class_name=class_name))


def new_skill(name: str, directory: str = ".") -> str:
    return _write(os.path.join(directory, f"{name}.md"),
                  SKILL_TEMPLATE.format(name=name))


def new_agent(name: str, directory: str = ".") -> str:
    return _write(os.path.join(directory, f"{name}.py"),
                  AGENT_TEMPLATE.format(name=name))


def scaffold(kind: str, name: str, extra: str | None,
             directory: str = ".") -> str:
    if kind == "scenario":
        return new_scenario(name, directory)
    if kind == "plugin":
        if not extra:
            raise ScaffoldError("plugin needs a layer and a plugin id:"
                                " nandatown new plugin <layer> <id>")
        return new_plugin(name, extra, directory)
    if kind == "skill":
        return new_skill(name, directory)
    if kind == "agent":
        return new_agent(name, directory)
    raise ScaffoldError(f"unknown kind {kind!r}")


HINTS = {
    "scenario": "run it: nandatown run {path}",
    "plugin": "name it in a scenario under layers: and load the file"
              " with plugin_files:",
    "skill": "check it: nandatown skills --validate {path}",
    "agent": "test it: nandatown test-agent --cmd \"python {path}\"",
}
