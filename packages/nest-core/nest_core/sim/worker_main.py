# SPDX-License-Identifier: Apache-2.0
"""Subprocess entry point for distributed simulation workers."""

from __future__ import annotations
import asyncio
import json
import sys
from pathlib import Path
from typing import Any
from nest_core.plugins import PluginRegistry
from nest_core.runner import ScenarioRunner, parse_partition_groups
from nest_core.scenario import ScenarioConfig
from nest_core.sim.partition import WorkerPartition
from nest_core.sim.worker import run_worker_partition
from nest_core.types import AgentId


def _load_spec(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


async def run_worker_spec(spec_path: Path) -> int:
    spec = _load_spec(spec_path)
    config = ScenarioConfig.from_yaml(spec["config_path"])
    registry = PluginRegistry()
    runner = ScenarioRunner(config, registry=registry)
    plugins, all_agents = runner.prepare()
    partition = WorkerPartition(
        worker_id=int(spec["worker_id"]),
        agent_ids=[AgentId(a) for a in spec["agent_ids"]],
        trace_path=Path(spec["trace_path"]),
        seed=int(spec["seed"]),
        listen_port=int(spec["listen_port"]),
        bind_host=str(spec.get("bind_host", "127.0.0.1")),
        advertise_host=str(spec.get("advertise_host", "127.0.0.1")),
    )
    routes = {AgentId(k): str(v) for k, v in spec["routes"].items()}
    registry_url = spec.get("registry_url")
    partition_groups: list[list[str]] | None = None
    if config.failures.network_partition:
        raw_groups = config.failures.network_partition.get("groups")
        partition_groups = parse_partition_groups(raw_groups)
    partition.trace_path.parent.mkdir(parents=True, exist_ok=True)
    await run_worker_partition(
        partition,
        config,
        all_agents,
        routes,
        plugins=plugins,
        partition_groups=partition_groups,
        registry_url=str(registry_url) if registry_url else None,
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if len(args) != 1:
        print("usage: python -m nest_core.sim.worker_main <worker-spec.json>", file=sys.stderr)
        return 2
    return asyncio.run(run_worker_spec(Path(args[0])))


if __name__ == "__main__":
    raise SystemExit(main())
