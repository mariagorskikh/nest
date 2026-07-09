# SPDX-License-Identifier: Apache-2.0
"""Worker partition helpers for distributed simulation.



Example::



    parts = partition_agents(agent_ids, n_workers=2)
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from nest_core.types import AgentId


@dataclass(frozen=True)
class WorkerPartition:
    """One worker's slice of a multi-agent scenario."""

    worker_id: int
    agent_ids: list[AgentId]
    trace_path: Path
    seed: int
    listen_port: int
    bind_host: str = "127.0.0.1"
    advertise_host: str = "127.0.0.1"


def partition_agents(
    agent_ids: list[AgentId],
    n_workers: int,
    *,
    master_seed: int,
    trace_dir: Path,
    base_port: int = 19000,
    bind_host: str = "127.0.0.1",
    worker_hosts: list[str] | None = None,
) -> list[WorkerPartition]:
    """Split agents round-robin across workers."""
    if n_workers < 1:
        msg = "n_workers must be >= 1"
        raise ValueError(msg)
    if not agent_ids:
        return []
    buckets: list[list[AgentId]] = [[] for _ in range(n_workers)]
    for idx, aid in enumerate(agent_ids):
        buckets[idx % n_workers].append(aid)
    partitions: list[WorkerPartition] = []
    for worker_id, bucket in enumerate(buckets):
        if not bucket:
            continue
        advertise = (
            worker_hosts[worker_id]
            if worker_hosts is not None and worker_id < len(worker_hosts)
            else bind_host
        )
        partitions.append(
            WorkerPartition(
                worker_id=worker_id,
                agent_ids=bucket,
                trace_path=trace_dir / f"worker-{worker_id}.jsonl",
                seed=master_seed + worker_id,
                listen_port=base_port + worker_id,
                bind_host=bind_host,
                advertise_host=advertise,
            )
        )
    return partitions
