# Distributed and parallel execution
Nanda Town supports three simulation modes:
| Mode | CLI | Deterministic trace | Use case |
|---|---|---|---|
| Default | `nest run marketplace` | Yes (byte-identical by seed) | Regression, protocol proofs |
| Parallel | `nest run marketplace --parallel` | No | Faster local runs, LLM scenarios |
| Distributed | `nest run marketplace --workers 2` | No | Multi-core / multi-machine partitions |
## Parallel mode
Enable with `--parallel` or `parallel: true` in scenario YAML.
The simulator dispatches same-timestamp events and agent lifecycle hooks
(`on_start`, `on_stop`) concurrently via `asyncio.gather`. Traces may
differ between runs even with the same seed.
## Distributed workers
`nest run --workers N` splits agents round-robin across **N workers**. In
**auto** mode (default) the coordinator spawns local subprocess workers.
Each worker:
1. Runs its own `Simulator` with a private event queue and trace file.
2. Starts an HTTP bridge on `worker_bind` (default `127.0.0.1`) at port
   `19000 + worker_id`.
3. Routes cross-partition messages through `RoutedTransport` using
   `advertise_host` from `worker_hosts` when configured.
After all workers finish, traces are merged with
`nest_core.sim.trace_merge.merge_traces` into the scenario's configured
output path.
### HTTP authentication
Distributed runs require a shared secret when `workers > 1` **or**
`worker_bind` is not localhost (`127.0.0.1`). The coordinator calls
`require_http_shared_secret()` before spawning workers; without a secret,
the run fails fast with a clear error.
```bash
# Bash
export NEST_HTTP_SHARED_SECRET="$(openssl rand -hex 32)"
nest run marketplace --workers 2 --ticks 2000
# PowerShell
$env:NEST_HTTP_SHARED_SECRET = "your-long-random-secret"
uv run nest run marketplace --workers 2 --ticks 2000
```
When the secret is set:
- `RoutedTransport` sends `X-Nest-Auth` (or `NEST_HTTP_AUTH_HEADER`) on
  every delivery POST.
- `check_health()` sends the same header on `GET /health` peer readiness
  probes.
- `WorkerHttpBridge` rejects requests with an invalid or missing header
  via `hmac.compare_digest`.
Single-process runs (`workers: 1`, default `worker_bind: 127.0.0.1`) do
not require a secret. This preserves the zero-config local dev path.
See [`security-audit.md`](security-audit.md) for the full findings register.
### Worker host configuration
```yaml
worker_bind: "0.0.0.0"          # bind address on each worker machine
worker_hosts: ["10.0.0.2", "10.0.0.3"]  # URLs other workers use to reach each bridge
```
Binding to `0.0.0.0` or any non-localhost address **requires**
`NEST_HTTP_SHARED_SECRET` even with `workers: 1`.
CLI equivalents:
```bash
nest run marketplace --workers 2 --worker-bind 0.0.0.0 \
  --worker-hosts 10.0.0.2,10.0.0.3
```
Each worker bridge exposes `GET /health` → `{"ok": true}` for readiness
checks. Verify from a manifest directory:
```bash
nest doctor --distributed ./traces/.marketplace-workers
```
### Partition heal in distributed runs
`failures.partition_heal_at_tick` is forwarded to each worker's
`Simulator`, so partition scenarios (for example
[`bft_consensus_partition.yaml`](../scenarios/bft_consensus_partition.yaml))
heal at the configured tick in both single-process and distributed modes.
### Multi-host manual launch
Use **manual** mode when workers run on separate machines without the
coordinator spawning subprocesses:
1. **Coordinator** writes a manifest under `.{scenario}-workers/` next to
   the trace output (`routes.json`, `worker-N-spec.json`, `scenario.yaml`):
   ```bash
   export NEST_HTTP_SHARED_SECRET="your-secret"
   nest run marketplace --workers 2 --worker-mode manual --ticks 2000
   ```
2. **On each host**, start the matching worker (same secret in env):
   ```bash
   export NEST_HTTP_SHARED_SECRET="your-secret"
   nest worker run --spec ./traces/.marketplace-workers/worker-0-spec.json
   nest worker run --spec ./traces/.marketplace-workers/worker-1-spec.json
   ```
3. The coordinator polls until all `worker-*.jsonl` traces exist, then
   merges them into the final output.
Copy the manifest directory to remote hosts (or share via NFS) so each
machine can read its spec and the shared `scenario.yaml`.
### Shared registry (opt-in)
Cross-worker agent discovery uses a coordinator-hosted registry RPC when
enabled:
```yaml
distributed:
  shared_registry: true
```
Workers replace their local `InMemoryRegistry` with a `RemoteRegistry`
client pointed at the coordinator. Other shared plugins (ledger,
blackboard) remain partition-local.
### Transport tuning
HTTP delivery retries, timeouts, and auth are configurable via environment
variables:
| Variable | Default | Purpose |
|---|---|---|
| `NEST_HTTP_SHARED_SECRET` | *(unset)* | Shared secret for worker bridges and registry RPC; **required** when `workers > 1` or bind is not localhost |
| `NEST_HTTP_AUTH_HEADER` | `X-Nest-Auth` | Header name for the shared secret |
| `NEST_HTTP_RETRIES` | `10` | Max delivery attempts per message |
| `NEST_HTTP_TIMEOUT` | `30` | Per-request timeout (seconds) |
| `NEST_HTTP_MAX_BODY` | `67108864` | Max request body bytes (64 MiB) |
| `NEST_HTTP_RETRY_BASE_DELAY` | `0.05` | Base delay between retries (seconds) |
| `NEST_HTTP_RETRY_JITTER` | `0.05` | Random jitter added to retry delay |
| `NEST_HTTP_RETRY_SEED` | `0` | Seed for deterministic retry jitter |
Set `NEST_LOG=info` to log delivery retries and failures at warning level.
### Limitations
- **Shared mutable plugins** other than registry are not synchronized
  across workers.
- **Non-deterministic ordering** across worker boundaries.
- **HTTP reference transport** is for testing seams; TLS is deferred — use
  a reverse proxy for production WAN deployment.
- **Trace files may contain sensitive payloads** — see
  [`security-audit.md`](security-audit.md) P2 backlog for redaction plans.
## HTTP transport plugin
Register in scenario YAML:
```yaml
layers:
  transport: http
```
The reference plugin lives in
[`nest_plugins_reference/transport/http_transport.py`](../packages/nest-plugins-reference/nest_plugins_reference/transport/http_transport.py)
and shares the delivery format with
[`nest_core/sim/network_runner.py`](../packages/nest-core/nest_core/sim/network_runner.py).
## Example
```bash
export NEST_HTTP_SHARED_SECRET="your-long-random-secret"
nest run marketplace --workers 2 --ticks 2000 -o ./traces/marketplace-dist.jsonl
nest inspect ./traces/marketplace-dist.jsonl
nest doctor --distributed ./traces/.marketplace-workers
```
See [`roadmap.md`](roadmap.md) for the phased hardening plan and
[`security-audit.md`](security-audit.md) for the post-audit backlog.
