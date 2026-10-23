# Setup guides (by role)

| Role | Guide |
|---|---|
| Gateway host (Windows) | [gateway-windows.md](gateway-windows.md) |
| Isolated worker host (Linux + Firecracker) | [worker-firecracker.md](worker-firecracker.md) |
| Parent host (spawn_worker + dsh) | [parent-spawn-worker.md](parent-spawn-worker.md) |
| Reverse tunnel gateway → worker host | [reverse-tunnel.md](reverse-tunnel.md) |
| Low-privilege accounts + sshd DenyUsers | [service-accounts.md](service-accounts.md) |
| Health monitoring / fail-closed | [health-monitoring.md](health-monitoring.md) |
| Test mode and quarantined read | [test-modes.md](test-modes.md) |
| Rollback | [rollback.md](rollback.md) |

## Placeholders

| Placeholder | Meaning | Default / example |
|---|---|---|
| `<GATEWAY_HOST>` | Windows host running ASG (loopback bind only) | — |
| `<WORKER_HOST>` | Linux host running Firecracker workers | `worker-host.example` |
| `<PARENT_HOST>` | host running the parent agent (dsh) and `spawn_worker.py` | — |
| `<MODEL_BASE_URL>` | OpenAI-compatible model endpoint that ASG forwards worker calls to | `http://model-host:9200/v1` |
| `<BRIDGE_IP>` | worker bridge address on the worker host; ASG is reachable there through the tunnel | `10.90.0.1` |
| `<GUEST_IP>` | worker microVM address | `10.90.0.2` |
| `<ASG_PORT>` | ASG port (loopback on the gateway, bridge on the worker host) | `8788` |
| `<OPERATOR>` | Windows profile that owns ASG state | — |

## Data flow

1. The parent calls `spawn_worker`. `spawn_worker.py` registers a run with ASG; the run gets a per-run worker identity.
2. It ssh-es to the worker host and runs `sudo asg-fc-worker <run> <task>`. The orchestrator boots a fresh microVM
   from the golden image; the spec and scoped credential arrive via MMDS.
3. The worker fetches allowed https pages and calls the model only via ASG (`fc.llm.chat`). It submits its answer
   as an artifact. The VM is destroyed afterwards.
4. The parent downloads the verified artifact and gets `result_untrusted` plus `warnings_asg`. The run is then
   revoked.

There is no direct worker↔parent link, the worker holds no secrets, and worker output is always untrusted data.
