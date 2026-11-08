# Isolated worker host (Linux + Firecracker)

Runbooks with full details: [../runbooks/firecracker-golden-image.md](../runbooks/firecracker-golden-image.md) and
[../runbooks/firecracker-worker.md](../runbooks/firecracker-worker.md).

1. **Host.**
   - `setup/firecracker-golden/golden.env.example` → `golden.env`. It sets the bridge, CIDR, pinned kernel/rootfs
     hashes and the Firecracker binary.
   - Run `sudo ./host-setup.sh`, `sudo ./host-network.sh` and `sudo ./host-kvm-perms.sh`.
   - `host-network.sh` installs the `inet asg` nftables table (`asg-nft.service`). Workers keep general outbound
     internet access via NAT (no ASG-only egress lockdown, by design); they may also reach `<BRIDGE_IP>:<ASG_PORT>`
     (the reverse-tunnel endpoint) and, if the ASG hub were hosted on the LAN, `ASG_IP:ASG_PORT`. LAN, link-local,
     metadata and other special ranges are dropped, and IPv6 is fully blocked.
2. **Kernel and golden image.**
   - Build as a normal user: `./build-kernel.sh`. Then build as root: `sudo ./build-golden.sh v1`.
   - Sign/verify the image with `sign-manifest.sh` / `verify-manifest.sh`. Test: `sudo ./boot-test.sh v1`.
   - Never modify a published version in place. Build v2, v3, … instead.
3. **Orchestrator.**
   - Copy `setup/firecracker-worker/{asg-fc-worker,worker_agent.py,install-worker.sh,fc-worker.env.example}` to the
     host.
   - Run `sudo bash install-worker.sh <login-user>` interactively; type the password yourself, never script it.
   - Re-running is an update; the previous versions are kept as `*.bak-<timestamp>`.
4. **Health.** Add `asg-health-check.sh` to the login user's crontab, see [health-monitoring.md](health-monitoring.md).
5. **Limits** (enforced by the orchestrator as root): steps ≤ 8, LLM calls ≤ 6, `max_tokens` ≤ 32768,
   `max_seconds` ≤ 1800, ≤ 5 URLs, ≤ 10 allowed hosts.
6. **Profiles.** `spawn_worker` selects `reader` (default), `researcher` or `repo_auditor`; the profile decides which hub routes the
   run scope lists and which limits the orchestrator applies.

   | Profile | Extra routes | Caps (steps / LLM calls / seconds / page chars) |
   |---|---|---|
   | `reader` | none | 8 / 6 / 1800 / 8000 |
   | `researcher` | `fc.search`, `fc.fetch` | 30 / 40 / 2400 / 12000 |
   | `repo_auditor` | `fc.repo` | 40 / 40 / 2400 / 12000 |

   `repo_auditor` also takes `repos` (1-3 `owner/name[@ref]` GitHub repositories, chosen by the parent, no URLs/hosts) and is
   read-only: tree, file read and literal grep over a snapshot held by the research service; nothing is executed.

   `researcher` and `repo_auditor` need the research service and their hub routes: see
   [../runbooks/research-service.md](../runbooks/research-service.md) and
   [../design/worker-profiles.md](../design/worker-profiles.md). The VM wall-clock cap is the profile's
   `max_seconds` + 120 s, never above `ASG_FC_TIMEOUT_MAX`.
