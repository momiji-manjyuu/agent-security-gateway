# Isolated worker host (Linux + Firecracker)

Runbooks with full details: [../runbooks/firecracker-golden-image.md](../runbooks/firecracker-golden-image.md) and
[../runbooks/firecracker-worker.md](../runbooks/firecracker-worker.md).

1. **Host.**
   - `setup/firecracker-golden/golden.env.example` → `golden.env`. It sets the bridge, CIDR, pinned kernel/rootfs
     hashes and the Firecracker binary.
   - Run `sudo ./host-setup.sh`, `sudo ./host-network.sh` and `sudo ./host-kvm-perms.sh`.
   - `host-network.sh` installs the `inet asg` nftables table (`asg-nft.service`). The worker CIDR may reach only
     `<BRIDGE_IP>:<ASG_PORT>`; LAN, link-local and metadata ranges are dropped.
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
