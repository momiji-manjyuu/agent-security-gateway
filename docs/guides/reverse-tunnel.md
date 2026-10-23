# Reverse tunnel (gateway host → worker host)

ASG binds only `127.0.0.1:<ASG_PORT>` on the gateway host. Workers reach it at `<BRIDGE_IP>:<ASG_PORT>` through an
outbound `ssh -R` from the gateway host.

1. **Key.**
   - `presets/parent/tunnel/New-AsgTunnelKey.ps1` creates a dedicated ed25519 key.
   - Its `authorized_keys` line on the worker host is `restrict`, has a no-op forced command and
     `permitlisten="<BRIDGE_IP>:<ASG_PORT>"`, so the key cannot open a shell.
   - Keep the key in `C:\ProgramData\asg-tunnel\id_ed25519`, with the host key pinned in `known_hosts` there.
2. **Task.**
   - `setup/windows-service-account/asg-tunnel.ps1` loops `ssh -N -R <BRIDGE_IP>:<ASG_PORT>:127.0.0.1:<ASG_PORT>`
     with `ExitOnForwardFailure`, keepalives, `BatchMode` and `StrictHostKeyChecking=yes`.
   - It runs as the low-privilege tunnel account, which owns the key.
3. **Worker host sshd.** `GatewayPorts clientspecified` (or a `Match User` block for the tunnel user) so the bind
   address `<BRIDGE_IP>` is allowed.
4. **Check.** From the worker host: `curl -fsS http://<BRIDGE_IP>:<ASG_PORT>/healthz`.
