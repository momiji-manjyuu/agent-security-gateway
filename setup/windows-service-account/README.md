# ASG on Windows: low-privilege accounts, self-healing, single-point-of-failure notes (Rev19)

## Accounts
| Task | Before | After | Access |
|---|---|---|---|
| AgentSecurityGateway | SYSTEM | `asgsvc` (standard user, batch logon only) | RX code, Modify `~\.agent-security-gateway` (not `quarantine`), Modify `model_runtime` (relay log) |
| ASG-Tunnel-90 | SYSTEM | `asgtun` (standard user, batch logon only) | owns/reads `C:\ProgramData\asg-tunnel\id_ed25519`, writes `asg-tunnel\logs` only |

- Interactive, RDP and network logon are denied to both accounts; neither is an administrator.
- Passwords are random, never printed or stored; only Task Scheduler holds them. Re-run the installer to rotate.
- Scripts run from `C:\ProgramData\asg\bin` (admin-only write) instead of the user-writable profile.
- `start_asg.ps1` sets `USERPROFILE`/`HOME` so `~` paths in the config keep pointing at the existing state.

Install (elevated): `Install-AsgServiceAccounts.ps1`. Backups: `C:\ProgramData\asg\bak-r19` (task XML + ACL dumps).
Rollback (elevated): `Rollback-AsgServiceAccounts.ps1` (re-imports the SYSTEM tasks, removes the ACEs, disables the accounts).

## Self-healing
- The supervisor checks `/healthz` every 15 s and restarts the gateway and relay itself (4 failures, or either exits), backoff 5–120 s.
- Task Scheduler restart-on-failure does not fire on a non-zero exit code (found in Rev19 testing), so the supervisor never exits. The tunnel task loops on its own (10 s).
- Worker host: `asg-health-check.sh` in the user crontab logs up/down changes of `10.90.0.1:8788/healthz`.

## Single point of failure (fail-closed)
- If ASG or the tunnel is down, no run can be registered, workers cannot reach the model or submit, and the parent gets no result.
- Nothing bypasses ASG; failures are closed, not open.
- **Restore on the same host:** run the rollback/installer from git, restore config/state from backup, then start the tasks.
- **Standby (proposal, not implemented):** a cold-standby ASG on a second Windows host with the same repo commit.
  - Config/state would be synced from .80 nightly. The HMAC keys and tokens would be copied out-of-band by the operator.
  - The tunnel task would be disabled; to fail over, enable it there.
  - This needs the user's decision: it puts secrets on a second host and needs a machine.
