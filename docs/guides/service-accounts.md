# Low-privilege service accounts and sshd hardening (Windows gateway host)

Full details: [../../setup/windows-service-account/README.md](../../setup/windows-service-account/README.md).

- **Accounts.** `asgsvc` runs the gateway + inspector relay; `asgtun` runs the tunnel.
  - Both are standard users, batch logon only. Interactive, RDP and network logon are denied (`secedit`).
  - Their passwords are random, never displayed, and held only by Task Scheduler. Re-run the installer to rotate.
- **ACLs.**
  - Code: read/execute.
  - State dir and relay log dir: modify. Protected subdirectories get explicit grants.
  - The `quarantine` folder is operator + SYSTEM only.
  - Scripts live in `C:\ProgramData\asg\bin` (admin-only write).
- **Profile paths.** The supervisor sets `USERPROFILE`/`HOME` to `<StateHome>` so `~` paths in the config resolve
  to the existing state.
- **sshd.** `Set-AsgSshDenyUsers.ps1`:
  - adds `DenyUsers asgsvc asgtun <host>\asgsvc <host>\asgtun` before the first `Match` block;
  - backs up `sshd_config`, validates with `sshd -t` and restarts sshd;
  - rolls back unless a fresh admin login creates the marker file within 180 s.
  - Run it as a one-shot SYSTEM task so the restart cannot kill it.
  - Denied accounts see "Connection reset".
- **Verify.**
  - Task principals are the new accounts, and the processes are owned by them.
  - `/healthz` works locally and from the worker host.
  - After a reboot, both come back without a login.
