# Health monitoring and fail-closed behaviour

- **Fail-closed.** If ASG or the tunnel is down:
  - `spawn_worker` cannot register a run and raises an error;
  - workers cannot reach the model or submit;
  - nothing bypasses ASG.
- **Supervisor (gateway host).**
  - `start_asg.ps1` polls `http://127.0.0.1:<ASG_PORT>/healthz` every 15 s.
  - After 4 failures, or if the gateway or relay exits, it restarts both itself with a 5–120 s backoff, logged to
    `disposable-search\supervisor.log`.
  - Task Scheduler's RestartCount does *not* fire on a non-zero exit code, so the supervisor never exits.
- **Tunnel.** `asg-tunnel.ps1` reconnects every 10 s (log: `C:\ProgramData\asg-tunnel\logs`).
- **Worker host.**
  - Add to the login user's crontab:
    `*/2 * * * * ASG_HEALTH_URL=http://<BRIDGE_IP>:<ASG_PORT>/healthz $HOME/asg-setup/asg-health-check.sh`
  - State changes go to `~/asg-health.log`.
- **Tests worth repeating.**
  - Kill `gateway.py`: recovery should take under 30 s.
  - Kill the tunnel `ssh.exe`: it reconnects.
  - Reboot the gateway host: both tasks start at boot without a login.
- **Standby.** A cold-standby gateway is described as an option in the service-account README. It is not part of
  the default setup because it copies secrets to a second host.
