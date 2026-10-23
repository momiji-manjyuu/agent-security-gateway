# Rollback

| What | How |
|---|---|
| gateway.py / proxy.py | `Deploy-AsgUpdate.ps1` keeps `*.bak-<tag>`: copy them back and restart the gateway task. Failed tests or validation roll back automatically. |
| config.json | restore `config.json.bak-<tag>` / `.bak-modes-*`, validate, restart. |
| Service accounts / ACLs | `Rollback-AsgServiceAccounts.ps1` (same `asg-windows.psd1`): re-imports the original tasks from `C:\ProgramData\asg\<BackupTag>`, removes the ACEs, disables the accounts. |
| sshd DenyUsers | copy `sshd_config.bak-r20` back, `sshd -t`, `Restart-Service sshd`. |
| Worker orchestrator | `install-worker.sh` keeps `*.bak-<timestamp>` under `/usr/local/sbin` and `/usr/local/lib/asg`: reinstall the previous file as root. |
| Golden image | versions are immutable; point the orchestrator back at the previous version. |
| spawn_worker.py | keep the previous copy next to it; restart dsh after swapping. |
