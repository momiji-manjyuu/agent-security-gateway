# Research service (researcher worker profile)

Files for the `researcher` profile; the full procedure is in
[../../docs/runbooks/research-service.md](../../docs/runbooks/research-service.md) and the design in
[../../docs/design/worker-profiles.md](../../docs/design/worker-profiles.md).

| File | Purpose |
|---|---|
| `research_service.py` | the service (standard library only): filtered search, eligible-URL fetch, per-run quotas, signed requests |
| `research-service.example.json` | config example (listen address, blocklist, limits) |
| `asg-research.service` | systemd unit for the service |
| `install-research.sh` | root installer for the service (asks for the hub signing key with hidden input) |
| `searxng.service` | systemd unit for the local SearXNG backend |
| `install-searxng.sh` | root installer for SearXNG at a commit you pin and review |

Order on the worker host: `install-searxng.sh <commit>`, `install-worker.sh <login-user>`, `install-research.sh <host-ip>`.
