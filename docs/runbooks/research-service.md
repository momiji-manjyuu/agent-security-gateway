# Research service runbook (`researcher` worker profile)

Design background: [../design/worker-profiles.md](../design/worker-profiles.md). Worker host basics:
[firecracker-worker.md](firecracker-worker.md) and [../guides/worker-firecracker.md](../guides/worker-firecracker.md).

The `researcher` profile lets a disposable worker search the web and follow links; the `repo_auditor` profile lets it read
(never execute) GitHub repositories the parent named, through the same service (section 6b). All internet access for such a run
goes through one small service on the worker host (`setup/research-service/research_service.py`, standard library
only), which talks to a local SearXNG. Workers never reach either of them directly; the ASG hub calls the service
through the routes `fc.search` and `fc.fetch`.

```
worker VM -> ASG hub (fc.search / fc.fetch, run scope + guards) -> research service (<WORKER_HOST>:8790)
                                                                      -> SearXNG (127.0.0.1:8080) -> internet
```

Placeholders: `<WORKER_HOST>` is the Firecracker host's LAN address, `<LOGIN_USER>` the orchestrating login user,
`<REPO>` a checkout of this repository on any machine that can `scp` to the worker host.

## 0. What the service enforces

- Search results: https only, port 443, no userinfo, no IP literals, plain hostnames, host blocklist
  (`blocked_hosts`, `blocked_suffixes`, `blocked_url_regex`), deduplicated and capped; control and bidi characters removed.
  Obvious bad hits are dropped before anything reaches the hub.
- Fetch: only URLs that are *eligible* for the run (a seed registered by the orchestrator, a search result, or a link of
  a page the run already fetched). The service resolves DNS itself, requires every answer to be globally routable,
  pins the TLS connection to the validated IP, re-checks redirects, and limits content type, size and time.
- Address redaction: private, loopback, link-local, metadata and reserved IP addresses in titles, snippets and page text
  are replaced (`private-address.invalid`, `ipv6-address.invalid`) so a documentation page that mentions a router or the
  metadata address is not withheld whole by the hub guards. `localhost` and `127.0.0.1` are kept (the `fc.llm.chat`
  route lists them in `allowed_private_instruction_hosts`). The hub guards stay in place as the second layer. Redeploy
  `research_service.py` (section 4) after updating it.
- Repositories (`repo_auditor`): only repositories the orchestrator registered for the run, from the operator's `repo_forges`
  templates (default GitHub's `codeload.github.com`; set a forge to `null` in `/etc/asg/research-service.json` to remove it).
  The archive is read in memory, never extracted; unsafe member names reject it, links/devices are skipped; size, member and file
  caps apply (`repo_max_*`). Served read-only as `list_tree`, `read_file` and a literal `grep`; quota `repo_calls`.
- Per-run quotas (searches, fetches, bytes, distinct hosts, repo calls); unregistered runs are denied.
- Hub requests must carry the hub's backend HMAC signature; `/register` (called only by `asg-fc-worker`) has its own key.

## 1. Requirements

- Worker host with the Firecracker orchestrator installed (see the worker-firecracker guide) and outbound internet.
- A Windows or Linux ASG hub that can reach `<WORKER_HOST>:8790` (hub config already allows outbound backend calls).
- The hub's backend signing key (the environment variable named by `backend_hmac_key_env`, at least 32 characters).
  You type it once during installation (hidden input); it is never stored in this repository.
- Interactive root (sudo) on the worker host. Type the password yourself; never script it.

## 2. Install SearXNG (worker host)

SearXNG is operator-installed software, not a dependency of this repository. The script pins an exact commit, creates
a private virtualenv, binds `127.0.0.1:8080`, enables the JSON format, turns the limiter off (the research service is the
only client) and generates a fresh `secret_key`.

1. Copy the setup files: `scp -r <REPO>/setup/firecracker-worker <REPO>/setup/research-service <LOGIN_USER>@<WORKER_HOST>:/tmp/`
2. Choose and review a SearXNG commit (for example `git ls-remote https://github.com/searxng/searxng HEAD`, then read the
   changes you care about). Never use a moving branch name.
3. `sudo bash /tmp/research-service/install-searxng.sh <40-hex-commit>`

Check: `curl -s 'http://127.0.0.1:8080/search?q=test&format=json' | head -c 200` returns JSON, and
`ss -ltn | grep :8080` shows only `127.0.0.1`. To update, re-run with another reviewed commit.

## 3. Update the orchestrator and worker agent (worker host)

`sudo bash /tmp/firecracker-worker/install-worker.sh <LOGIN_USER>`. Re-running is an update; the previous
`asg-fc-worker` and `worker_agent.py` are kept as `.bak-<timestamp>`.

## 4. Install the research service (worker host)

`sudo bash /tmp/research-service/install-research.sh <WORKER_HOST>`

It creates the `asg-research` user, installs the service and unit, writes `/etc/asg/research.env` (0600, service user)
holding the hub signing key you type and a freshly generated register key, writes the same register key to
`/etc/asg/research-register.key` (0600, root), and adds `ASG_FC_RESEARCH_URL`, `ASG_FC_RESEARCH_KEY_FILE` and
`ASG_FC_TIMEOUT_MAX` to `/etc/asg/fc-worker.env`. Edit `/etc/asg/research-service.json` for your blocklist and limits
(example: `setup/research-service/research-service.example.json`) and restart with `systemctl restart asg-research`.

Check: `curl -s http://<WORKER_HOST>:8790/healthz` returns `{"ok": true}`.

## 5. Firewall

Allow TCP 8790 from the hub only. If the host runs ufw: `sudo ufw allow from <HUB_IP> to any port 8790 proto tcp`.
The Firecracker bridge must not reach the service (the `inet asg` nftables table already drops bridge-originated
connections to the host except the ASG tunnel endpoint).

## 6. Hub routes

Merge `fc.search`, `fc.fetch` and the extra `fc_worker` capabilities/routes from
`examples/config.fc-worker.fragment.json`, replacing `<RESEARCH_SERVICE_HOST>` with `<WORKER_HOST>`. Then:

1. Back up the hub config and environment file.
2. `python gateway.py --config <candidate> validate-config` with the hub environment loaded.
3. Swap in the config, stop the gateway **and** relay processes (not only the scheduled task, see
   [../guides/gateway-windows.md](../guides/gateway-windows.md)), start again, and confirm `/healthz` shows the new route count.

## 6b. repo_auditor

1. Re-install the research service (section 4), the orchestrator (section 3: `asg-fc-worker` validates and registers `repos`)
   and the worker agent (section 3). Update `/etc/asg/research-service.json` only if you want other forges or other caps
   (`repo_forges`, `repo_max_archive_bytes`, `repo_max_files`, ...; example: `setup/research-service/research-service.example.json`).
2. Merge the `fc.repo` route and the `worker_repo` capability from `examples/config.fc-worker.fragment.json` (replace
   `<RESEARCH_SERVICE_HOST>`), validate, restart as in section 6. `untrusted_github` must be accepted by the route (it is in the fragment).
3. Check: `python spawn_worker.py --profile repo_auditor --repo <owner>/<name>@<tag> --task "Summarise the architecture; cite path:line"`
   returns `status: ok`, the footer shows `repo_calls=N`, and the teardown report is clean. Negative checks: a `researcher` run that
   calls `fc.repo` is denied by the hub (`run_scope_denied`); a repository that was not registered for the run returns
   `backend_repo_not_registered`.
4. The service must reach the forge (`codeload.github.com` over 443) from the worker host; the VMs never do.

## 7. Parent tool

Copy `setup/firecracker-worker/spawn_worker.py` to the parent machine's installed location (keep a backup). The MCP tool
`spawn_worker` then accepts `profile: reader | researcher | repo_auditor` (plus `repos` for the last) (default `reader`).

## 8. Verify

- `python spawn_worker.py --profile researcher --task "Compare two sources on <topic>; cite URLs"` returns
  `status: ok`, the artifact footer shows `searches=N` and `fetches=M`, and the run is revoked afterwards.
- Negative checks: a `reader` run that tries `fc.search` is denied by the hub (`run_scope_denied`);
  an unsigned request to `/search` returns 401; `/fetch` for a URL never returned by a search returns 403 `url_not_eligible`.
- Teardown report shows `firecracker_procs_left: 0`, `tap_left: false`, `run_dir_left: false`.

## 9. Operations

- Logs: `journalctl -u asg-research -u searxng`. The service logs method and path only, never queries or URLs.
- Quotas live in memory; a restart clears per-run counters (the hub run TTL still bounds a run).
- Rollback: restore the `.bak-<timestamp>` files, `systemctl disable --now asg-research`, and remove `fc.search` /
  `fc.fetch` from the hub config (readers are unaffected either way).
- Known limits: results quality depends on the SearXNG engines you enable; a researcher can reach any public page the
  search or links lead to (bounded by quotas and the input guard on everything the model reads).
