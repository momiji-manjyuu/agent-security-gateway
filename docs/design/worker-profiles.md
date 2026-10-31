# Worker profiles: research and repository work in disposable workers

Status: design + phase 1 (researcher). Phases 2 and 3 are specified here and not implemented yet.

## Goal

Today a disposable Firecracker worker only reads URLs the parent hands it (`reader`). We want it to also
**explore** (search, follow links, cross-check sources) and to **evaluate repositories**, including running
builds and tests, without widening what a compromised worker can reach.

## Principles (unchanged)

- The worker talks only to the ASG hub. No caller-controlled backend URLs; backend credentials stay in hub
  route config (env var names). The worker holds one per-run credential.
- Every new capability is a **route on the hub** that the run scope must list. Authority comes from the run
  record the parent registered, never from the worker's own claims.
- Fail closed: unknown profile, unknown route, quota exceeded, URL not eligible, guard block.
- All fetched, searched and cloned content is untrusted data. Model output is guarded as before.
- Python standard library only. No new third-party runtime dependency in this repository.
  (SearXNG is an operator-installed service on the worker host, not a dependency of this code.)

## Profiles

| Profile | Routes added to the run scope | Worker tools | Typical caps |
|---|---|---|---|
| `reader` (today) | `fc.llm.chat`, `fc.artifacts.submit` | fetch of listed hosts | steps 8, llm 6, 1200 s |
| `researcher` (phase 1) | + `fc.search`, `fc.fetch` | `search`, `fetch`, `final` | steps 30, llm 40, 3600 s |
| `repo_auditor` (phase 2) | + `fc.repo` | `list_tree`, `read_file`, `grep`, `final` | steps 40, llm 40 |
| `repo_builder` (phase 3) | + `fc.repo`, run tool | + `run` (fixed command set) | exec caps below |

Enforcement is layered, and each layer is independent:

1. **Hub run scope.** `spawn_worker` registers the profile's `allowed_routes`. A `reader` run cannot call
   `fc.search` because the hub denies the route (`run_scope_denied`).
2. **Orchestrator caps.** `asg-fc-worker` (root on the worker host) clamps the requested limits to the
   profile's table. Unknown profile names are rejected.
3. **Research service quotas** (below): per-run search/fetch/byte counts, independent of the worker.
4. **Model quota** on the hub (`run_model_quota`) still bounds model calls per run (default 200).

The MCP tool exposes `profile` to the parent, but only the names above; `limits` stays operator-only.

## Phase 1: researcher

### Research service (on the worker host, 192.168.1.90)

`setup/research-service/research_service.py` is a small stdlib HTTP service bound to a LAN address that only
the hub can reach (host firewall). It has two jobs and is the **only** thing that touches the internet for a
researcher run:

- `POST /search` `{run_id, query}`: calls a local SearXNG instance whose URL is fixed in the service config
  (never taken from the request), then **filters the results**: https only, port 443, public hosts only,
  host not on the blocklist, no userinfo, deduplicated, capped count, title/snippet length-limited and
  stripped of control characters. Obvious bad results never reach the hub. Every returned URL is recorded
  as *eligible* for that run.
- `POST /fetch` `{run_id, url}`: fetches a page only if the URL is **eligible**: it came from this run's
  search results, from a link inside a page this run already fetched, or from a seed URL the orchestrator
  registered. It resolves DNS itself, rejects private/special addresses, pins the connection to the
  validated IP, does not follow redirects automatically (each redirect target is re-checked and must also be
  eligible-by-host-policy), limits size/time/content type, and returns extracted text plus the outgoing links.
- `POST /register` (orchestrator only, HMAC with a key read from an environment variable name in the service
  config): `{run_id, seed_urls, limits}` before the VM boots. Seeds come from the parent's trusted request.

Per-run quotas (searches, fetches, total bytes, distinct hosts) are enforced here and cleared on expiry.
Counters are in memory: a restart resets them, which is acceptable because the hub run TTL still bounds a run.

### Hub routes

The two routes set `output_policy.untrusted_tool_result: true`: their responses are untrusted web pages headed for a model
with its own input guard, and the generic output guard's URL/path-shape rules (localhost, long or encoded paths, query
strings) would otherwise block most technical pages. Only those shape findings are relaxed; secrets, canary, injection,
obfuscation, dangerous schemes, credentials in URLs and incomplete inspection still block.

`fc.search` and `fc.fetch` are `http_json` routes (existing kind, POST), callers `fc_worker`, `require_run_id`,
backend `base_url` pointing at the research service with signed requests. Input policy accepts the worker's
taint; output policy blocks secrets and private URLs; the existing input guard on `fc.llm.chat` still
inspects everything that reaches the model, and the worker's warn-and-drop behavior still applies.

### Worker (`worker_agent.py`)

Actions become `fetch`, `search`, `final`. For the `reader` profile behavior is exactly as today (direct
fetch of listed hosts). For `researcher`, `search` and `fetch` go through the hub routes, so allow-list
decisions are made outside the guest. The loop keeps a compact **notes** buffer (the model is asked to
rewrite it each turn) instead of re-sending every page, so long explorations fit in context.

### Output

A structured report artifact: findings, each with source URLs (no query strings), plus the same warnings list.
Artifact status handling (`verified`, `verified_with_warnings`, quarantine) is unchanged.

## Phase 2: repo_auditor

- `fc.repo` fetches a repository archive (allowed forges only, size capped) via the research service, which
  unpacks it safely (no absolute paths, `..`, links, device files; file count/size caps) and serves tree
  listings, file reads and grep over a read-only snapshot keyed by `run_id`.
- Repository files get their own taint class `repo_content`. Security-related repositories trigger input
  guard false positives, so the route carries its own tuned `input_policy`/guard settings; a block still
  drops that file from context with a warning (fail closed).
- The worker never executes repository code in this profile.

## Phase 3: repo_builder (build and test execution)

Execution is a different trust level, so it gets a different VM class:

- **No network.** A second tap/nft profile with no NAT and no route to the hub except the single
  `<BRIDGE_IP>:<ASG_PORT>` endpoint is not enough for build tools, so dependencies are **pre-fetched by the
  research service into a read-only snapshot** (vendored/locked dependencies only) and attached as an
  extra block device. The build VM cannot reach the internet or the LAN.
- **Fixed command set**, chosen by the parent from a registry (for example `pytest`, `python -m unittest`,
  `npm test --ignore-scripts`, `cargo test --offline`, `go test`), never free-form shell. Each command has
  cpu/memory/pid/time/output caps. Install-time scripts are disabled where the tool supports it.
- Output is `sandbox_output` taint, size-limited and guarded like any other content.
- The run record, not the worker, decides whether `run` exists in the scope; golden image gets a new version
  (v3) with the toolchains; published versions are never modified.
- The VM is destroyed after every run; no state survives. Build artifacts are not returned, only reports.

## Rollout

1. Phase 1 code + tests; SearXNG and the research service installed on the worker host by the operator
   (needs the operator's interactive sudo; see the runbook); hub routes added after `validate-config`;
   e2e with a research task.
2. Phase 2 once phase 1 has run clean for a while.
3. Phase 3 only after a separate review of the no-network build VM class.

## Non-goals

- Letting the worker choose its own backend, model endpoint or credentials.
- Free-form shell in any profile.
- LLM-based allow/deny decisions for URLs or commands (all checks are deterministic).
