# Migration From agent-security-proxy

Agent Security Gateway is not a drop-in feature update to Agent Security Proxy. It changes the central routing model from one configured `target` to server-side route tables.

## Runtime Paths

| Old | New |
| --- | --- |
| `~/.agent-security-proxy/config.json` | `~/.agent-security-gateway/config.json` |
| `~/.agent-security-proxy/audit.jsonl` | `~/.agent-security-gateway/audit.jsonl` |
| `~/.agent-security-proxy/KILL_SWITCH` | `~/.agent-security-gateway/KILL_SWITCH` |
| `ASP_*` | `ASG_*` |

## Config Model

Old proxy configs used one `target`. Gateway configs use:

- `agents.<agent_id>.token_sha256`
- `agents.<agent_id>.allowed_capabilities`
- `agents.<agent_id>.allowed_routes`
- `routes.<route_id>.backend`
- optional `runs.<run_id>`
- optional `run_store.path` and `run_store.max_ttl_seconds` for runtime run registration records

Move backend URLs and backend credential environment variable names into `routes`. Do not expose those values to callers.

## API Changes

- `/inspect` remains inspection-only.
- `/routes` is new and returns only caller-visible route metadata.
- `/v1/chat/completions` now requires a route through `X-ASG-Route`, `metadata.route_id`, or a configured model alias.
- `/v1/tasks`, `/v1/results`, and `/v1/approvals` are new MVP endpoints.
- `/v1/approvals` now requires a separate human/operator caller with `approve_action` on route `security.approvals.create`.
- `/v1/runs` registers short-lived dynamic run scopes and requires a controller caller with `register_run` on route `security.runs.register`.
- Approval record schema changed. Target fields are now `target_agent_id`, `target_route_id`, and `target_capability`; the approver is recorded separately as `approver_agent_id`.
- Old approval records with `agent_id`, `route_id`, and `capability` may be ignored or require migration.
- `input_policy` fields are now enforced, so requests previously accepted may now be rejected.

## Preserved Defenses

Gateway preserves the useful proxy defenses: bearer token hash authentication, trust tier metadata, CIDR checks, rate limit, kill switch, Unicode normalization, deterministic scanner, secret-like scanner, obfuscation scanner, structured extraction, output guard, LLM inspector hook, smoke-test posture, and hash-chained JSONL audit logs.

## Intentional Breaks

- No implicit single backend.
- No caller-provided backend URL.
- No route-less chat forwarding.
- No caller token forwarding to backend.
- Command backends are disabled unless a command route explicitly sets `enabled: true`.
