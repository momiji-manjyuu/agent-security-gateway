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

# Boundary policy migration

This update hardens the v0.1.x gateway's existing policy boundaries. Back up
the runtime configuration and append-only stores before deploying. Keep real
credentials outside the source checkout. Validate configuration and test the
configured backends in staging before switching the service.

## Artifact operations are explicit

Each artifact route needs `artifact_policy.allowed_operations`. An omitted or
empty list grants no artifact operations. The matching capability, route,
caller, run, taint, and status checks still apply.

| Purpose | Required capability | Allowed operations |
| --- | --- | --- |
| Upload | `submit_artifact` | `["submit"]` |
| Read verified artifacts | `download_artifact` | `["metadata", "content"]` |
| Read metadata only | `download_artifact` | `["metadata"]` |
| Isolated summary review | `review_artifact` | `["review"]` |
| Human quarantine review | `review_quarantined_artifact` | `["metadata", "content"]` |

Update custom routes as well as built-in routes. The public configuration
examples include these fields. Inspect-only permissions do not grant artifact
access. Reviews inherit the source artifact's run/task scope and recheck its
caller, route, expiry and taint restrictions. A conflicting supplied scope is
denied. Derived artifacts preserve the source run/task scope.

Previously verified artifacts are inspected again before download or review.
Old artifacts containing newly detected findings or invalid media types may
be denied. Re-submit them through the current upload path for an updated
classification; do not change their stored status to bypass inspection.

## IDs and notifications

`run_id` and `task_id` must match `[A-Za-z0-9._-]{1,128}`. Header, metadata and
top-level values must agree; ambiguous or invalid values are rejected.
`X-Request-ID` supplied by a caller is no longer used: correlate requests with
the generated `request_id` in the response. Static runs now enforce
`allowed_callers`, just like registered runs.

Receipt policy and receipt rate limits belong to the route. They apply on
`/v1/results`, `/v1/tasks`, `/v1/chat/completions`, and query-string variants.
OpenAI notification messages contain an allowlist of gateway-generated audit
fields. Caller-selected run/task IDs appear as `sha256_` references in those
messages; correlation metadata outside the messages retains validated IDs.
Free-form warnings, classifier explanations and caller report text do not
enter these model notifications. Caller-supplied `receipt_type` is reserved
and rejected.

## Complete inspection and approvals

Input and backend output inspection covers decoded JSON keys and values,
including sibling fields, multimodal extensions and unknown fields. HTML
comments are inspected. `normalize.strip_html_comments` is deprecated and
ignored; it cannot hide comment contents from inspection.

Multipart text is also inspected in its concatenated form, so splitting a
token or instruction across text parts cannot bypass the same patterns.
Alternate projections do not count identical findings twice.

Exceeding `normalize.max_content_chars` is a blocking inspection-limit result,
even if risk thresholds are raised or a route allows other findings. The
limit applies to the complete inspection projection including JSON field
names. Split large jobs or explicitly configure a suitable bounded limit;
silent truncation no longer authorizes forwarding. Image URLs are inspected
locally while derived inspector/model text retains image URL redaction.

`allow_defensive_secret_instructions: true` is rejected at startup. Remove
this flag. Put fixed defensive instructions in the trusted backend setup;
caller text cannot enable an exception by containing defensive wording.

Action approval hashes now bind every field in canonical original JSON.
Existing pending approvals may no longer match. Re-inspect and reissue them
through the authorized approval workflow; do not rewrite stored hashes.

## Request resources

Two integer settings are available (each accepts 1 through 600):

```json
{"request_read_timeout_seconds": 15, "max_concurrent_requests": 32}
```

The read deadline covers headers and body from connection acceptance; slow
drip traffic cannot extend it. It does not limit backend processing time.
Excess simultaneous connections are closed before a worker thread is created.
POST authentication and rate admission occur before reading the body.
Requests require one Content-Length and cannot use Transfer-Encoding.

General rate limits use authenticated agent identity and peer IP, including
rejected capability requests. Expired state is removed; at most 4096 active
buckets are retained, with new buckets denied when full. Tune legitimate
clients' rate allowance for this change.

## Verification

```sh
python3 gateway.py --config config.example.json validate-config
python3 gateway.py --config examples/config.home-lab.example.json validate-config
python3 -m unittest discover -s tests
```

These checks use synthetic credentials and loopback backends. They do not
verify a production service or guarantee that every semantic prompt injection
is detectable. A reviewed summary remains untrusted data; do not promote it
to parent instructions or give it authority to run tools.
