# Changelog

## Unreleased

- Run scope is fail-closed by default: `require_known_run_id` now defaults to `true` (set it to `false` explicitly for compatibility mode), and a static run policy with an unparseable `expires_at` is denied with 403 instead of raising. Review finding V3.
- `relax_fetch_action_url_query` is stricter: duplicate JSON keys are refused, the `url_query` findings are dropped only when the verified fetch URL is the only URL-with-query in everything that was scanned (think blocks, other fields), and `blocked` keeps incomplete-inspection (`boundary:scan_limit`) instead of being recomputed from the score alone. Review finding V2.
- Multipart text parts that exceed the inspection limit now raise `action_guard:inspection_limit` like the plain body does. Review finding V4.
- Fixed quarantined read so it no longer lifts action-guard blocks: only the input guard has a quarantine exception (injection-type findings per `quarantine_eligible`); private/LAN/metadata targets, dangerous schemes, caller-controlled backends, inspection limits and secret-exfiltration requests stay blocked. The now-unreachable `quarantined_read_action_pass` audit path was removed.
- Snippet check (`llm_snippet_check`) now asks the classifier about EVERY match of a pattern before lowering a finding and fails closed when there are more matches than the `max_checks` budget can verify; `parse_snippet_verdict` requires the exact single verdict word (negations like "not a description", extra prose, multiple verdict words, or an unclosed think tag keep the pattern judgment). Removed the unused `max_matches_per_finding` option (still accepted in configs for compatibility).
- Firecracker worker redirects are now allowlist-checked BEFORE any request is sent via an `AllowlistRedirectHandler` (previously the check ran after the redirected request had already contacted the disallowed host). `fetch()` also validates the initial URL with the same rules (scheme/hostname/userinfo/port, malformed port refused).
- Added a gateway-side per-run quota on model invocations (`run_model_quota.enabled`, `run_model_quota.max_model_calls_per_run`, default 200): chat-completions requests with a `run_id` are counted across all such routes and denied with `run_model_quota_exceeded` once the cap is reached; only requests that are actually forwarded count, and requests without a `run_id` are unaffected. Worker-side limits were advisory only.
- Fixed `gc-runs` so it cannot revive revoked credentials: a run whose LATEST record is expired has all of its records dropped (revocation is itself an expiring record, so pruning expired records individually let the older pre-revocation registration survive and re-activate the per-run worker identity).
- `host-network.sh` now matches `docs/guides/reverse-tunnel.md`: workers may reach `BRIDGE_IP:ASG_PORT` (the reverse-tunnel endpoint on the worker host) via a new input rule, and the `ASG_IP:ASG_PORT` forward rule is documented as the ASG-hub-on-LAN exception. Worker outbound internet access via NAT is intentionally unchanged (no ASG-only egress lockdown).
- Hardened the Firecracker orchestrator: `/etc/asg/fc-worker.env` is parsed as data (known `ASG_FC_*` keys, plain `KEY=VALUE` values, no expansion or shell syntax; root-owned, not group/other-writable, parent dir not writable by others; anything else fails closed) instead of being sourced as root shell code, and the per-run spec is validated with explicit checks instead of `assert` (which `python -O` would drop).

- Hub (`gateway.py`, and the legacy `proxy.py` serve path) is now loopback-only: `bind` must be `127.0.0.1`/`::1`/`localhost` (default `127.0.0.1`), any non-loopback or wildcard bind is refused at config validation before listening, and `allow_public_bind` no longer overrides this. Reach the hub from other hosts through SSH tunnels.

- Hardened complete-payload inspection, receipt-only forwarding, output metadata scanning, artifact operation/run authorization, media types, request deadlines, and rate limits. Removed the defensive-secret-instruction bypass; see `MIGRATION.md`.
- Added 30 security-boundary regression tests and a disposable Docker research-worker example with fixed Qwen/DeepSeek model brokers, signed ASG integration, and CI coverage.

- Reworked the project into Agent Security Gateway.
- Added route-based policy resolution for multi-backend AI systems.
- Added `gateway.py` with `/healthz`, `/inspect`, `/routes`, `/v1/chat/completions`, `/v1/tasks`, `/v1/results`, and `/v1/approvals`.
- Added route conflict detection, model alias routing, run-level scope, taint enforcement, action guard, and route-owned backend credentials.
- Added `/v1/runs` runtime run registration, file-backed `run_store`, dynamic run scope enforcement, and `gc-runs`.
- Hardened `/v1/approvals` so only human/operator callers with `approve_action` can create target approvals, and target agents cannot self-approve.
- Split non-approvable action guard categories from approvable categories and require category coverage in approval records.
- Enforced route input policy fields including `max_messages`, `require_message_type`, `require_structured_task`, `allow_raw_external_content`, `disallow_external_urls`, and `max_batch_size`.
- Added `/readyz` and canonical backend HMAC signing over method, path, body hash, ASG identity headers, and timestamp.
- Added route-level `backend.require_signature` so selected backends fail closed when `backend_hmac_key_env` is unset, and added ASG HMAC verification to the result receipt collector.
- Changed generated and example configs to set `require_known_run_id: true`, while `validate-config` now warns when compatibility mode leaves it false.
- Added route-local `report_policy.max_receipts_per_minute` for `/v1/results` audit receipt forwarding routes.
- Added client-side `/v1/results` rate limiting and 429 retry backoff to the OpenAI-compatible worker shim.
- Hardened `x_research_request` so `query` and `question` reject control, zero-width, and bidirectional format characters.
- Added audit anchor export, collector storage for off-host anchors, and `verify-audit --expect-anchor` tail-hash verification.
- Expanded the red-team corpus and added CI thresholds for minimum attack detection and maximum benign false positives.
- Added `artifact_review` routes that load verified artifacts by ID, isolate raw text to a route-configured review backend, validate reviewed-summary JSON, return only schema-approved fields, and record derived artifact/audit lineage with `reviewed_untrusted_summary` taint.
- Added `/v1/results` audit receipt forwarding for Mac/controller notification routes so worker reports can trigger follow-up checks without forwarding raw report content.
- Added ASG-managed artifact quarantine storage with `/v1/artifacts`, `/v1/artifacts/{id}/metadata`, and `/v1/artifacts/{id}/content`; artifacts move from `unchecked` to `verified`, `needs_review`, or `blocked`, and content retrieval is forced through route/capability/taint policy.
- Changed new artifact manifests and quarantine indexes to UTC date-partitioned storage while keeping read fallback for the earlier flat artifact layout.
- Added OpenAI chat backend support for result audit receipt forwarding so Mac Hermes can receive audited worker completion notifications on port `8642`.
- Added route-local trusted control policy for known internal ASG instruction URLs and defensive secret-handling text without weakening default scanner/action/output guards.
- Documented and tested route-local trusted control exceptions for destructive worker maintenance instructions while keeping caller-controlled backend selection blocked.
- Added `scripts/openai_asg_shim.py` so workers with plain OpenAI-compatible clients can forward through ASG with fixed route, capability, and taint metadata, including `/v1/results` mode for report-only Mac/controller contact.
- Added `scripts/result_receipt_collector.py` as a minimal authenticated Mac/controller backend for storing ASG result audit receipts.
- Preserved deterministic scanner, Unicode normalization, output guard, LLM inspector hook, kill switch, rate limit, and hash-chained JSONL audit logs from the proxy codebase.
- Replaced runtime paths and scripts with `~/.agent-security-gateway` and `ASG_*`.
- Added gateway config examples, request examples, schema references, migration notes, and security-first agent instructions.
