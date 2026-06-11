# Changelog

## Unreleased

- Reworked the project into Agent Security Gateway.
- Added route-based policy resolution for multi-backend AI systems.
- Added `gateway.py` with `/healthz`, `/inspect`, `/routes`, `/v1/chat/completions`, `/v1/tasks`, `/v1/results`, and `/v1/approvals`.
- Added route conflict detection, model alias routing, run-level scope, taint enforcement, action guard, and route-owned backend credentials.
- Hardened `/v1/approvals` so only human/operator callers with `approve_action` can create target approvals, and target agents cannot self-approve.
- Split non-approvable action guard categories from approvable categories and require category coverage in approval records.
- Enforced route input policy fields including `max_messages`, `require_message_type`, `require_structured_task`, `allow_raw_external_content`, `disallow_external_urls`, and `max_batch_size`.
- Added `/readyz` and canonical backend HMAC signing over method, path, body hash, ASG identity headers, and timestamp.
- Added route-level `backend.require_signature` so selected backends fail closed when `backend_hmac_key_env` is unset, and added ASG HMAC verification to the result receipt collector.
- Changed generated and example configs to set `require_known_run_id: true`, while `validate-config` now warns when compatibility mode leaves it false.
- Added route-local `report_policy.max_receipts_per_minute` for `/v1/results` audit receipt forwarding routes.
- Hardened `x_research_request` so `query` and `question` reject control, zero-width, and bidirectional format characters.
- Added audit anchor export, collector storage for off-host anchors, and `verify-audit --expect-anchor` tail-hash verification.
- Expanded the red-team corpus and added CI thresholds for minimum attack detection and maximum benign false positives.
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
