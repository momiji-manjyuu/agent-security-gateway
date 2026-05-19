# Changelog

## Unreleased

- Added response_format schema-content linting for long descriptions and suspicious instruction-like text.
- Added Windows `msvcrt.locking` audit file-lock fallback and documented file-lock limits.
- Expanded GitHub Actions CI to Python 3.10, 3.11, and 3.12.

## [0.1.0] - 2026-05-19

- Added capability-aware output URL policies.
- Added audit hash-chain verification.
- Added red-team corpus metrics.
- Added configuration validation and a JSON Schema reference.
- Added a GitHub Actions CI workflow and a reference copy under `docs/`.
- Expanded scanner coverage for caller tool/function controls, privileged message roles, sensitive image URL queries, JWT/GitLab/Google-style secrets, and additional languages.
- Expanded the red-team corpus with tagged payload cases for tool calls, function arguments, image URLs, and multilingual injection probes.
- Added audit finding summaries for easier log aggregation.
- Added backend policy manifest export and stricter validation that backend tools must be explicitly allowlisted by capability.
- Blocked forward attempts from inspect-only capabilities with explicit `allow_forward` policy.
- Enforced `requires_human_approval` as a forward stop and added policy/manifest hashes for backend contract checks.
- Added audit write locking, undefined capability rejection, and fixed-policy `response_format` forwarding.
- Hardened `capability_allows_forward`, documented the threat model, and added a real GitHub Actions CI workflow.
- Added README badges, a recommended deployment diagram, a static architecture diagram, and the initial security policy.
