# Changelog

## Unreleased

- Added capability-aware output URL policies.
- Added audit hash-chain verification.
- Added red-team corpus metrics.
- Added configuration validation and a JSON Schema reference.
- Added a CI workflow template for tests, corpus evaluation, and example config validation.
- Expanded scanner coverage for caller tool/function controls, privileged message roles, sensitive image URL queries, JWT/GitLab/Google-style secrets, and additional languages.
- Expanded the red-team corpus with tagged payload cases for tool calls, function arguments, image URLs, and multilingual injection probes.
- Added audit finding summaries for easier log aggregation.
- Added backend policy manifest export and stricter validation that backend tools must be explicitly allowlisted by capability.
