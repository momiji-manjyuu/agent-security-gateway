# Test mode and quarantined read

Both are **off by default**. Enable them only for an approved test session, and switch them off afterwards with
`python scripts/asg_run_modes.py --config <cfg> --test-mode off --quarantined-read off` plus a restart.

| | `test_modes.input_guard_log_only` | `quarantined_read` |
|---|---|---|
| Purpose | measure what the input/action guards would block (red-team runs) | read risky pages while extracting useful info |
| Opt-in | config `enabled` + per-run `test_mode` at registration (parent only, TTL-limited) | config `enabled` + per-run `read_mode: "quarantined"` (parent only) |
| Passes | all input/action guard blocks on the listed routes (logged as `test_mode_*_bypass`) | only injection-type findings (prompt_injection / obfuscation / llm_inspector / local path) with risk ≤ `max_risk_score`, on read-only model routes |
| Still enforced | output guard, canary, per-run identity, allowlist | secrets, DLP, private URLs, canary, output guard |
| Evidence | optional `evidence_file` (raw snippets, untrusted): move to quarantine after the session with `Move-AsgEvidenceToQuarantine.ps1` | none; mandatory `asg_warnings` on artifacts |

- **Tradeoff of quarantined read.** Injected text reaches the model, which may then write a misleading summary or
  make extra fetches on allowed hosts.
- **What limits it.** The model has no tools and no secrets, the allowlist and output guard still apply, the VM is
  disposable, and results are always untrusted.
- **Operator-only.** Neither mode can be requested through the MCP tool schema; both are operator arguments only.
