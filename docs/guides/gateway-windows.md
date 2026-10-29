# Gateway host (Windows)

1. **Install.** Python 3.12 (`<PythonExe>`). Clone the repo to `<CodeDir>`. Create the state dir
   `<StateHome>\.agent-security-gateway`.
2. **Config.**
   - Start from `config.example.json` + `examples/config.fc-worker.fragment.json` (worker routes: `fc.llm.chat`,
     `fc.artifacts.submit`, decoy export).
   - Keep `bind` at `127.0.0.1`.
   - Set `routes.fc.llm.chat.backend.base_url` to `<MODEL_BASE_URL>` and `api_key_env` to an env var NAME.
   - Put secrets (HMAC keys, backend keys) only in an operator-only env file
     (`disposable-search\asg-env.json`, mapping env-var name → value). Never commit it.
   - Validate: `python gateway.py --config <cfg> validate-config`.
3. **Recommended route options.**

   | Route | Option | Effect |
   |---|---|---|
   | `fc.llm.chat` | `action_policy.read_only_model: true` | model has no tools |
   | `fc.llm.chat` | `report_run_warnings: true` | per-run warnings |
   | `fc.llm.chat` | `output_policy.allow_fetch_query_to_run_hosts: true` | query strings allowed only in exact fetch actions to run-registered hosts |
   | `fc.artifacts.submit` | `artifact_policy.review_injection_as_warning: true` | describe-only answers released as status `verified_with_warnings` (add it to the download route's `allowed_statuses`; `warning_release_categories` defaults to `prompt_injection:` only) |

   Also set `llm_snippet_check.apply_to_output: true`.
4. **Service.**
   - Copy `setup/windows-service-account/asg-windows.example.psd1` to `asg-windows.psd1` and fill it in.
   - Run `Install-AsgServiceAccounts.ps1` elevated. It creates the low-privilege accounts and minimal ACLs, and
     moves the scripts to `C:\ProgramData\asg\bin`. It also points the scheduled tasks (boot trigger) at the
     supervisor `start_asg.ps1` and the tunnel `asg-tunnel.ps1`.
   - See [service-accounts.md](service-accounts.md).
5. **Updates.**
   - `Deploy-AsgUpdate.ps1 -From <dir> -Tag <rev>` backs up, copies, runs the tests, validates the config,
     restarts, and rolls back on failure.
   - Run modes: `python scripts/asg_run_modes.py --config <cfg> --show`.
6. **Never.** Bind non-loopback, disable guards, or keep test mode on outside a test session.

7. **Changing the model endpoint.**
   - The gateway's `llm_inspector` goes through `model_runtime\inspector_relay.py`, which reads `MODEL_BROKER_HOST` /
     `MODEL_BROKER_PORT` from `asg-env.json`. If that endpoint has no live backend, the inspector fails closed and EVERY
     input is reported as `llm_inspector:error` (blocked).
   - `start_asg.ps1` reads `asg-env.json` once when it starts. Killing only the gateway/relay makes the supervisor restart
     them with the OLD environment; after editing `asg-env.json` run `Stop-ScheduledTask` / `Start-ScheduledTask`
     on the gateway task (`AgentSecurityGateway`) so the supervisor itself restarts.
   - Check with `asg_inspect` on a harmless sentence (expect `blocked: false`) and an injection sentence (expect `blocked: true`).
