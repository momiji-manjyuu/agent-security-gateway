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
   | `fc.search`, `fc.fetch` | `output_policy.untrusted_tool_result: true` | researcher tool results are untrusted web pages: URL/path SHAPE findings (localhost, long or encoded paths, query strings, local paths in docs) no longer block; secrets, canary, injection, obfuscation, dangerous schemes, userinfo/sensitive query parameters, IP literals, system disclosure and incomplete inspection still do. Only valid on `http_json` routes; relaxed categories appear as `relaxed_categories` in the scan audit |
   | `fc.llm.chat` | `input_policy.allow_scanner_findings: [input_dlp:private_host, ...]` | the model-side input guard ignores the listed URL/path SHAPE categories (see the fragment for the list) so fetched technical pages reach the model; secrets, injection, obfuscation, schemes, userinfo, `url_sensitive_query` and `boundary:` findings still block. Applies to every request on the route; ignored categories show as `route_ignored_input_finding:*` warnings |
   | `fc.llm.chat` | `input_policy.allowed_private_instruction_hosts: [localhost, 127.0.0.1]` | the action guard and input guard accept those exact hosts in fetched pages (loopback examples in docs); any other private host in the same request (LAN ranges, `[::1]`, link-local) still blocks the whole request, and the metadata endpoint always blocks |
   | `fc.repo` | `output_policy.untrusted_tool_result: true`, `backend.passthrough_error_codes` | repo_auditor tool results (tree, file text, grep hits) are untrusted repository content: same relaxation and same code passthrough as `fc.search`/`fc.fetch`; the route accepts the taint `untrusted_github` and requires capability `worker_repo` |
   | `fc.search`, `fc.fetch` | `backend.passthrough_error_codes: [...]` | a backend 4xx whose JSON body carries `{"error": {"code": X}}` with X in the list reaches the caller as `backend_X` (status kept; 401/407 and 5xx excluded) instead of the opaque `backend_error`. Exact codes only: the backend's message, body and headers are never forwarded. List policy and quota codes; never authentication or configuration codes. Only valid on `http_json` routes |
   | `fc.artifacts.submit` | `artifact_policy.review_injection_as_warning: true` | describe-only answers released as status `verified_with_warnings` (add it to the download route's `allowed_statuses` AND add the taint `describes_untrusted_instructions` to that route's `input_policy.accepted_taint`, otherwise the download is refused with `taint_denied`; `warning_release_categories` defaults to `prompt_injection:` only) |

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
   - `Stop-ScheduledTask` stops only the supervisor: the child `gateway.py` and `inspector_relay.py` processes keep
     running, the old gateway keeps port 8788 with the OLD config and environment, and the new one cannot bind. After
     a config or environment change also stop every `python` process whose command line contains `gateway.py` or
     `inspector_relay.py`, then start the task, and confirm the change took effect: `/healthz` must show the new route
     count and a worker run must report the expected model (the artifact footer lists `model(s) via ASG fc.llm.chat`).
   - Check with `asg_inspect` on a harmless sentence (expect `blocked: false`) and an injection sentence (expect `blocked: true`).
