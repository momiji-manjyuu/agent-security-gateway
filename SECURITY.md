# Security Policy

Agent Security Proxy is a defense-in-depth boundary, not a complete guarantee against prompt injection or data exfiltration.

## Reporting

Please report vulnerabilities privately through GitHub Security Advisories when possible. Avoid posting exploit details in public issues before there is a fix or mitigation.

If advisories are unavailable, open a minimal issue that says a private security report is needed without including secrets, tokens, live endpoints, or exploit payloads.

## Scope

Useful reports include:

- bypasses that allow caller-controlled `tools`, `tool_choice`, `stream`, or other unsafe OpenAI-compatible fields to reach the backend;
- bypasses that allow inspect-only or non-forward capabilities to forward requests;
- validation gaps where undefined capabilities, malformed capability policy, or caller-supplied `response_format` can weaken enforcement;
- prompt-injection patterns that should be blocked or reviewed but are currently allowed;
- output guard bypasses for credentials, local paths, private hosts, or sensitive URL query strings;
- audit hash-chain verification failures;
- audit write-lock failures that can corrupt concurrent hash-chain writes;
- configuration validation gaps that make an unsafe deployment easy.

Out of scope:

- reports that require a malicious operator with full write access to the proxy configuration and runtime files;
- benchmark-only claims without a concrete bypass or reproducible corpus entry;
- attacks against the backend AI agent runtime when the proxy correctly blocks or strips the relevant input.

## Supported Versions

| Version | Supported |
| --- | --- |
| `v0.1.x` | Yes |
| `main` | Best-effort development branch |
| `< v0.1.0` | No |

Security fixes will normally land on `main` first and then be included in the next tagged release.
