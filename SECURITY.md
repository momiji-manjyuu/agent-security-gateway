# Security Policy

Agent Security Proxy is a defense-in-depth boundary, not a complete guarantee against prompt injection or data exfiltration.

## Reporting

Please report vulnerabilities privately through GitHub Security Advisories when possible. Avoid posting exploit details in public issues before there is a fix or mitigation.

If advisories are unavailable, open a minimal issue that says a private security report is needed without including secrets, tokens, live endpoints, or exploit payloads.

## Scope

Useful reports include:

- bypasses that allow caller-controlled `tools`, `tool_choice`, `stream`, or other unsafe OpenAI-compatible fields to reach the backend;
- prompt-injection patterns that should be blocked or reviewed but are currently allowed;
- output guard bypasses for credentials, local paths, private hosts, or sensitive URL query strings;
- audit hash-chain verification failures;
- configuration validation gaps that make an unsafe deployment easy.

Out of scope:

- reports that require a malicious operator with full write access to the proxy configuration and runtime files;
- benchmark-only claims without a concrete bypass or reproducible corpus entry;
- attacks against the backend AI agent runtime when the proxy correctly blocks or strips the relevant input.

## Supported Versions

The public `main` branch is the only supported version until tagged releases exist.
