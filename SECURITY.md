# Security Policy

Agent Security Gateway is a defense-in-depth policy boundary, not a complete guarantee against prompt injection, backend compromise, or data exfiltration.

## Reporting

Please report vulnerabilities privately through GitHub Security Advisories when possible. Avoid posting exploit details in public issues before there is a fix or mitigation.

If advisories are unavailable, open a minimal issue that says a private security report is needed without including secrets, tokens, live endpoints, or exploit payloads.

## Scope

Useful reports include:

- route resolution bypasses, route conflict bypasses, or fallback-to-default backend behavior;
- caller-controlled backend URL or backend credential injection;
- caller `Authorization` token forwarding to a backend;
- CIDR, capability, route, run-scope, taint, or caller allowlist bypasses;
- prompt-injection patterns that should be blocked or reviewed but are currently allowed;
- action guard bypasses for private URLs, metadata endpoints, secret exfiltration, external upload, package install, delete, email, social post, purchase, or release publish;
- output guard bypasses for credentials, local paths, private hosts, dangerous schemes, or sensitive URL query strings;
- audit hash-chain verification failures;
- audit write-lock failures that can corrupt concurrent hash-chain writes;
- configuration validation gaps that make unsafe deployment easy.

Out of scope:

- reports that require a malicious operator with full write access to gateway configuration and runtime files;
- benchmark-only claims without a concrete bypass or reproducible corpus entry;
- attacks against backend AI agent runtimes when the gateway correctly blocks or strips the relevant input;
- absence of TLS/VPN/mTLS, WORM storage, or host firewalling in the gateway process itself.

## Supported Versions

| Version | Supported |
| --- | --- |
| `v0.1.x` | Yes |
| `main` | Best-effort development branch |
| `< v0.1.0` | No |

Security fixes normally land on `main` first and then ship in the next tagged release.
