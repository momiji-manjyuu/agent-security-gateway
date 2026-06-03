#!/usr/bin/env python3
"""Agent Security Gateway.

Central policy gateway for multi-agent AI systems.  The gateway authenticates
callers, resolves route IDs to server-side backends, enforces route/run/taint
policy, scans input and output, and records append-only hash-chained audit logs.
"""

from __future__ import annotations

import argparse
import copy
import dataclasses
import datetime as dt
import hashlib
import hmac
import http.server
import ipaddress
import json
import os
import re
import secrets
import socket
import stat
import subprocess
import sys
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any

import proxy as security


APP_NAME = "agent-security-gateway"
VERSION = "0.1.0"
RUNTIME_DIR = Path.home() / ".agent-security-gateway"
DEFAULT_CONFIG_PATH = RUNTIME_DIR / "config.json"
DEFAULT_AUDIT_PATH = RUNTIME_DIR / "audit.jsonl"
DEFAULT_KILL_SWITCH = RUNTIME_DIR / "KILL_SWITCH"
DEFAULT_APPROVAL_STORE = RUNTIME_DIR / "approvals.jsonl"
MAX_TIMEOUT_SECONDS = 600
ROUTE_KINDS = {"inspect_only", "openai_chat_completions", "http_json", "command"}
PUBLIC_ROUTE_FIELDS = ("description", "kind", "required_capability", "allowed_capabilities", "aliases")
REPORT_POLICY_BOOL_FIELDS = {
    "forward_audit_receipt",
    "return_audit_receipt",
    "include_structured_extract",
    "notify_on_block",
}
NON_APPROVABLE_ACTION_CATEGORIES = {
    "caller_controlled_backend",
    "private_network_target",
    "metadata_endpoint",
    "dangerous_uri_scheme",
    "secret_exfiltration",
}
APPROVABLE_ACTION_CATEGORIES = {
    "host_package_install",
    "external_upload",
    "privileged_command",
    "delete_operation",
}
CALLER_BACKEND_FIELD_NAMES = {
    "target_url",
    "backend_url",
    "base_url",
    "upstream_url",
    "proxy_url",
    "target_endpoint",
    "backend_endpoint",
    "x-target-url",
}
RAW_EXTERNAL_CONTENT_KEYS = {
    "raw_content",
    "raw_html",
    "html",
    "body_html",
    "full_text",
    "page_text",
    "document_text",
    "source_text",
    "raw_document",
    "raw_page",
    "raw_markdown",
    "transcript_raw",
}
BATCH_SIZE_KEYS = {
    "batch_size",
    "n",
    "count",
    "num_images",
    "num_prompts",
    "samples",
}
BATCH_LIST_KEYS = {
    "prompts",
    "prompt_matrix",
    "items",
    "jobs",
    "requests",
}
SHELL_LIKE_PATTERN = re.compile(
    r"\b(?:curl|wget|bash|zsh|sh|sudo|rm\s+-rf|python\s+-c|pip\s+install|npm\s+install|apt(?:-get)?\s+install|brew\s+install)\b",
    re.IGNORECASE,
)
DEFENSIVE_SECRET_INSTRUCTION_PATTERN = re.compile(
    r"\b(?:do not|don't|never|must not|without)\b.{0,100}\b(?:show|print|dump|send|upload|reveal|disclose|share|include)\b.{0,100}\b(?:\.env|auth\.json|credentials?|secrets?|private key|api[_ -]?key|token|password)\b",
    re.IGNORECASE | re.DOTALL,
)
DANGEROUS_ACTION_PATTERNS: list[tuple[str, str, int, str]] = [
    ("secret_exfiltration", r"\b(read|open|cat|show|print|dump|send|upload)\b.{0,100}(\.env|id_rsa|credentials?|auth\.json|private key|api[_ -]?key|token)", 10, "secret exfiltration request"),
    ("curl_pipe_shell", r"\bcurl\b[^\n|]{0,200}\|\s*(sh|bash|zsh)\b", 10, "curl piped into a shell"),
    ("privileged_command", r"\bsudo\b", 9, "sudo is disallowed"),
    ("host_package_install", r"\b(apt|apt-get|brew|yum|dnf|pacman|pip|npm|pnpm|yarn)\s+(install|add)\b", 9, "host package install is disallowed"),
    ("external_upload", r"\b(upload|post|publish|send)\b.{0,80}\b(http|https|external|slack|discord|twitter|x\.com|github|gist|s3|drive)\b", 8, "external upload or publish is disallowed"),
    ("email_send", r"\b(email|mail|smtp)\b.{0,80}\b(send|deliver|forward)\b|\b(send|forward)\b.{0,80}\b(email|mail)\b", 8, "email sending is disallowed"),
    ("social_post", r"\b(tweet|post to|publish to)\b.{0,80}\b(x|twitter|sns|facebook|mastodon|linkedin|reddit)\b", 8, "social posting is disallowed"),
    ("purchase_payment", r"\b(purchase|buy|order|pay|payment|checkout|charge)\b", 9, "purchase or payment action is disallowed"),
    ("delete_operation", r"\b(rm\s+-rf|delete|remove|wipe|destroy)\b", 9, "destructive delete operation is disallowed"),
    ("git_publish", r"\bgit\s+(push|merge|tag)\b|\b(release|publish)\b.{0,40}\b(github|repo|package|artifact)\b", 8, "git push, merge, release, or publish is disallowed"),
]


def _scanner_defaults() -> dict[str, Any]:
    base = copy.deepcopy(security.DEFAULT_CONFIG)
    return {
        "block_risk_score": base["block_risk_score"],
        "review_risk_score": base["review_risk_score"],
        "review_policy": {"block_forward": False},
        "rate_limit": base["rate_limit"],
        "audit": base["audit"],
        "output_guard": base["output_guard"],
        "normalize": base["normalize"],
        "llm_inspector": base["llm_inspector"],
        "structured_extract": base["structured_extract"],
    }


DEFAULT_CONFIG: dict[str, Any] = {
    **_scanner_defaults(),
    "bind": "127.0.0.1",
    "port": 8788,
    "max_body_bytes": 524_288,
    "kill_switch_file": str(DEFAULT_KILL_SWITCH),
    "audit_log": str(DEFAULT_AUDIT_PATH),
    "approval_store": str(DEFAULT_APPROVAL_STORE),
    "backend_hmac_key_env": "ASG_BACKEND_HMAC_KEY",
    "require_known_run_id": False,
    "agents": {},
    "routes": {
        "security.inspect_only": {
            "kind": "inspect_only",
            "description": "Run gateway inspection without backend forwarding.",
            "aliases": ["asg/inspect-only"],
            "allowed_callers": ["*"],
            "required_capability": "inspect",
            "input_policy": {
                "accepted_taint": [
                    "trusted_instruction",
                    "untrusted_web",
                    "untrusted_pdf",
                    "untrusted_github",
                    "sandbox_output",
                    "model_output",
                    "human_approved",
                    "reviewed_untrusted_summary",
                    "reviewed_prompt_matrix",
                    "promoted_knowledge",
                ],
                "allow_missing_taint": True,
            },
            "output_policy": {
                "block_secrets": True,
                "block_private_urls": True,
                "block_internal_paths": True,
            },
        },
        "security.approvals.create": {
            "kind": "inspect_only",
            "description": "Create a human/operator approval artifact for a target agent action.",
            "aliases": ["asg/approvals-create"],
            "allowed_callers": ["human_operator"],
            "required_capability": "approve_action",
            "input_policy": {
                "accepted_taint": ["human_approved"],
                "allow_missing_taint": True,
            },
            "output_policy": {
                "block_secrets": True,
                "block_private_urls": True,
                "block_internal_paths": True,
            },
        },
    },
    "runs": {},
}


class GatewayError(Exception):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


@dataclasses.dataclass
class VerifiedAgent:
    agent_id: str
    agent: dict[str, Any]


@dataclasses.dataclass
class RouteDecision:
    route_id: str
    route: dict[str, Any]
    capability: str
    run_id: str | None
    task_id: str | None
    taint: list[str]
    warnings: list[str]


@dataclasses.dataclass
class ActionGuardResult:
    normalized_action_hash: str
    findings: list[security.Finding]

    @property
    def blocked(self) -> bool:
        return bool(self.findings)

    def public_dict(self) -> dict[str, Any]:
        return {
            "normalized_action_hash": self.normalized_action_hash,
            "findings": [dataclasses.asdict(finding) for finding in self.findings],
            "blocked": self.blocked,
        }


def deep_update(base: dict[str, Any], override: dict[str, Any]) -> None:
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            deep_update(base[key], value)
        else:
            base[key] = value


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def hash_token(token: str) -> str:
    return sha256_text(token)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def expand_path(value: str | os.PathLike[str]) -> Path:
    return Path(value).expanduser()


def load_config(path: Path) -> dict[str, Any]:
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    if path.exists():
        with path.open("r", encoding="utf-8") as fh:
            user_cfg = json.load(fh)
        if not isinstance(user_cfg, dict):
            raise ValueError("config must be a JSON object")
        deep_update(cfg, user_cfg)
    validate_config(cfg)
    return cfg


def parse_int(value: Any, *, default: int) -> tuple[int, bool]:
    try:
        return int(value), True
    except (TypeError, ValueError):
        return default, False


def validate_config(cfg: dict[str, Any]) -> None:
    errors: list[str] = []
    bind = str(cfg.get("bind", ""))
    if not bind:
        errors.append("bind must be a non-empty string")
    if bind in {"0.0.0.0", "::"} and not bool(cfg.get("allow_public_bind", False)):
        errors.append("bind uses a wildcard address; set allow_public_bind=true only behind a TLS/VPN boundary")
    port, port_ok = parse_int(cfg.get("port"), default=8788)
    if not port_ok or not 1 <= port <= 65_535:
        errors.append("port must be between 1 and 65535")
    max_body, max_body_ok = parse_int(cfg.get("max_body_bytes"), default=524_288)
    if not max_body_ok or max_body <= 0:
        errors.append("max_body_bytes must be a positive integer")

    agents = cfg.get("agents")
    routes = cfg.get("routes")
    runs = cfg.get("runs")
    if not isinstance(agents, dict):
        errors.append("agents must be an object")
        agents = {}
    if not isinstance(routes, dict) or not routes:
        errors.append("routes must be a non-empty object")
        routes = {}
    if runs is not None and not isinstance(runs, dict):
        errors.append("runs must be an object")

    alias_to_route: dict[str, str] = {}
    route_required_capabilities: set[str] = set()
    for route_id, route in routes.items():
        if not isinstance(route_id, str) or not route_id.strip():
            errors.append("route IDs must be non-empty strings")
            continue
        if not isinstance(route, dict):
            errors.append(f"routes.{route_id} must be an object")
            continue
        kind = str(route.get("kind", ""))
        if kind not in ROUTE_KINDS:
            errors.append(f"routes.{route_id}.kind must be one of {sorted(ROUTE_KINDS)}")
        required_capability = route.get("required_capability")
        if not isinstance(required_capability, str) or not required_capability.strip():
            errors.append(f"routes.{route_id}.required_capability must be a non-empty string")
        else:
            route_required_capabilities.add(required_capability)
        allowed_capabilities = route.get("allowed_capabilities") or []
        if "allowed_capabilities" in route and not isinstance(allowed_capabilities, list):
            errors.append(f"routes.{route_id}.allowed_capabilities must be an array")
            allowed_capabilities = []
        for capability in allowed_capabilities:
            if isinstance(capability, str) and capability.strip():
                route_required_capabilities.add(capability)
            else:
                errors.append(f"routes.{route_id}.allowed_capabilities must contain non-empty strings")
        aliases = route.get("aliases") or []
        if "aliases" in route and not isinstance(aliases, list):
            errors.append(f"routes.{route_id}.aliases must be an array")
            aliases = []
        for alias in aliases:
            if not isinstance(alias, str) or not alias.strip():
                errors.append(f"routes.{route_id}.aliases must contain non-empty strings")
                continue
            if alias in alias_to_route and alias_to_route[alias] != route_id:
                errors.append(f"route alias {alias!r} is defined by both {alias_to_route[alias]} and {route_id}")
            alias_to_route[alias] = route_id
        allowed_callers = route.get("allowed_callers", [])
        if not isinstance(allowed_callers, list) or not allowed_callers:
            errors.append(f"routes.{route_id}.allowed_callers must be a non-empty array")
        elif not all(isinstance(item, str) and item.strip() for item in allowed_callers):
            errors.append(f"routes.{route_id}.allowed_callers must contain non-empty strings")
        input_policy = route.get("input_policy", {})
        if input_policy is not None and not isinstance(input_policy, dict):
            errors.append(f"routes.{route_id}.input_policy must be an object")
        report_policy = route.get("report_policy", {})
        if report_policy is not None and not isinstance(report_policy, dict):
            errors.append(f"routes.{route_id}.report_policy must be an object")
            report_policy = {}
        if isinstance(report_policy, dict):
            for field in REPORT_POLICY_BOOL_FIELDS:
                if field in report_policy and not isinstance(report_policy.get(field), bool):
                    errors.append(f"routes.{route_id}.report_policy.{field} must be a boolean")
            if report_policy.get("forward_audit_receipt") and kind not in {"http_json", "openai_chat_completions"}:
                errors.append(f"routes.{route_id}.report_policy.forward_audit_receipt requires kind 'http_json' or 'openai_chat_completions'")
        backend = route.get("backend", {})
        if kind != "inspect_only":
            if not isinstance(backend, dict):
                errors.append(f"routes.{route_id}.backend must be an object")
            else:
                mode = str(backend.get("mode", "http"))
                if mode not in {"http", "command"}:
                    errors.append(f"routes.{route_id}.backend.mode must be 'http' or 'command'")
                if kind == "command" or mode == "command":
                    if not bool(route.get("enabled", backend.get("enabled", False))):
                        errors.append(f"routes.{route_id} command routes must set enabled=true explicitly")
                if mode == "http":
                    base_url = str(backend.get("base_url", ""))
                    parsed = urllib.parse.urlsplit(base_url)
                    if parsed.scheme not in {"http", "https", "mock"} or not (parsed.netloc or parsed.scheme == "mock"):
                        errors.append(f"routes.{route_id}.backend.base_url must be an absolute http(s) URL")
                    method = str(backend.get("method", "POST")).upper()
                    if kind == "http_json" and method != "POST":
                        errors.append(f"routes.{route_id}.backend.method must be POST")
                timeout, timeout_ok = parse_int(backend.get("timeout_seconds", 180), default=180)
                if not timeout_ok or not 1 <= timeout <= MAX_TIMEOUT_SECONDS:
                    errors.append(f"routes.{route_id}.backend.timeout_seconds must be between 1 and {MAX_TIMEOUT_SECONDS}")

    for agent_id, agent in agents.items():
        if not isinstance(agent_id, str) or not agent_id.strip():
            errors.append("agent IDs must be non-empty strings")
            continue
        if not isinstance(agent, dict):
            errors.append(f"agents.{agent_id} must be an object")
            continue
        token_hash = str(agent.get("token_sha256", ""))
        if token_hash and not re.fullmatch(r"[a-fA-F0-9]{64}", token_hash):
            errors.append(f"agents.{agent_id}.token_sha256 must be a 64-character SHA-256 hex digest")
        allowed_capabilities = agent.get("allowed_capabilities", [])
        if not isinstance(allowed_capabilities, list):
            errors.append(f"agents.{agent_id}.allowed_capabilities must be an array")
            allowed_capabilities = []
        for capability in allowed_capabilities:
            if not isinstance(capability, str) or not capability.strip():
                errors.append(f"agents.{agent_id}.allowed_capabilities must contain non-empty strings")
        allowed_routes = agent.get("allowed_routes", [])
        if not isinstance(allowed_routes, list):
            errors.append(f"agents.{agent_id}.allowed_routes must be an array")
            allowed_routes = []
        for route_id in allowed_routes:
            if route_id not in routes:
                errors.append(f"agents.{agent_id}.allowed_routes references undefined route: {route_id}")
        for cidr in agent.get("allowed_client_cidrs") or []:
            try:
                ipaddress.ip_network(str(cidr), strict=False)
            except ValueError:
                errors.append(f"agents.{agent_id}.allowed_client_cidrs contains invalid CIDR: {cidr}")

    if isinstance(runs, dict):
        for run_id, run in runs.items():
            if not isinstance(run, dict):
                errors.append(f"runs.{run_id} must be an object")
                continue
            for field in ("allowed_routes", "denied_routes"):
                values = run.get(field, [])
                if values and not isinstance(values, list):
                    errors.append(f"runs.{run_id}.{field} must be an array")
                elif isinstance(values, list):
                    for route_id in values:
                        if route_id not in routes:
                            errors.append(f"runs.{run_id}.{field} references undefined route: {route_id}")
            if "expires_at" in run:
                try:
                    parse_datetime(str(run["expires_at"]))
                except ValueError:
                    errors.append(f"runs.{run_id}.expires_at must be an ISO-8601 datetime")

    if errors:
        raise ValueError("invalid config: " + "; ".join(errors))


def parse_datetime(value: str) -> dt.datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = dt.datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def json_error(code: str, message: str, request_id: str) -> dict[str, Any]:
    return {"error": {"code": code, "message": message, "request_id": request_id}}


def metadata(payload: dict[str, Any]) -> dict[str, Any]:
    value = payload.get("metadata")
    return value if isinstance(value, dict) else {}


def header_value(headers: Any, name: str) -> str:
    value = headers.get(name)
    return value.strip() if isinstance(value, str) and value.strip() else ""


def client_allowed(client_ip: str, agent: dict[str, Any]) -> bool:
    allowed = agent.get("allowed_client_cidrs") or []
    if not allowed:
        return True
    try:
        ip = ipaddress.ip_address(client_ip)
    except ValueError:
        return False
    for cidr in allowed:
        try:
            if ip in ipaddress.ip_network(str(cidr), strict=False):
                return True
        except ValueError:
            continue
    return False


def verify_agent(headers: Any, cfg: dict[str, Any], client_ip: str) -> VerifiedAgent:
    auth = headers.get("Authorization", "")
    if not isinstance(auth, str) or not auth.startswith("Bearer "):
        raise GatewayError(401, "unauthorized", "missing bearer token")
    token = auth.removeprefix("Bearer ").strip()
    token_hash = hash_token(token)
    for agent_id, agent in (cfg.get("agents") or {}).items():
        if not isinstance(agent, dict):
            continue
        configured_hash = str(agent.get("token_sha256", ""))
        if configured_hash and hmac.compare_digest(configured_hash, token_hash):
            if not client_allowed(client_ip, agent):
                raise GatewayError(403, "client_ip_denied", f"client IP is not allowed for agent '{agent_id}'")
            return VerifiedAgent(str(agent_id), agent)
    raise GatewayError(401, "unauthorized", "unknown bearer token")


def route_alias_map(cfg: dict[str, Any]) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for route_id, route in (cfg.get("routes") or {}).items():
        for alias in route.get("aliases") or []:
            aliases[str(alias)] = str(route_id)
    return aliases


def resolve_capability(headers: Any, payload: dict[str, Any], *, inspect_default: bool = False) -> str:
    header = header_value(headers, "X-Agent-Capability")
    meta = metadata(payload)
    meta_value = meta.get("capability")
    top_value = payload.get("capability")
    capability = header
    if not capability and isinstance(meta_value, str):
        capability = meta_value.strip()
    if not capability and isinstance(top_value, str):
        capability = top_value.strip()
    if not capability and inspect_default:
        capability = "inspect"
    if not capability:
        raise GatewayError(400, "capability_required", "capability is required")
    return capability


def resolve_optional_id(headers: Any, payload: dict[str, Any], header_name: str, metadata_name: str) -> str | None:
    header = header_value(headers, header_name)
    meta = metadata(payload)
    value = header
    if not value and isinstance(meta.get(metadata_name), str):
        value = meta[metadata_name].strip()
    if not value and isinstance(payload.get(metadata_name), str):
        value = payload[metadata_name].strip()
    return value or None


def resolve_taint(payload: dict[str, Any]) -> list[str]:
    value: Any = metadata(payload).get("taint")
    if value is None:
        value = payload.get("taint")
    if value is None:
        return []
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list) or not all(isinstance(item, str) and item.strip() for item in value):
        raise GatewayError(400, "taint_denied", "taint must be an array of non-empty strings")
    result: list[str] = []
    for item in value:
        if item not in result:
            result.append(item.strip())
    return result


def route_from_sources(headers: Any, payload: dict[str, Any], cfg: dict[str, Any]) -> tuple[str, list[str]]:
    warnings: list[str] = []
    aliases = route_alias_map(cfg)
    meta = metadata(payload)
    header_route = header_value(headers, "X-ASG-Route")
    metadata_route = meta.get("route_id") if isinstance(meta.get("route_id"), str) else ""
    top_route = payload.get("route_id") if isinstance(payload.get("route_id"), str) else ""
    model = payload.get("model") if isinstance(payload.get("model"), str) else ""
    explicit = [value.strip() for value in (header_route, metadata_route, top_route) if value and value.strip()]
    for left, right in zip(explicit, explicit[1:]):
        if left != right:
            raise GatewayError(400, "route_conflict", "multiple route IDs were supplied and do not match")
    explicit_route = explicit[0] if explicit else ""

    alias_route = ""
    if model:
        if model in aliases:
            alias_route = aliases[model]
        elif model.startswith("asg/"):
            raise GatewayError(400, "unknown_route_alias", f"unknown route alias '{model}'")
    if explicit_route and alias_route and explicit_route != alias_route:
        raise GatewayError(400, "route_conflict", "model alias resolves to a different route")
    route_id = explicit_route or alias_route
    if not route_id:
        raise GatewayError(400, "route_required", "route_id is required")
    if route_id not in (cfg.get("routes") or {}):
        raise GatewayError(404, "unknown_route", f"unknown route '{route_id}'")
    if model and not alias_route and explicit_route:
        warnings.append("model_not_used_for_routing")
    return route_id, warnings


def resolve_route_decision(headers: Any, payload: dict[str, Any], cfg: dict[str, Any]) -> RouteDecision:
    capability = resolve_capability(headers, payload)
    route_id, warnings = route_from_sources(headers, payload, cfg)
    route = cfg["routes"][route_id]
    return RouteDecision(
        route_id=route_id,
        route=route,
        capability=capability,
        run_id=resolve_optional_id(headers, payload, "X-ASG-Run-Id", "run_id"),
        task_id=resolve_optional_id(headers, payload, "X-ASG-Task-Id", "task_id"),
        taint=resolve_taint(payload),
        warnings=warnings,
    )


def enforce_route_policy(verified: VerifiedAgent, decision: RouteDecision, cfg: dict[str, Any]) -> None:
    agent = verified.agent
    route = decision.route
    capability = decision.capability
    allowed_capabilities = set(str(item) for item in agent.get("allowed_capabilities") or [])
    if capability not in allowed_capabilities:
        raise GatewayError(403, "capability_denied", f"capability '{capability}' is not allowed for agent '{verified.agent_id}'")

    allowed_routes = set(str(item) for item in agent.get("allowed_routes") or [])
    if decision.route_id not in allowed_routes:
        raise GatewayError(403, "route_denied", f"route '{decision.route_id}' is not allowed for agent '{verified.agent_id}'")

    allowed_callers = set(str(item) for item in route.get("allowed_callers") or [])
    if "*" not in allowed_callers and verified.agent_id not in allowed_callers:
        raise GatewayError(403, "caller_not_allowed", f"agent '{verified.agent_id}' is not allowed to call route '{decision.route_id}'")

    route_capabilities = set(str(item) for item in route.get("allowed_capabilities") or [])
    required = str(route.get("required_capability", ""))
    if capability != required and capability not in route_capabilities:
        raise GatewayError(403, "capability_denied", f"route '{decision.route_id}' requires capability '{required}'")

    enforce_run_scope(decision, cfg)
    enforce_taint_policy(decision)


def enforce_run_scope(decision: RouteDecision, cfg: dict[str, Any]) -> None:
    route = decision.route
    run_id = decision.run_id
    if route.get("require_run_id") and not run_id:
        raise GatewayError(403, "run_scope_denied", f"route '{decision.route_id}' requires run_id")
    if not run_id:
        return
    runs = cfg.get("runs") or {}
    run = runs.get(run_id)
    if run is None:
        if cfg.get("require_known_run_id"):
            raise GatewayError(403, "run_scope_denied", f"unknown run_id '{run_id}'")
        decision.warnings.append("unknown_run_id_allowed")
        return
    if not isinstance(run, dict):
        raise GatewayError(403, "run_scope_denied", f"run_id '{run_id}' has invalid policy")
    if "expires_at" in run and parse_datetime(str(run["expires_at"])) < dt.datetime.now(dt.timezone.utc):
        raise GatewayError(403, "run_expired", f"run_id '{run_id}' is expired")
    denied_routes = set(str(item) for item in run.get("denied_routes") or [])
    if decision.route_id in denied_routes:
        raise GatewayError(403, "run_scope_denied", f"run_id '{run_id}' denies route '{decision.route_id}'")
    allowed_routes = set(str(item) for item in run.get("allowed_routes") or [])
    if allowed_routes and decision.route_id not in allowed_routes:
        raise GatewayError(403, "run_scope_denied", f"run_id '{run_id}' does not allow route '{decision.route_id}'")


def enforce_taint_policy(decision: RouteDecision) -> None:
    policy = decision.route.get("input_policy", {})
    if not isinstance(policy, dict):
        raise GatewayError(403, "taint_denied", "route input_policy is invalid")
    if not decision.taint:
        if policy.get("allow_missing_taint"):
            return
        raise GatewayError(403, "taint_denied", f"route '{decision.route_id}' requires taint metadata")
    accepted = set(str(item) for item in policy.get("accepted_taint") or [])
    rejected = [taint for taint in decision.taint if taint not in accepted]
    if rejected:
        raise GatewayError(403, "taint_denied", f"route '{decision.route_id}' does not accept taint: {', '.join(rejected)}")


def payload_message_type(payload: dict[str, Any]) -> str:
    meta = metadata(payload)
    value = payload.get("message_type")
    if isinstance(value, str) and value.strip():
        return value.strip()
    meta_value = meta.get("message_type")
    return meta_value.strip() if isinstance(meta_value, str) and meta_value.strip() else ""


def enforce_input_policy(payload: dict[str, Any], decision: RouteDecision) -> None:
    policy = decision.route.get("input_policy", {})
    if not isinstance(policy, dict):
        raise GatewayError(403, "input_policy_denied", "route input_policy is invalid")

    if "max_messages" in policy:
        max_messages, ok = parse_int(policy.get("max_messages"), default=0)
        if not ok or max_messages < 0:
            raise GatewayError(403, "input_policy_denied", "route max_messages policy is invalid")
        messages = payload.get("messages")
        if isinstance(messages, list) and len(messages) > max_messages:
            raise GatewayError(403, "input_policy_denied", f"route allows at most {max_messages} messages")

    required_message_type = policy.get("require_message_type")
    if isinstance(required_message_type, str) and required_message_type.strip():
        if payload_message_type(payload) != required_message_type.strip():
            raise GatewayError(403, "input_policy_denied", f"route requires message_type '{required_message_type.strip()}'")

    if policy.get("require_structured_task"):
        if not structured_task_allowed(payload):
            raise GatewayError(403, "input_policy_denied", "route requires a structured task packet")

    if policy.get("allow_raw_external_content") is False:
        for path, _ in recursive_items(payload):
            key = path.rsplit(".", 1)[-1]
            if "[" in key:
                key = key.rsplit("[", 1)[0]
            if key.lower() in RAW_EXTERNAL_CONTENT_KEYS:
                raise GatewayError(403, "input_policy_denied", f"raw external content field is not allowed: {key}")

    if policy.get("disallow_external_urls"):
        for _, value in recursive_items(payload):
            if isinstance(value, str) and security.URL_PATTERN.search(value):
                raise GatewayError(403, "input_policy_denied", "external URLs are not allowed on this route")

    if "max_batch_size" in policy:
        max_batch_size, ok = parse_int(policy.get("max_batch_size"), default=0)
        if not ok or max_batch_size < 1:
            raise GatewayError(403, "input_policy_denied", "route max_batch_size policy is invalid")
        enforce_batch_size_policy(payload, max_batch_size)

    if policy.get("forbid_shell_from_chat") or decision.route.get("action_policy", {}).get("forbid_shell_from_chat"):
        if chat_messages_contain_shell(payload):
            raise GatewayError(403, "input_policy_denied", "shell-like commands in chat messages are not allowed on this route")


def structured_task_allowed(payload: dict[str, Any]) -> bool:
    task = payload.get("task")
    if isinstance(task, dict):
        objective = task.get("objective")
        if not isinstance(objective, str) or not objective.strip():
            return False
        if "constraints" in task and not isinstance(task.get("constraints"), dict):
            return False
        if "output_contract" in task and not isinstance(task.get("output_contract"), dict):
            return False
        return True
    return payload_message_type(payload) == "task_instruction" and isinstance(payload.get("messages"), list)


def enforce_batch_size_policy(payload: dict[str, Any], max_batch_size: int) -> None:
    for path, value in recursive_items(payload):
        key = path.rsplit(".", 1)[-1].lower()
        if "[" in key:
            key = key.rsplit("[", 1)[0]
        if key in BATCH_SIZE_KEYS:
            if isinstance(value, bool):
                raise GatewayError(403, "input_policy_denied", f"batch size field must be an integer: {key}")
            number, ok = parse_int(value, default=0)
            if not ok:
                raise GatewayError(403, "input_policy_denied", f"batch size field must be an integer: {key}")
            if number > max_batch_size:
                raise GatewayError(403, "input_policy_denied", f"batch size exceeds route maximum {max_batch_size}")
        if key in BATCH_LIST_KEYS and isinstance(value, list) and len(value) > max_batch_size:
            raise GatewayError(403, "input_policy_denied", f"batch list exceeds route maximum {max_batch_size}")


def chat_messages_contain_shell(payload: dict[str, Any]) -> bool:
    messages = payload.get("messages")
    if not isinstance(messages, list):
        return False
    for message in messages:
        if not isinstance(message, dict):
            continue
        text = security.content_to_text(message.get("content"))
        if SHELL_LIKE_PATTERN.search(text):
            return True
    return False


def scan_inbound(payload: dict[str, Any], cfg: dict[str, Any]) -> security.InboundScan:
    return security.scan_inbound_payload(payload, cfg)


def route_input_policy(decision: RouteDecision) -> dict[str, Any]:
    policy = decision.route.get("input_policy", {})
    return policy if isinstance(policy, dict) else {}


def normalized_allowed_private_instruction_hosts(decision: RouteDecision) -> set[str]:
    hosts = route_input_policy(decision).get("allowed_private_instruction_hosts") or []
    if not isinstance(hosts, list):
        return set()
    return {str(host).lower().strip().strip("[]") for host in hosts if str(host).strip()}


def private_url_hosts(text: str) -> set[str]:
    hosts: set[str] = set()
    for match in security.URL_PATTERN.finditer(text):
        parsed = urllib.parse.urlsplit(match.group(0))
        host = (parsed.hostname or "").lower().strip("[]")
        if host and is_private_host(host):
            hosts.add(host)
    return hosts


def route_allows_private_instruction_hosts(decision: RouteDecision, text: str) -> bool:
    allowed = normalized_allowed_private_instruction_hosts(decision)
    if not allowed:
        return False
    private_hosts = private_url_hosts(text)
    return bool(private_hosts) and private_hosts.issubset(allowed)


def route_allows_defensive_secret_instruction(decision: RouteDecision, text: str) -> bool:
    return bool(route_input_policy(decision).get("allow_defensive_secret_instructions")) and bool(DEFENSIVE_SECRET_INSTRUCTION_PATTERN.search(text))


def route_allows_input_finding(decision: RouteDecision, finding: security.Finding, text: str) -> bool:
    policy = route_input_policy(decision)
    allowed = policy.get("allow_scanner_findings") or []
    if isinstance(allowed, list) and finding.category in {str(item) for item in allowed}:
        return True
    if finding.category == "input_dlp:private_host":
        return route_allows_private_instruction_hosts(decision, text)
    if finding.category in {
        "prompt_injection:secret_exfiltration",
        "prompt_injection:local_secret_file_request",
        "prompt_injection:ja_secret_exfiltration",
    }:
        return route_allows_defensive_secret_instruction(decision, text)
    return False


def apply_route_inbound_scan_policy(inbound: security.InboundScan, decision: RouteDecision, cfg: dict[str, Any]) -> security.InboundScan:
    kept: list[security.Finding] = []
    ignored_categories: list[str] = []
    for finding in inbound.scan.findings:
        if route_allows_input_finding(decision, finding, inbound.extracted_text):
            ignored_categories.append(finding.category)
            continue
        kept.append(finding)
    if len(kept) == len(inbound.scan.findings):
        return inbound
    inbound.scan.findings = kept
    inbound.scan.risk_score = sum(finding.severity for finding in kept)
    inbound.scan.blocked = inbound.scan.risk_score >= int(cfg.get("block_risk_score", 8))
    inbound.scan.requires_review = inbound.scan.risk_score >= int(cfg.get("review_risk_score", 4))
    for category in sorted(set(ignored_categories)):
        decision.warnings.append("route_ignored_input_finding:" + category)
    return inbound


def scan_inbound_for_route(payload: dict[str, Any], cfg: dict[str, Any], decision: RouteDecision) -> security.InboundScan:
    return apply_route_inbound_scan_policy(scan_inbound(payload, cfg), decision, cfg)


def recursive_items(value: Any, path: str = "$") -> list[tuple[str, Any]]:
    items: list[tuple[str, Any]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            items.append((child_path, child))
            items.extend(recursive_items(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            child_path = f"{path}[{index}]"
            items.append((child_path, child))
            items.extend(recursive_items(child, child_path))
    return items


def is_private_host(host: str) -> bool:
    host = host.lower().strip("[]")
    if host in {"localhost", "localhost.localdomain"}:
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast
    except ValueError:
        return False


def action_guard(headers: Any, payload: dict[str, Any]) -> ActionGuardResult:
    findings: list[security.Finding] = []
    content = security.extract_content(payload)
    control_text = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    normalized, _ = security.normalize_untrusted_text(content + "\n" + control_text, DEFAULT_CONFIG)

    if header_value(headers, "X-Target-URL"):
        findings.append(security.Finding("action_guard:caller_controlled_backend", 10, "X-Target-URL is not allowed"))

    for path, value in recursive_items(payload):
        key = path.rsplit(".", 1)[-1].lower()
        if key in CALLER_BACKEND_FIELD_NAMES:
            findings.append(security.Finding("action_guard:caller_controlled_backend", 10, f"{key} is not allowed"))
        if isinstance(value, str):
            lowered = value.lower()
            if re.match(r"^(file|data|javascript|smb)[:/]", lowered):
                findings.append(security.Finding("action_guard:dangerous_uri_scheme", 10, "dangerous URI scheme is not allowed"))

    if security.DANGEROUS_URI_PATTERN.search(normalized):
        findings.append(security.Finding("action_guard:dangerous_uri_scheme", 10, "dangerous URI scheme is not allowed"))

    for match in security.URL_PATTERN.finditer(normalized):
        parsed = urllib.parse.urlsplit(match.group(0))
        if parsed.hostname and is_private_host(parsed.hostname):
            findings.append(security.Finding("action_guard:private_network_target", 10, "private, loopback, or metadata URL target is not allowed"))
        if parsed.hostname and parsed.hostname.strip("[]") == "169.254.169.254":
            findings.append(security.Finding("action_guard:metadata_endpoint", 10, "cloud metadata endpoint is not allowed"))

    for category, pattern, severity, detail in DANGEROUS_ACTION_PATTERNS:
        if re.search(pattern, normalized, flags=re.IGNORECASE | re.DOTALL):
            findings.append(security.Finding("action_guard:" + category, severity, detail))

    deduped: list[security.Finding] = []
    seen: set[tuple[str, str]] = set()
    for finding in findings:
        key = (finding.category, finding.detail)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return ActionGuardResult("sha256:" + sha256_text(normalized), deduped)


def route_allows_action_finding(decision: RouteDecision, finding: security.Finding, text: str) -> bool:
    policy = route_input_policy(decision)
    allowed = policy.get("allow_action_guard_findings") or []
    if isinstance(allowed, list) and finding.category in {str(item) for item in allowed}:
        return True
    if finding.category == "action_guard:private_network_target":
        return route_allows_private_instruction_hosts(decision, text)
    if finding.category == "action_guard:secret_exfiltration":
        return route_allows_defensive_secret_instruction(decision, text)
    return False


def apply_route_action_guard_policy(result: ActionGuardResult, decision: RouteDecision, payload: dict[str, Any]) -> ActionGuardResult:
    text = security.extract_content(payload) + "\n" + json.dumps(payload, ensure_ascii=False, sort_keys=True)
    kept: list[security.Finding] = []
    ignored_categories: list[str] = []
    for finding in result.findings:
        if route_allows_action_finding(decision, finding, text):
            ignored_categories.append(finding.category)
            continue
        kept.append(finding)
    if len(kept) == len(result.findings):
        return result
    for category in sorted(set(ignored_categories)):
        decision.warnings.append("route_ignored_action_finding:" + category)
    return ActionGuardResult(result.normalized_action_hash, kept)


def approval_store_path(cfg: dict[str, Any]) -> Path:
    return expand_path(str(cfg.get("approval_store", DEFAULT_APPROVAL_STORE)))


def approval_record_valid(
    record: dict[str, Any],
    decision: RouteDecision,
    verified: VerifiedAgent,
    action_hash: str,
    required_categories: set[str],
) -> bool:
    if not isinstance(record.get("approver_agent_id"), str) or not record.get("approver_agent_id", "").strip():
        return False
    if record.get("target_agent_id") != verified.agent_id:
        return False
    if record.get("target_route_id") != decision.route_id:
        return False
    if record.get("target_capability") != decision.capability:
        return False
    if record.get("normalized_action_hash") != action_hash:
        return False
    approved = record.get("approved_categories")
    if not isinstance(approved, list) or not approved or not all(isinstance(item, str) and item.strip() for item in approved):
        return False
    if not required_categories.issubset({str(item).strip() for item in approved}):
        return False
    try:
        if parse_datetime(str(record.get("expires_at"))) < dt.datetime.now(dt.timezone.utc):
            return False
    except (TypeError, ValueError):
        return False
    return True


def has_approval(
    cfg: dict[str, Any],
    decision: RouteDecision,
    verified: VerifiedAgent,
    action_hash: str,
    required_categories: set[str],
) -> bool:
    path = approval_store_path(cfg)
    if not path.exists():
        return False
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(record, dict) and approval_record_valid(record, decision, verified, action_hash, required_categories):
                return True
    return False


def enforce_action_guard(
    cfg: dict[str, Any],
    decision: RouteDecision,
    verified: VerifiedAgent,
    result: ActionGuardResult,
) -> None:
    if not result.blocked:
        return
    policy = decision.route.get("action_policy", {})
    approval_categories = {str(item) for item in policy.get("approval_required_for", [])} if isinstance(policy, dict) else set()
    finding_keys = {finding.category.removeprefix("action_guard:") for finding in result.findings}
    if finding_keys & NON_APPROVABLE_ACTION_CATEGORIES:
        raise GatewayError(403, "blocked_by_action_guard", "request contains a non-approvable action guard finding")

    approvable_findings = finding_keys & APPROVABLE_ACTION_CATEGORIES
    unknown_findings = finding_keys - NON_APPROVABLE_ACTION_CATEGORIES - APPROVABLE_ACTION_CATEGORIES
    if unknown_findings:
        raise GatewayError(403, "blocked_by_action_guard", "request contains an unknown action guard finding")
    if not approvable_findings:
        raise GatewayError(403, "blocked_by_action_guard", "request was blocked by action guard")
    if not approvable_findings.issubset(approval_categories):
        raise GatewayError(403, "blocked_by_action_guard", "route does not allow approval for this action category")
    if has_approval(cfg, decision, verified, result.normalized_action_hash, approvable_findings):
        return
    raise GatewayError(403, "approval_required", "action requires a matching approval artifact")


def backend_headers(
    cfg: dict[str, Any],
    decision: RouteDecision,
    verified: VerifiedAgent,
    body: bytes,
    backend: dict[str, Any],
    backend_path: str,
) -> dict[str, str]:
    body_sha256 = hashlib.sha256(body).hexdigest()
    timestamp = utc_now()
    headers = {
        "Content-Type": "application/json",
        "X-ASG-Agent-Id": verified.agent_id,
        "X-ASG-Route-Id": decision.route_id,
        "X-ASG-Request-SHA256": body_sha256,
        "X-ASG-Timestamp": timestamp,
    }
    if decision.run_id:
        headers["X-ASG-Run-Id"] = decision.run_id
    if decision.task_id:
        headers["X-ASG-Task-Id"] = decision.task_id
    api_key_env = str(backend.get("api_key_env", "") or "")
    api_key = os.environ.get(api_key_env, "") if api_key_env else ""
    if api_key:
        headers["Authorization"] = "Bearer " + api_key
    hmac_env = str(cfg.get("backend_hmac_key_env", "") or "")
    hmac_key = os.environ.get(hmac_env, "") if hmac_env else ""
    if hmac_key:
        canonical = "\n".join(
            [
                "POST",
                backend_path or "/",
                body_sha256,
                headers["X-ASG-Agent-Id"],
                headers["X-ASG-Route-Id"],
                headers.get("X-ASG-Run-Id", ""),
                headers.get("X-ASG-Task-Id", ""),
                timestamp,
            ]
        )
        signature = hmac.new(hmac_key.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()
        headers["X-ASG-Signature"] = "sha256=" + signature
    return headers


def backend_url(backend: dict[str, Any], default_path: str) -> str:
    base_url = str(backend.get("base_url", "")).rstrip("/")
    path = str(backend.get("path", default_path) or default_path)
    if not path.startswith("/"):
        path = "/" + path
    return base_url + path


def audit_receipt_chat_messages(receipt: dict[str, Any]) -> list[dict[str, str]]:
    allowed_fields = (
        "receipt_type",
        "ok",
        "decision",
        "reason",
        "request_id",
        "agent_id",
        "route_id",
        "route_kind",
        "capability",
        "run_id",
        "task_id",
        "taint",
        "warnings",
        "content_sha256",
        "content_length",
        "scan",
        "action_guard",
        "delivery",
    )
    summary = {field: receipt.get(field) for field in allowed_fields if field in receipt}
    content = (
        "Agent Security Gateway received a worker completion report. "
        "Raw worker report content was not forwarded. Treat this as audit metadata only.\n"
        + json.dumps(summary, ensure_ascii=False, sort_keys=True)
    )
    return [{"role": "user", "content": content}]


def build_openai_backend_payload(payload: dict[str, Any], decision: RouteDecision) -> dict[str, Any]:
    backend = decision.route.get("backend", {})
    messages = payload.get("messages")
    if payload.get("receipt_type") == "asg_result_audit":
        messages = audit_receipt_chat_messages(payload)
    if not isinstance(messages, list):
        messages = [{"role": "user", "content": security.content_to_text(payload.get("input", payload))}]
    model = backend.get("model_rewrite") or backend.get("model") or decision.route_id
    body: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "stream": False,
        "metadata": {
            "asg_route_id": decision.route_id,
            "asg_run_id": decision.run_id,
            "asg_task_id": decision.task_id,
            "asg_taint": decision.taint,
        },
    }
    for field in ("temperature", "top_p", "max_tokens", "user"):
        if field in payload:
            body[field] = payload[field]
    max_tokens = backend.get("max_tokens")
    if isinstance(max_tokens, int) and max_tokens > 0:
        requested = body.get("max_tokens")
        try:
            body["max_tokens"] = min(int(requested), max_tokens) if requested is not None else max_tokens
        except (TypeError, ValueError):
            body["max_tokens"] = max_tokens
    return body


def forward_http_json(
    cfg: dict[str, Any],
    payload: dict[str, Any],
    decision: RouteDecision,
    verified: VerifiedAgent,
) -> tuple[int, dict[str, Any]]:
    route = decision.route
    backend = route.get("backend", {})
    if backend.get("dry_run") or str(backend.get("base_url", "")).startswith("mock://"):
        return 200, {"ok": True, "dry_run": True, "route_id": decision.route_id}
    body = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
    url = backend_url(backend, "/")
    headers = backend_headers(cfg, decision, verified, body, backend, urllib.parse.urlsplit(url).path or "/")
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers=headers,
    )
    timeout = float(backend.get("timeout_seconds", 180))
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8", errors="replace")
            parsed = json.loads(raw) if raw.strip() else {}
            if not isinstance(parsed, dict):
                parsed = {"value": parsed}
            return response.status, parsed
    except (socket.timeout, TimeoutError) as exc:
        raise GatewayError(504, "backend_timeout", "backend request timed out") from exc
    except urllib.error.URLError as exc:
        raise GatewayError(502, "backend_error", f"backend request failed: {type(exc).__name__}") from exc


def forward_openai_chat(
    cfg: dict[str, Any],
    payload: dict[str, Any],
    decision: RouteDecision,
    verified: VerifiedAgent,
) -> tuple[int, dict[str, Any]]:
    backend = decision.route.get("backend", {})
    if backend.get("dry_run") or str(backend.get("base_url", "")).startswith("mock://"):
        return 200, openai_response("DRY_RUN: request accepted by Agent Security Gateway but not forwarded.", decision.route_id)
    body_payload = build_openai_backend_payload(payload, decision)
    body = json.dumps(body_payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
    url = backend_url(backend, "/chat/completions")
    headers = backend_headers(cfg, decision, verified, body, backend, urllib.parse.urlsplit(url).path or "/")
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers=headers,
    )
    timeout = float(backend.get("timeout_seconds", 180))
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8", errors="replace")
            parsed = json.loads(raw)
            if not isinstance(parsed, dict):
                raise GatewayError(502, "backend_error", "backend response was not a JSON object")
            return response.status, parsed
    except (socket.timeout, TimeoutError) as exc:
        raise GatewayError(504, "backend_timeout", "backend request timed out") from exc
    except urllib.error.URLError as exc:
        raise GatewayError(502, "backend_error", f"backend request failed: {type(exc).__name__}") from exc


def forward_command(
    payload: dict[str, Any],
    decision: RouteDecision,
) -> tuple[int, dict[str, Any]]:
    route = decision.route
    backend = route.get("backend", {})
    if not bool(route.get("enabled", backend.get("enabled", False))):
        raise GatewayError(403, "route_denied", "command route is disabled")
    command = backend.get("command")
    if not isinstance(command, list) or not command:
        raise GatewayError(502, "backend_error", "command backend has no command")
    input_text = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    try:
        proc = subprocess.run(
            [str(item) for item in command],
            input=input_text,
            text=True,
            capture_output=True,
            timeout=float(backend.get("timeout_seconds", 180)),
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise GatewayError(504, "backend_timeout", "command backend timed out") from exc
    if proc.returncode != 0:
        raise GatewayError(502, "backend_error", "command backend failed")
    return 200, openai_response(proc.stdout.strip(), decision.route_id)


def openai_response(content: str, model: str) -> dict[str, Any]:
    return {
        "id": "chatcmpl-" + uuid.uuid4().hex[:24],
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ],
    }


def output_text_for_route(payload: dict[str, Any], route_kind: str) -> str:
    if route_kind == "openai_chat_completions":
        return security.extract_openai_response_text(payload)
    return json.dumps(payload, ensure_ascii=False, sort_keys=True)


def enforce_output_guard(payload: dict[str, Any], cfg: dict[str, Any], decision: RouteDecision) -> security.ScanResult:
    text = output_text_for_route(payload, str(decision.route.get("kind")))
    scan = security.scan_output_text(text, cfg, None)
    output_policy = decision.route.get("output_policy", {})
    if isinstance(output_policy, dict) and output_policy.get("require_json_object"):
        try:
            parsed = json.loads(text)
            if not isinstance(parsed, dict):
                scan.findings.append(security.Finding("output_guard:not_json_object", 8, "route requires a JSON object output"))
        except json.JSONDecodeError:
            scan.findings.append(security.Finding("output_guard:not_json_object", 8, "route requires a JSON object output"))
        scan.risk_score = sum(f.severity for f in scan.findings)
        scan.blocked = scan.risk_score >= int(cfg.get("output_guard", {}).get("block_risk_score", cfg.get("block_risk_score", 8)))
        scan.requires_review = scan.risk_score >= int(cfg.get("output_guard", {}).get("review_risk_score", cfg.get("review_risk_score", 4)))
    return scan


def output_guard_blocks(scan: security.ScanResult, cfg: dict[str, Any], decision: RouteDecision) -> bool:
    if scan.blocked:
        return True
    output_policy = decision.route.get("output_policy", {})
    if isinstance(output_policy, dict) and output_policy.get("block_on_review") is False:
        return False
    return security.output_guard_blocks(scan, cfg)


def audit_base(
    request_id: str,
    verified: VerifiedAgent | None,
    client_ip: str,
    decision: RouteDecision | None = None,
) -> dict[str, Any]:
    event: dict[str, Any] = {"request_id": request_id, "client_ip": client_ip}
    if verified is not None:
        event.update(
            {
                "agent_id": verified.agent_id,
                "trust_tier": verified.agent.get("trust_tier"),
            }
        )
    if decision is not None:
        event.update(
            {
                "route_id": decision.route_id,
                "route_kind": decision.route.get("kind"),
                "capability": decision.capability,
                "run_id": decision.run_id,
                "task_id": decision.task_id,
                "taint": decision.taint,
                "warnings": decision.warnings,
            }
        )
    return event


def route_report_policy(route: dict[str, Any]) -> dict[str, Any]:
    policy = route.get("report_policy", {})
    return policy if isinstance(policy, dict) else {}


def report_policy_enabled(path: str, decision: RouteDecision, field: str) -> bool:
    if path != "/v1/results":
        return False
    return bool(route_report_policy(decision.route).get(field, False))


def report_policy_notify_on_block(path: str, decision: RouteDecision) -> bool:
    if path != "/v1/results":
        return False
    policy = route_report_policy(decision.route)
    if "notify_on_block" in policy:
        return bool(policy.get("notify_on_block"))
    return bool(policy.get("forward_audit_receipt", False))


def result_audit_receipt(
    *,
    request_id: str,
    verified: VerifiedAgent,
    client_ip: str,
    decision: RouteDecision,
    inbound: security.InboundScan,
    action: ActionGuardResult,
    cfg: dict[str, Any],
    receipt_decision: str,
    reason: str | None = None,
    forward_payload_mode: str = "raw",
    backend_status: int | None = None,
    include_structured_extract: bool = False,
) -> dict[str, Any]:
    receipt: dict[str, Any] = {
        "ok": receipt_decision == "allow",
        "receipt_type": "asg_result_audit",
        "decision": receipt_decision,
        "request_id": request_id,
        "agent_id": verified.agent_id,
        "trust_tier": verified.agent.get("trust_tier"),
        "client_ip": client_ip,
        "route_id": decision.route_id,
        "route_kind": decision.route.get("kind"),
        "capability": decision.capability,
        "run_id": decision.run_id,
        "task_id": decision.task_id,
        "taint": decision.taint,
        "warnings": decision.warnings,
        "content_sha256": inbound.scan.normalized_sha256,
        "content_length": len(inbound.extracted_text),
        "scan": security.public_scan_for_audit(inbound.scan, cfg),
        "action_guard": action.public_dict(),
        "delivery": {
            "forward_payload_mode": forward_payload_mode,
            "raw_report_forwarded": forward_payload_mode == "raw",
        },
    }
    if reason:
        receipt["reason"] = reason
    if backend_status is not None:
        receipt["delivery"]["backend_status"] = backend_status
    if include_structured_extract:
        receipt["structured_extract"] = inbound.structured_extract
    return receipt


def write_audit(cfg: dict[str, Any], event: dict[str, Any]) -> dict[str, Any]:
    return security.AuditLogger(expand_path(str(cfg["audit_log"]))).write(event)


def public_route(route_id: str, route: dict[str, Any]) -> dict[str, Any]:
    item = {"route_id": route_id}
    for field in PUBLIC_ROUTE_FIELDS:
        if field in route:
            item[field] = route[field]
    return item


def readiness_status(cfg: dict[str, Any]) -> dict[str, Any]:
    checks: dict[str, Any] = {
        "config_loaded": isinstance(cfg, dict),
        "routes_present": bool(cfg.get("routes")),
        "audit_parent_writable": False,
        "approval_parent_writable": False,
        "kill_switch_inactive": not expand_path(str(cfg.get("kill_switch_file", DEFAULT_KILL_SWITCH))).exists(),
    }
    audit_parent = expand_path(str(cfg.get("audit_log", DEFAULT_AUDIT_PATH))).parent
    approval_parent = approval_store_path(cfg).parent
    checks["audit_parent_writable"] = audit_parent.exists() and os.access(audit_parent, os.W_OK)
    checks["approval_parent_writable"] = approval_parent.exists() and os.access(approval_parent, os.W_OK)
    return {
        "ok": all(bool(value) for value in checks.values()),
        "app": APP_NAME,
        "version": VERSION,
        "checks": checks,
    }


class GatewayHandler(http.server.BaseHTTPRequestHandler):
    server_version = "AgentSecurityGateway/" + VERSION

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/healthz":
            cfg = self.server.config  # type: ignore[attr-defined]
            self.write_json(
                200,
                {
                    "ok": True,
                    "app": APP_NAME,
                    "version": VERSION,
                    "routes": len(cfg.get("routes") or {}),
                },
            )
            return
        if self.path == "/readyz":
            cfg = self.server.config  # type: ignore[attr-defined]
            ready = readiness_status(cfg)
            self.write_json(200 if ready["ok"] else 503, ready)
            return
        if self.path == "/routes":
            self.handle_routes()
            return
        self.write_json(404, json_error("not_found", "not found", "req_" + uuid.uuid4().hex))

    def do_POST(self) -> None:  # noqa: N802
        if self.path == "/inspect":
            self.handle_inspect()
            return
        if self.path in {"/v1/chat/completions", "/v1/tasks", "/v1/results"}:
            self.handle_routed_request()
            return
        if self.path == "/v1/approvals":
            self.handle_approval()
            return
        self.write_json(404, json_error("not_found", "not found", "req_" + uuid.uuid4().hex))

    def handle_routes(self) -> None:
        cfg = self.server.config  # type: ignore[attr-defined]
        request_id = self.headers.get("X-Request-ID") or "req_" + uuid.uuid4().hex
        client_ip = self.client_address[0]
        try:
            self.check_kill_switch(cfg, request_id, client_ip)
            verified = verify_agent(self.headers, cfg, client_ip)
            visible = []
            allowed_routes = set(str(item) for item in verified.agent.get("allowed_routes") or [])
            for route_id, route in (cfg.get("routes") or {}).items():
                callers = set(str(item) for item in route.get("allowed_callers") or [])
                if route_id in allowed_routes and ("*" in callers or verified.agent_id in callers):
                    visible.append(public_route(route_id, route))
            write_audit(cfg, {"event": "routes", "decision": "allow", **audit_base(request_id, verified, client_ip)})
            self.write_json(200, {"routes": visible, "request_id": request_id})
        except GatewayError as exc:
            self.deny(cfg, exc, request_id, client_ip, None, None)
        except Exception as exc:  # noqa: BLE001
            self.internal_error(cfg, exc, request_id, client_ip)

    def handle_inspect(self) -> None:
        cfg = self.server.config  # type: ignore[attr-defined]
        request_id = self.headers.get("X-Request-ID") or "req_" + uuid.uuid4().hex
        client_ip = self.client_address[0]
        verified: VerifiedAgent | None = None
        try:
            self.check_kill_switch(cfg, request_id, client_ip)
            payload = self.read_json_body(cfg)
            verified = verify_agent(self.headers, cfg, client_ip)
            capability = resolve_capability(self.headers, payload, inspect_default=True)
            if capability != "inspect":
                raise GatewayError(403, "capability_denied", "/inspect requires inspect capability")
            if capability not in set(str(item) for item in verified.agent.get("allowed_capabilities") or []):
                raise GatewayError(403, "capability_denied", f"capability '{capability}' is not allowed for agent '{verified.agent_id}'")
            inbound = scan_inbound(payload, cfg)
            action = action_guard(self.headers, payload)
            event = {
                "event": "inspect",
                "decision": "allow",
                **audit_base(request_id, verified, client_ip),
                "capability": capability,
                "content_sha256": inbound.scan.normalized_sha256,
                "content_length": len(inbound.extracted_text),
                "scan": security.public_scan_for_audit(inbound.scan, cfg),
                "action_guard": action.public_dict(),
                "taint": resolve_taint(payload),
            }
            write_audit(cfg, event)
            self.write_json(
                200,
                {
                    "request_id": request_id,
                    "scan": inbound.scan.public_dict(),
                    "structured_extract": inbound.structured_extract,
                    "action_guard": action.public_dict(),
                },
            )
        except GatewayError as exc:
            self.deny(cfg, exc, request_id, client_ip, verified, None)
        except Exception as exc:  # noqa: BLE001
            self.internal_error(cfg, exc, request_id, client_ip)

    def handle_routed_request(self) -> None:
        cfg = self.server.config  # type: ignore[attr-defined]
        request_id = self.headers.get("X-Request-ID") or "req_" + uuid.uuid4().hex
        client_ip = self.client_address[0]
        verified: VerifiedAgent | None = None
        decision: RouteDecision | None = None
        try:
            self.check_kill_switch(cfg, request_id, client_ip)
            payload = self.read_json_body(cfg)
            verified = verify_agent(self.headers, cfg, client_ip)
            decision = resolve_route_decision(self.headers, payload, cfg)
            self.check_rate_limit(cfg, verified, decision, client_ip)
            enforce_route_policy(verified, decision, cfg)
            enforce_input_policy(payload, decision)
            inbound = scan_inbound_for_route(payload, cfg, decision)
            action = apply_route_action_guard_policy(action_guard(self.headers, payload), decision, payload)
            event = {
                **audit_base(request_id, verified, client_ip, decision),
                "content_sha256": inbound.scan.normalized_sha256,
                "content_length": len(inbound.extracted_text),
                "scan": security.public_scan_for_audit(inbound.scan, cfg),
                "action_guard": action.public_dict(),
            }
            include_receipt_structured = report_policy_enabled(self.path, decision, "include_structured_extract")
            forward_receipt = report_policy_enabled(self.path, decision, "forward_audit_receipt")
            return_receipt = report_policy_enabled(self.path, decision, "return_audit_receipt")
            notify_on_block = report_policy_notify_on_block(self.path, decision)
            if inbound.scan.blocked:
                receipt, delivery = self.maybe_deliver_block_receipt(
                    cfg,
                    request_id,
                    client_ip,
                    verified,
                    decision,
                    inbound,
                    action,
                    "deny",
                    "blocked_by_input_guard",
                    notify_on_block,
                    include_receipt_structured,
                )
                audit_event = {"event": "deny", "reason": "blocked_by_input_guard", **event}
                if delivery is not None:
                    audit_event["receipt_delivery"] = delivery
                write_audit(cfg, audit_event)
                if return_receipt:
                    self.write_json(403, receipt)
                else:
                    self.write_json(403, json_error("blocked_by_input_guard", "request was blocked by input guard", request_id))
                return
            if inbound.scan.requires_review and bool(decision.route.get("input_policy", {}).get("block_on_review", cfg.get("review_policy", {}).get("block_forward", False))):
                receipt, delivery = self.maybe_deliver_block_receipt(
                    cfg,
                    request_id,
                    client_ip,
                    verified,
                    decision,
                    inbound,
                    action,
                    "review_required",
                    "manual_review_required",
                    notify_on_block,
                    include_receipt_structured,
                )
                audit_event = {"event": "review_required", "reason": "manual_review_required", **event}
                if delivery is not None:
                    audit_event["receipt_delivery"] = delivery
                write_audit(cfg, audit_event)
                if return_receipt:
                    self.write_json(403, receipt)
                else:
                    self.write_json(403, json_error("manual_review_required", "request requires manual review", request_id))
                return
            try:
                enforce_action_guard(cfg, decision, verified, action)
            except GatewayError as exc:
                receipt, delivery = self.maybe_deliver_block_receipt(
                    cfg,
                    request_id,
                    client_ip,
                    verified,
                    decision,
                    inbound,
                    action,
                    "deny",
                    exc.code,
                    notify_on_block,
                    include_receipt_structured,
                )
                audit_event = {"event": "deny", "reason": exc.code, **event}
                if delivery is not None:
                    audit_event["receipt_delivery"] = delivery
                write_audit(cfg, audit_event)
                if return_receipt:
                    self.write_json(exc.status, receipt)
                else:
                    self.write_json(exc.status, json_error(exc.code, exc.message, request_id))
                return
            forward_payload_mode = "audit_receipt" if forward_receipt else "raw"
            receipt = result_audit_receipt(
                request_id=request_id,
                verified=verified,
                client_ip=client_ip,
                decision=decision,
                inbound=inbound,
                action=action,
                cfg=cfg,
                receipt_decision="allow",
                forward_payload_mode=forward_payload_mode,
                include_structured_extract=include_receipt_structured,
            )
            forward_payload = receipt if forward_receipt else payload
            upstream_status, upstream = self.forward(forward_payload, cfg, decision, verified)
            output_scan = enforce_output_guard(upstream, cfg, decision)
            if output_guard_blocks(output_scan, cfg, decision):
                write_audit(
                    cfg,
                    {
                        "event": "deny",
                        "reason": "blocked_by_output_guard",
                        **event,
                        "backend_status": upstream_status,
                        "forward_payload_mode": forward_payload_mode,
                        "output_scan": security.public_scan_for_audit(output_scan, cfg),
                    },
                )
                self.write_json(403, json_error("blocked_by_output_guard", "backend output was blocked by output guard", request_id))
                return
            receipt["delivery"]["backend_status"] = upstream_status
            write_audit(
                cfg,
                {
                    "event": "allow",
                    "decision": "forward",
                    **event,
                    "backend_status": upstream_status,
                    "forward_payload_mode": forward_payload_mode,
                    "output_scan": security.public_scan_for_audit(output_scan, cfg),
                },
            )
            self.write_json(200, receipt if return_receipt else upstream)
        except GatewayError as exc:
            extra_event: dict[str, Any] | None = None
            self.deny(cfg, exc, request_id, client_ip, verified, decision, extra_event)
        except Exception as exc:  # noqa: BLE001
            self.internal_error(cfg, exc, request_id, client_ip)

    def handle_approval(self) -> None:
        cfg = self.server.config  # type: ignore[attr-defined]
        request_id = self.headers.get("X-Request-ID") or "req_" + uuid.uuid4().hex
        client_ip = self.client_address[0]
        verified: VerifiedAgent | None = None
        decision: RouteDecision | None = None
        try:
            self.check_kill_switch(cfg, request_id, client_ip)
            payload = self.read_json_body(cfg)
            verified = verify_agent(self.headers, cfg, client_ip)
            decision = resolve_route_decision(self.headers, payload, cfg)
            if decision.route_id != "security.approvals.create":
                raise GatewayError(403, "route_denied", "/v1/approvals requires route 'security.approvals.create'")
            enforce_route_policy(verified, decision, cfg)
            enforce_input_policy(payload, decision)

            required = (
                "approval_id",
                "target_agent_id",
                "target_route_id",
                "target_capability",
                "normalized_action_hash",
                "approved_by",
                "expires_at",
            )
            missing = [field for field in required if not isinstance(payload.get(field), str) or not payload.get(field, "").strip()]
            if missing:
                raise GatewayError(400, "invalid_json", "approval is missing required fields: " + ", ".join(missing))
            approved_categories = payload.get("approved_categories")
            if not isinstance(approved_categories, list) or not approved_categories or not all(
                isinstance(item, str) and item.strip() for item in approved_categories
            ):
                raise GatewayError(400, "invalid_json", "approved_categories must be a non-empty string array")
            approved_category_set = {str(item).strip() for item in approved_categories}
            if not approved_category_set.issubset(APPROVABLE_ACTION_CATEGORIES):
                raise GatewayError(400, "invalid_json", "approved_categories contains a non-approvable category")
            if payload["target_agent_id"] == verified.agent_id:
                raise GatewayError(403, "self_approval_denied", "agents cannot approve their own actions")
            target_agent = (cfg.get("agents") or {}).get(payload["target_agent_id"])
            if not isinstance(target_agent, dict):
                raise GatewayError(400, "invalid_json", "unknown target_agent_id")
            if payload["target_route_id"] not in (cfg.get("routes") or {}):
                raise GatewayError(404, "unknown_route", "unknown target_route_id")
            if payload["target_route_id"] not in set(str(item) for item in target_agent.get("allowed_routes") or []):
                raise GatewayError(403, "route_denied", "target agent is not allowed to use target_route_id")
            if payload["target_capability"] not in set(str(item) for item in target_agent.get("allowed_capabilities") or []):
                raise GatewayError(403, "capability_denied", "target agent is not allowed to use target_capability")
            parse_datetime(payload["expires_at"])
            inbound = scan_inbound(payload, cfg)
            if inbound.scan.blocked:
                raise GatewayError(403, "blocked_by_input_guard", "approval payload was blocked by input guard")
            record = {
                "approval_id": payload["approval_id"],
                "approver_agent_id": verified.agent_id,
                "approver_trust_tier": verified.agent.get("trust_tier"),
                "target_agent_id": payload["target_agent_id"],
                "target_route_id": payload["target_route_id"],
                "target_capability": payload["target_capability"],
                "normalized_action_hash": payload["normalized_action_hash"],
                "approved_categories": sorted(approved_category_set),
                "approved_by": payload["approved_by"],
                "expires_at": payload["expires_at"],
                "created_at": utc_now(),
                "reason": str(payload.get("reason", "")),
            }
            path = approval_store_path(cfg)
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
            try:
                os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
            except FileNotFoundError:
                pass
            write_audit(
                cfg,
                {
                    "event": "approval",
                    "decision": "stored",
                    **audit_base(request_id, verified, client_ip, decision),
                    "approval_id": record["approval_id"],
                    "target_agent_id": record["target_agent_id"],
                    "target_route_id": record["target_route_id"],
                    "target_capability": record["target_capability"],
                    "approved_categories": record["approved_categories"],
                    "scan": security.public_scan_for_audit(inbound.scan, cfg),
                },
            )
            self.write_json(200, {"ok": True, "request_id": request_id, "approval_id": record["approval_id"]})
        except GatewayError as exc:
            self.deny(cfg, exc, request_id, client_ip, verified, decision)
        except Exception as exc:  # noqa: BLE001
            self.internal_error(cfg, exc, request_id, client_ip)

    def forward(
        self,
        payload: dict[str, Any],
        cfg: dict[str, Any],
        decision: RouteDecision,
        verified: VerifiedAgent,
    ) -> tuple[int, dict[str, Any]]:
        kind = str(decision.route.get("kind"))
        if kind == "inspect_only":
            inbound = scan_inbound(payload, cfg)
            return 200, {
                "request_id": self.headers.get("X-Request-ID") or "req_" + uuid.uuid4().hex,
                "route_id": decision.route_id,
                "scan": inbound.scan.public_dict(),
                "structured_extract": inbound.structured_extract,
            }
        if kind == "openai_chat_completions":
            return forward_openai_chat(cfg, payload, decision, verified)
        if kind == "http_json":
            return forward_http_json(cfg, payload, decision, verified)
        if kind == "command":
            return forward_command(payload, decision)
        raise GatewayError(502, "backend_error", f"unsupported route kind: {kind}")

    def deliver_result_audit_receipt(
        self,
        receipt: dict[str, Any],
        cfg: dict[str, Any],
        decision: RouteDecision,
        verified: VerifiedAgent,
    ) -> dict[str, Any]:
        upstream_status, upstream = self.forward(receipt, cfg, decision, verified)
        output_scan = enforce_output_guard(upstream, cfg, decision)
        delivery = {
            "ok": True,
            "backend_status": upstream_status,
            "output_scan": security.public_scan_for_audit(output_scan, cfg),
        }
        if output_guard_blocks(output_scan, cfg, decision):
            raise GatewayError(403, "blocked_by_output_guard", "result audit receipt backend output was blocked by output guard")
        return delivery

    def maybe_deliver_block_receipt(
        self,
        cfg: dict[str, Any],
        request_id: str,
        client_ip: str,
        verified: VerifiedAgent,
        decision: RouteDecision,
        inbound: security.InboundScan,
        action: ActionGuardResult,
        receipt_decision: str,
        reason: str,
        notify_on_block: bool,
        include_structured_extract: bool,
    ) -> tuple[dict[str, Any], dict[str, Any] | None]:
        receipt = result_audit_receipt(
            request_id=request_id,
            verified=verified,
            client_ip=client_ip,
            decision=decision,
            inbound=inbound,
            action=action,
            cfg=cfg,
            receipt_decision=receipt_decision,
            reason=reason,
            forward_payload_mode="audit_receipt" if notify_on_block else "none",
            include_structured_extract=include_structured_extract,
        )
        if not notify_on_block:
            return receipt, None
        try:
            delivery = self.deliver_result_audit_receipt(receipt, cfg, decision, verified)
        except GatewayError as exc:
            delivery = {"ok": False, "error": exc.code, "status": exc.status}
        if "backend_status" in delivery:
            receipt["delivery"]["backend_status"] = delivery["backend_status"]
        if "error" in delivery:
            receipt["delivery"]["error"] = delivery["error"]
        return receipt, delivery

    def check_kill_switch(self, cfg: dict[str, Any], request_id: str, client_ip: str) -> None:
        if expand_path(str(cfg["kill_switch_file"])).exists():
            write_audit(cfg, {"event": "deny", "reason": "kill_switch_active", "request_id": request_id, "client_ip": client_ip})
            raise GatewayError(503, "kill_switch_active", "kill switch is active")

    def check_rate_limit(self, cfg: dict[str, Any], verified: VerifiedAgent, decision: RouteDecision, client_ip: str) -> None:
        allowed, retry_after = security.RATE_LIMITER.check(f"agent:{verified.agent_id}:{client_ip}:{decision.capability}", cfg)
        if not allowed:
            raise GatewayError(429, "rate_limited", f"rate limited; retry after {retry_after} seconds")

    def read_json_body(self, cfg: dict[str, Any]) -> dict[str, Any]:
        length_text = self.headers.get("Content-Length", "0")
        try:
            length = int(length_text)
        except ValueError as exc:
            raise GatewayError(400, "invalid_json", "invalid Content-Length") from exc
        max_body = int(cfg.get("max_body_bytes", 524_288))
        if length < 0 or length > max_body:
            raise GatewayError(413, "request_too_large", "request body is too large")
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise GatewayError(400, "invalid_json", "request body must be valid JSON") from exc
        if not isinstance(payload, dict):
            raise GatewayError(400, "invalid_json", "request body must be a JSON object")
        return payload

    def deny(
        self,
        cfg: dict[str, Any],
        exc: GatewayError,
        request_id: str,
        client_ip: str,
        verified: VerifiedAgent | None,
        decision: RouteDecision | None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        event = {
            "event": "deny",
            "reason": exc.code,
            **audit_base(request_id, verified, client_ip, decision),
        }
        if extra:
            event.update(extra)
        try:
            write_audit(cfg, event)
        except Exception:  # noqa: BLE001 - do not hide the policy response.
            pass
        self.write_json(exc.status, json_error(exc.code, exc.message, request_id))

    def internal_error(self, cfg: dict[str, Any], exc: Exception, request_id: str, client_ip: str) -> None:
        try:
            write_audit(
                cfg,
                {
                    "event": "internal_error",
                    "request_id": request_id,
                    "client_ip": client_ip,
                    "error_type": type(exc).__name__,
                    "traceback_sha256": sha256_text(traceback.format_exc()),
                },
            )
        except Exception:  # noqa: BLE001
            pass
        self.write_json(500, json_error("internal_error", "internal error", request_id))

    def write_json(self, status: int, body: dict[str, Any], extra_headers: dict[str, str] | None = None) -> None:
        encoded = json.dumps(body, ensure_ascii=False, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write("[%s] %s\n" % (utc_now(), fmt % args))


class ThreadingHTTPServer(http.server.ThreadingHTTPServer):
    config: dict[str, Any]


def serve(config_path: Path) -> None:
    cfg = load_config(config_path)
    security.RATE_LIMITER.reset()
    server = ThreadingHTTPServer((str(cfg["bind"]), int(cfg["port"])), GatewayHandler)
    server.config = cfg
    print(f"{APP_NAME} listening on http://{cfg['bind']}:{cfg['port']}", flush=True)
    server.serve_forever()


def generate_agent_token(num_bytes: int) -> dict[str, str]:
    token = secrets.token_urlsafe(num_bytes)
    return {"token": token, "token_sha256": hash_token(token)}


def write_example_config(path: Path) -> None:
    if path.exists():
        raise SystemExit(f"{path} already exists")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as fh:
        json.dump(DEFAULT_CONFIG, fh, ensure_ascii=False, indent=2, sort_keys=True)
        fh.write("\n")
    print(f"wrote {path}")


def inspect_cli(config_path: Path, text: str) -> None:
    cfg = load_config(config_path)
    scan = security.scan_text(text, cfg)
    security.apply_llm_inspector(scan, cfg)
    print(
        json.dumps(
            {
                "scan": scan.public_dict(),
                "structured_extract": security.build_structured_extract(scan, cfg),
                "normalized_text": scan.normalized_text,
            },
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
    )


def validate_config_cli(config_path: Path) -> None:
    cfg = load_config(config_path)
    print(json.dumps({"ok": True, "app": APP_NAME, "config": str(config_path), "routes": len(cfg.get("routes") or {})}, sort_keys=True))


def verify_audit_cli(path: Path) -> None:
    result = security.verify_audit_log(path)
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    if not result["ok"]:
        raise SystemExit(1)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Agent Security Gateway")
    parser.add_argument("--config", type=Path, default=Path(os.environ.get("ASG_CONFIG", DEFAULT_CONFIG_PATH)))
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("serve")
    p_hash = sub.add_parser("hash-token")
    p_hash.add_argument("token")
    p_token = sub.add_parser("generate-token")
    p_token.add_argument("--bytes", type=int, default=32)
    p_init = sub.add_parser("init-config")
    p_init.add_argument("--path", type=Path, default=DEFAULT_CONFIG_PATH)
    p_inspect = sub.add_parser("inspect")
    p_inspect.add_argument("text")
    sub.add_parser("validate-config")
    p_verify = sub.add_parser("verify-audit")
    p_verify.add_argument("--path", type=Path)
    args = parser.parse_args(argv)

    if args.command == "serve":
        serve(args.config)
    elif args.command == "hash-token":
        print(hash_token(args.token))
    elif args.command == "generate-token":
        if args.bytes < 16:
            raise SystemExit("--bytes must be at least 16")
        print(json.dumps(generate_agent_token(args.bytes), ensure_ascii=False, indent=2, sort_keys=True))
        print("Do not put the raw token in config; store only token_sha256 there.", file=sys.stderr)
    elif args.command == "init-config":
        write_example_config(args.path)
    elif args.command == "inspect":
        inspect_cli(args.config, args.text)
    elif args.command == "validate-config":
        validate_config_cli(args.config)
    elif args.command == "verify-audit":
        verify_audit_cli(args.path or expand_path(str(load_config(args.config)["audit_log"])))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
