#!/usr/bin/env python3
"""Initialize runtime config and token files for Agent Security Gateway."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import gateway  # noqa: E402


def write_private(path: Path, content: str, *, overwrite: bool) -> None:
    if path.exists() and not overwrite:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


def load_or_create_token(path: Path, *, overwrite: bool) -> str:
    if path.exists() and not overwrite:
        return path.read_text(encoding="utf-8").strip()
    token = secrets.token_urlsafe(32)
    write_private(path, token + "\n", overwrite=True)
    return token


def dry_run_backend(enabled_forward: bool, base_url: str, path: str, api_key_env: str, timeout: int = 60) -> dict:
    if enabled_forward:
        return {
            "mode": "http",
            "base_url": base_url,
            "path": path,
            "api_key_env": api_key_env,
            "timeout_seconds": timeout,
        }
    return {
        "mode": "http",
        "base_url": "mock://dry-run",
        "path": path,
        "api_key_env": api_key_env,
        "timeout_seconds": timeout,
        "dry_run": True,
    }


def build_config(args: argparse.Namespace, mac_token: str, pi_token: str) -> dict:
    cfg = json.loads(json.dumps(gateway.DEFAULT_CONFIG))
    bind_cidr = f"{args.bind}/32" if args.bind != "127.0.0.1" else "127.0.0.1/32"
    external_cidrs = args.external_cidr or []
    cfg.update(
        {
            "bind": args.bind,
            "port": args.port,
            "audit_log": str(args.runtime_dir / "audit.jsonl"),
            "kill_switch_file": str(args.runtime_dir / "KILL_SWITCH"),
            "approval_store": str(args.runtime_dir / "approvals.jsonl"),
        }
    )
    cfg["agents"] = {
        "mac_gpt55": {
            "token_sha256": gateway.hash_token(mac_token),
            "trust_tier": "privileged_core",
            "allowed_capabilities": ["inspect", "delegate_web_research", "search_trusted_knowledge"],
            "allowed_client_cidrs": sorted({"127.0.0.1/32", bind_cidr}),
            "allowed_routes": ["security.inspect_only", "pi.web_research.chat", "ubuntu1.knowledge.search_trusted"],
        },
        "pi_research_1": {
            "token_sha256": gateway.hash_token(pi_token),
            "trust_tier": "web_dmz",
            "allowed_capabilities": ["inspect", "submit_source_card"],
            "allowed_client_cidrs": sorted({"127.0.0.1/32", *external_cidrs}),
            "allowed_routes": ["security.inspect_only", "ubuntu1.knowledge.submit_source_card"],
        },
    }
    cfg["routes"].update(
        {
            "pi.web_research.chat": {
                "kind": "openai_chat_completions",
                "description": "Delegate web research to the Pi web DMZ worker.",
                "aliases": ["asg/pi-web-research"],
                "backend": {
                    **dry_run_backend(args.enable_forward, args.pi_backend_url, "/chat/completions", "PI1_AGENT_BACKEND_KEY", 180),
                    "model_rewrite": "pi-web-research-agent",
                },
                "allowed_callers": ["mac_gpt55"],
                "required_capability": "delegate_web_research",
                "input_policy": {"accepted_taint": ["trusted_instruction"], "allow_missing_taint": False},
                "output_policy": {"block_secrets": True, "block_private_urls": True, "block_internal_paths": True},
            },
            "ubuntu1.knowledge.search_trusted": {
                "kind": "http_json",
                "description": "Search trusted knowledge.",
                "backend": dry_run_backend(args.enable_forward, args.knowledge_backend_url, "/api/search/trusted", "UBUNTU1_KB_BACKEND_KEY", 60),
                "allowed_callers": ["mac_gpt55"],
                "required_capability": "search_trusted_knowledge",
                "input_policy": {"accepted_taint": ["trusted_instruction", "promoted_knowledge"], "allow_missing_taint": False},
                "output_policy": {"block_secrets": True, "block_private_urls": True, "block_internal_paths": True},
            },
            "ubuntu1.knowledge.submit_source_card": {
                "kind": "http_json",
                "description": "Submit source cards into staging.",
                "backend": dry_run_backend(args.enable_forward, args.knowledge_backend_url, "/api/staging/source-card", "UBUNTU1_STAGING_BACKEND_KEY", 60),
                "allowed_callers": ["pi_research_1"],
                "required_capability": "submit_source_card",
                "input_policy": {"accepted_taint": ["untrusted_web"], "allow_missing_taint": False},
                "output_policy": {"block_secrets": True, "block_private_urls": True, "block_internal_paths": True},
            },
        }
    )
    if args.home_lab:
        cfg["runs"]["example-run"] = {
            "user_intent": "example home lab AI research run",
            "allowed_routes": ["pi.web_research.chat", "ubuntu1.knowledge.search_trusted"],
            "denied_routes": [],
            "expires_at": "2099-01-01T00:00:00Z",
        }
    gateway.validate_config(cfg)
    return cfg


def main() -> int:
    parser = argparse.ArgumentParser(description="Create Agent Security Gateway runtime config.")
    parser.add_argument("--runtime-dir", type=Path, default=Path.home() / ".agent-security-gateway")
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8788)
    parser.add_argument("--external-cidr", action="append", default=[])
    parser.add_argument("--enable-forward", action="store_true")
    parser.add_argument("--home-lab", action="store_true")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--pi-backend-url", default="http://pi1-agent.internal:8000/v1")
    parser.add_argument("--knowledge-backend-url", default="http://ubuntu1-knowledge.internal:8801")
    args = parser.parse_args()

    args.runtime_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(args.runtime_dir, stat.S_IRWXU)
    token_dir = args.runtime_dir / "tokens"
    token_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(token_dir, stat.S_IRWXU)

    mac_token = load_or_create_token(token_dir / "mac_gpt55.token", overwrite=args.force)
    pi_token = load_or_create_token(token_dir / "pi_research_1.token", overwrite=args.force)
    cfg = build_config(args, mac_token, pi_token)

    config_path = args.runtime_dir / "config.json"
    if config_path.exists() and not args.force:
        print(f"kept existing {config_path}")
    else:
        write_private(config_path, json.dumps(cfg, ensure_ascii=False, indent=2, sort_keys=True) + "\n", overwrite=True)
        print(f"wrote {config_path}")

    print(f"runtime_dir={args.runtime_dir}")
    print(f"bind={args.bind}:{args.port}")
    print(f"forward_enabled={args.enable_forward}")
    print("token files are under tokens/ and raw token values were not printed")
    print(f"export ASG_CONFIG={config_path}")
    print(f"export ASG_AGENT_TOKEN=\"$(cat {token_dir / 'mac_gpt55.token'})\"")
    print("scripts/start.sh")
    print(f"python3 scripts/smoke_test.py --base-url http://{args.bind}:{args.port}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
