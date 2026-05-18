#!/usr/bin/env python3
"""Initialize a runtime config and token files for Agent Security Proxy."""

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

import proxy  # noqa: E402


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


def build_config(args: argparse.Namespace, local_token: str, external_token: str) -> dict:
    cfg = json.loads(json.dumps(proxy.DEFAULT_CONFIG))
    bind_cidr = f"{args.bind}/32" if args.bind != "127.0.0.1" else "127.0.0.1/32"
    external_cidrs = args.external_cidr or []
    cfg.update(
        {
            "bind": args.bind,
            "port": args.port,
            "audit_log": str(args.runtime_dir / "audit.jsonl"),
            "kill_switch_file": str(args.runtime_dir / "KILL_SWITCH"),
        }
    )
    cfg["target"].update(
        {
            "dry_run": not args.enable_forward,
            "mode": "command",
            "agent_bin": args.agent_bin,
            "source": "agent-security-proxy",
            "toolsets": [],
            "ignore_rules": False,
            "ignore_user_config": False,
            "checkpoints": True,
            "http_model": "backend-agent",
            "forward_raw_content": False,
        }
    )
    cfg["agents"] = {
        "local-agent": {
            "token_sha256": proxy.hash_token(local_token),
            "trust_tier": "local_trusted",
            "allowed_capabilities": ["inspect", "coordination_result", "public_readonly_search", "submit_result"],
            "allowed_client_cidrs": sorted({"127.0.0.1/32", bind_cidr}),
        },
        "external-worker-01": {
            "token_sha256": proxy.hash_token(external_token),
            "trust_tier": "external_readonly",
            "allowed_capabilities": ["inspect", "public_readonly_search", "submit_result", "coordination_result"],
            "allowed_client_cidrs": external_cidrs,
        },
    }
    return cfg


def main() -> int:
    parser = argparse.ArgumentParser(description="Create Agent Security Proxy runtime config.")
    parser.add_argument("--runtime-dir", type=Path, default=Path.home() / ".agent-security-proxy")
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--external-cidr", action="append", default=[])
    parser.add_argument("--enable-forward", action="store_true")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--agent-bin", default="agent")
    args = parser.parse_args()

    args.runtime_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(args.runtime_dir, stat.S_IRWXU)
    (args.runtime_dir / "tokens").mkdir(parents=True, exist_ok=True)
    os.chmod(args.runtime_dir / "tokens", stat.S_IRWXU)
    (args.runtime_dir / "logs").mkdir(parents=True, exist_ok=True)
    os.chmod(args.runtime_dir / "logs", stat.S_IRWXU)

    local_token = load_or_create_token(args.runtime_dir / "tokens" / "local-agent.token", overwrite=args.force)
    external_token = load_or_create_token(args.runtime_dir / "tokens" / "external-worker-01.token", overwrite=args.force)
    cfg = build_config(args, local_token, external_token)

    config_path = args.runtime_dir / "config.json"
    if config_path.exists() and not args.force:
        print(f"kept existing {config_path}")
    else:
        write_private(config_path, json.dumps(cfg, ensure_ascii=False, indent=2, sort_keys=True) + "\n", overwrite=True)
        print(f"wrote {config_path}")

    print(f"runtime_dir={args.runtime_dir}")
    print(f"bind={args.bind}:{args.port}")
    print(f"forward_enabled={args.enable_forward}")
    print("token files are under tokens/ and were not printed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
