#!/usr/bin/env python3
"""asgctl operations (phase 2): secrets init, fragment merge, runs register.

Safety rules shared by every command here:
  * Secret values are never printed or logged. Files that hold them are created owner-only and never overwritten.
  * Config changes are dry-run by default; --write makes a timestamped backup first, validates the candidate with
    `gateway.py validate-config`, and only then replaces the file atomically.
  * HTTP calls go to loopback URLs only. Standard library only.
"""
from __future__ import annotations

import argparse
import copy
import getpass
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import gateway  # noqa: E402

NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{1,63}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
PLACEHOLDER_RE = re.compile(r"REPLACE_WITH", re.I)
MERGE_SECTIONS = ("agents", "routes", "runs")
UNION_FIELDS = ("allowed_capabilities", "allowed_routes")
LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}


class OpsError(Exception):
    """A refusal with a stable, secret-free message."""


def emit(obj: dict) -> None:
    print(json.dumps(obj, ensure_ascii=False, indent=2))


# ----- private files ----------------------------------------------------------------------------------------

def make_private(path: Path) -> None:
    if os.name == "nt":
        user = getpass.getuser()
        proc = subprocess.run(["icacls", str(path), "/inheritance:r", "/grant:r", f"{user}:F"],
                              capture_output=True, stdin=subprocess.DEVNULL)
        if proc.returncode != 0:
            raise OpsError("could not restrict file permissions (icacls failed)")
    else:
        os.chmod(path, 0o600)


def write_private_new(path: Path, content: str) -> None:
    """Create a new owner-only file; refuse to overwrite."""
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(content)
    make_private(path)


# ----- secrets init -----------------------------------------------------------------------------------------

def secrets_init(directory: Path, names: list[str], kind: str) -> dict:
    if not names:
        raise OpsError("give at least one --name")
    for name in names:
        if not NAME_RE.match(name):
            raise OpsError(f"bad name {name!r}")
    if len(set(names)) != len(names):
        raise OpsError("duplicate --name")
    results = []
    for name in names:
        path = directory / (f"{name}.token" if kind == "token" else f"{name}.key")
        if path.exists():
            results.append({"name": name, "path": str(path), "status": "exists_not_modified"})
            continue
        value = secrets.token_urlsafe(32 if kind == "token" else 48)
        write_private_new(path, value + "\n")
        entry = {"name": name, "path": str(path), "status": "created"}
        if kind == "token":
            entry["token_sha256"] = gateway.hash_token(value)  # the only value that belongs in config
        results.append(entry)
    return {"kind": kind, "files": results, "note": "secret values are in the files only; move them to the other host yourself"}


# ----- fragment merge ---------------------------------------------------------------------------------------

def substitute_ids(fragment: dict, mapping: dict[str, str]) -> dict:
    """Rename agent ids (e.g. the placeholder 'controller') everywhere an id can appear."""
    if not mapping:
        return fragment

    def rename(value):
        if isinstance(value, str):
            return mapping.get(value, value)
        if isinstance(value, list):
            return [rename(v) for v in value]
        return value

    out = copy.deepcopy(fragment)
    if "agents" in out:
        out["agents"] = {mapping.get(k, k): v for k, v in out["agents"].items()}
    for route in out.get("routes", {}).values():
        if "allowed_callers" in route:
            route["allowed_callers"] = rename(route["allowed_callers"])
    for run in out.get("runs", {}).values():
        if "allowed_callers" in run:
            run["allowed_callers"] = rename(run["allowed_callers"])
    return out


def merge_fragment(config: dict, fragment: dict, token_hashes: dict[str, str]) -> tuple[dict, list[dict], list[str]]:
    """Return (merged, changes, conflicts). Never overwrites an existing differing definition."""
    merged = copy.deepcopy(config)
    changes: list[dict] = []
    conflicts: list[str] = []

    for key, value in fragment.items():
        if key in MERGE_SECTIONS:
            continue
        if key not in merged:
            merged[key] = copy.deepcopy(value)
            changes.append({"op": "add", "path": key})
        elif merged[key] != value:
            conflicts.append(f"{key}: differs from the existing value")

    for section in MERGE_SECTIONS:
        incoming = fragment.get(section, {})
        if not incoming:
            continue
        target = merged.setdefault(section, {})
        for name, definition in incoming.items():
            path = f"{section}.{name}"
            if name not in target:
                new_def = copy.deepcopy(definition)
                if section == "agents":
                    if name in token_hashes:
                        new_def["token_sha256"] = token_hashes[name]
                    if not HEX64_RE.match(str(new_def.get("token_sha256", ""))):
                        conflicts.append(f"{path}: new agent needs a real token hash (--token-sha256 {name}=<hex>)")
                target[name] = new_def
                changes.append({"op": "add", "path": path})
            elif section == "agents":
                existing = target[name]  # keep token, tier and CIDRs; only widen capabilities/routes
                for field in UNION_FIELDS:
                    add = [v for v in definition.get(field, []) if v not in existing.get(field, [])]
                    if add:
                        existing[field] = list(existing.get(field, [])) + add
                        changes.append({"op": "extend", "path": f"{path}.{field}", "added": add})
            elif target[name] != definition:
                conflicts.append(f"{path}: already defined differently")
    leftovers = find_placeholders(merged)
    conflicts.extend(f"{p}: unresolved placeholder" for p in leftovers)
    return merged, changes, conflicts


def find_placeholders(node, prefix: str = "") -> list[str]:
    found = []
    if isinstance(node, dict):
        for k, v in node.items():
            found += find_placeholders(v, f"{prefix}.{k}" if prefix else k)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            found += find_placeholders(v, f"{prefix}[{i}]")
    elif isinstance(node, str) and PLACEHOLDER_RE.search(node):
        found.append(prefix)
    return found


def validate_candidate(path: Path) -> tuple[bool, str]:
    proc = subprocess.run([sys.executable, "-B", str(ROOT / "gateway.py"), "--config", str(path), "validate-config"],
                          capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=60)
    return proc.returncode == 0, (proc.stdout or proc.stderr).strip()[:300]


def fragment_merge(config_path: Path, fragment_path: Path, mapping: dict[str, str], token_hashes: dict[str, str],
                   write: bool, skip_validate: bool = False) -> dict:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    fragment = substitute_ids(json.loads(fragment_path.read_text(encoding="utf-8")), mapping)
    merged, changes, conflicts = merge_fragment(config, fragment, token_hashes)
    report = {"config": str(config_path), "write": write, "changes": changes, "conflicts": conflicts}
    if conflicts:
        report["status"] = "refused"
        return report
    if not write:
        report["status"] = "dry_run"
        return report
    if not changes:
        report["status"] = "nothing_to_do"
        return report
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, suffix=".json", dir=config_path.parent) as tmp:
        json.dump(merged, tmp, indent=2, ensure_ascii=False)
        tmp.write("\n")
        candidate = Path(tmp.name)
    try:
        if not skip_validate:
            ok, message = validate_candidate(candidate)
            report["validate_config"] = {"ok": ok, "detail": message}
            if not ok:
                report["status"] = "refused_invalid_config"
                return report
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup = config_path.with_name(f"{config_path.name}.bak-before-fragment-{stamp}")
        backup.write_bytes(config_path.read_bytes())
        os.replace(candidate, config_path)
        report["backup"] = str(backup)
        report["status"] = "written"
        report["next"] = "restart ASG to load the new config"
    finally:
        if candidate.exists():
            candidate.unlink()
    return report


# ----- runs register ----------------------------------------------------------------------------------------

def runs_register(url: str, token_file: Path, body: dict, route: str = "security.runs.register") -> dict:
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "http" or (parts.hostname or "") not in LOOPBACK_HOSTS:
        raise OpsError("only http://127.0.0.1 / localhost URLs are allowed (use the SSH tunnel)")
    if not token_file.is_file():
        raise OpsError("token file not found")
    token = token_file.read_text(encoding="utf-8").strip()
    if not token:
        raise OpsError("token file is empty")
    request = urllib.request.Request(
        url.rstrip("/") + "/v1/runs", data=json.dumps(body).encode("utf-8"), method="POST",
        headers={"Authorization": f"Bearer {token}", "X-Agent-Capability": "register_run", "X-ASG-Route": route,
                 "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=15) as resp:
            data = json.loads(resp.read(65536).decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            code = json.loads(exc.read(4096).decode("utf-8")).get("error", "")
        except (ValueError, OSError):
            code = ""
        raise OpsError(f"ASG refused the request: http {exc.code} {code}".strip()) from None
    except (OSError, json.JSONDecodeError) as exc:
        raise OpsError(f"request failed: {type(exc).__name__}") from None
    keep = ("run_id", "expires_at", "allowed_routes", "denied_routes", "allowed_callers")
    return {k: data[k] for k in keep if k in data}


# ----- CLI --------------------------------------------------------------------------------------------------

def parse_pairs(items: list[str], what: str) -> dict[str, str]:
    out = {}
    for item in items or []:
        key, sep, value = item.partition("=")
        if not sep or not NAME_RE.match(key) or not value:
            raise OpsError(f"bad {what} {item!r}; expected NAME=VALUE")
        out[key] = value
    return out


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="asgctl")
    sub = ap.add_subparsers(dest="group", required=True)

    sec = sub.add_parser("secrets").add_subparsers(dest="action", required=True).add_parser("init")
    sec.add_argument("--dir", type=Path, required=True)
    sec.add_argument("--name", action="append", default=[])
    sec.add_argument("--kind", choices=["token", "key"], default="token")

    frag = sub.add_parser("fragment").add_subparsers(dest="action", required=True).add_parser("merge")
    frag.add_argument("--into", type=Path, required=True)
    frag.add_argument("--from", dest="source", type=Path, required=True)
    frag.add_argument("--map", action="append", default=[], metavar="OLD=NEW", help="rename an agent id in the fragment")
    frag.add_argument("--token-sha256", action="append", default=[], metavar="AGENT=HEX", help="token hash for a NEW agent")
    frag.add_argument("--write", action="store_true")
    frag.add_argument("--skip-validate", action="store_true")

    runs = sub.add_parser("runs").add_subparsers(dest="action", required=True).add_parser("register")
    runs.add_argument("--url", default="http://127.0.0.1:8788")
    runs.add_argument("--token-file", type=Path, required=True)
    runs.add_argument("--body", type=Path, required=True, help="JSON file, e.g. run-registration.example.json")

    args = ap.parse_args(argv)
    try:
        if args.group == "secrets":
            emit(secrets_init(args.dir, args.name, args.kind))
        elif args.group == "fragment":
            report = fragment_merge(args.into, args.source, parse_pairs(args.map, "--map"),
                                    parse_pairs(args.token_sha256, "--token-sha256"), args.write, args.skip_validate)
            emit(report)
            return 0 if report["status"] in ("dry_run", "written", "nothing_to_do") else 1
        else:
            emit(runs_register(args.url, args.token_file, json.loads(args.body.read_text(encoding="utf-8"))))
    except OpsError as exc:
        print(json.dumps({"status": "error", "error": str(exc)}), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
