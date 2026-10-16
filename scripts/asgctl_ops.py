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

import canary  # noqa: E402
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
    """Rename placeholder ids (e.g. 'controller'). A value may list several ids (a,b,c) only where a LIST of caller ids
    is renamed; an agent definition (which owns a token) can map to exactly one id."""
    if not mapping:
        return fragment

    def targets(value: str) -> list[str]:
        return [part for part in mapping.get(value, value).split(",") if part]

    def rename_list(values):
        out: list = []
        for value in values:
            if isinstance(value, str):
                for item in targets(value):
                    if item not in out:
                        out.append(item)
            else:
                out.append(value)
        return out

    out = copy.deepcopy(fragment)
    if "agents" in out:
        renamed = {}
        for key, value in out["agents"].items():
            ids = targets(key)
            if len(ids) != 1:
                raise OpsError(f"agent {key!r} cannot map to several ids: each agent owns its own token")
            renamed[ids[0]] = value
        out["agents"] = renamed
    for route in out.get("routes", {}).values():
        if "allowed_callers" in route:
            route["allowed_callers"] = rename_list(route["allowed_callers"])
    for run in out.get("runs", {}).values():
        if "allowed_callers" in run:
            run["allowed_callers"] = rename_list(run["allowed_callers"])
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
                existing = target[name]
                # A route that differs ONLY by caller ids may be widened by adding callers (never removed, never reordered away).
                if (section == "routes" and isinstance(existing, dict) and isinstance(definition, dict)
                        and {k: v for k, v in existing.items() if k != "allowed_callers"} == {k: v for k, v in definition.items() if k != "allowed_callers"}):
                    have = list(existing.get("allowed_callers", []))
                    add = [c for c in definition.get("allowed_callers", []) if c not in have]
                    if add and "*" not in have:
                        existing["allowed_callers"] = have + add
                        changes.append({"op": "extend", "path": f"{path}.allowed_callers", "added": add})
                else:
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
            body = json.loads(exc.read(4096).decode("utf-8")).get("error", "")
            code = body.get("code", "") if isinstance(body, dict) else body  # ASG: {"error": {"code": ...}}
            code = code if isinstance(code, str) and re.fullmatch(r"[a-z0-9_.-]{1,48}", code) else ""
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


# ----- canary (honeytoken) operations -----------------------------------------------------------------------

DECOY_KINDS = {
    "cloud_key": lambda: "AKIA" + "".join(secrets.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") for _ in range(16)),
    "api_key": lambda: "sk-" + "".join(secrets.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(40)),
    "session_token": lambda: secrets.token_hex(24),
    "bank_ref": lambda: "BK-" + "".join(secrets.choice("0123456789ABCDEF") for _ in range(20)),
}


def canary_cfg(config_path: Path) -> dict:
    cfg = json.loads(config_path.read_text(encoding="utf-8"))
    if not canary.settings(cfg):
        raise OpsError("the config has no 'canary' section")
    return cfg


def canary_init(config_path: Path) -> dict:
    cfg = canary_cfg(config_path)
    try:
        canary.hmac_key(cfg)
    except canary.CanaryError as exc:
        raise OpsError(str(exc)) from None
    path = canary.registry_path(cfg)
    created = not path.exists()
    if created:
        write_private_new(path, "")
    return {"registry": str(path), "created": created, "revoked_file": str(canary.revoked_path(cfg)),
            "note": "set canary.enabled=true in the config and restart ASG to start detecting"}


def canary_add(config_path: Path, canary_id: str, kind: str, out: Path) -> dict:
    cfg = canary_cfg(config_path)
    if kind not in DECOY_KINDS:
        raise OpsError(f"unknown kind {kind!r}; choose one of {', '.join(sorted(DECOY_KINDS))}")
    try:
        key = canary.hmac_key(cfg)
        value = DECOY_KINDS[kind]()
        entry = canary.make_entry(key, value, canary_id, kind)
    except canary.CanaryError as exc:
        raise OpsError(str(exc)) from None
    registry = canary.registry_path(cfg)
    if not registry.exists():
        raise OpsError("registry missing; run 'canary init' first")
    if any(canary_id == item["id"] for item in canary.load_registry(cfg).values()):
        raise OpsError(f"canary id {canary_id!r} already exists")
    if out.exists():
        raise OpsError("the decoy output file already exists; refusing to overwrite")
    write_private_new(out, value + "\n")  # the decoy text goes to the file you will plant; it is never printed or stored in the registry
    with open(registry, "a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(entry, sort_keys=True) + "\n")
    return {"id": canary_id, "kind": kind, "decoy_file": str(out), "registry": str(registry),
            "note": "plant the file's content where a real secret could be; ASG already ignores a decoy until it is seen in traffic"}


def canary_list(config_path: Path) -> dict:
    cfg = canary_cfg(config_path)
    entries = sorted(canary.load_registry(cfg).values(), key=lambda e: e["id"])
    revoked = sorted(a for a, rec in canary._revocations(cfg).items() if rec.get("action") == "revoke")
    return {"canaries": entries, "revoked_agents": revoked}


def canary_release(config_path: Path, agent: str, note: str) -> dict:
    if not NAME_RE.match(agent):
        raise OpsError("bad agent id")
    cfg = canary_cfg(config_path)
    canary.release(cfg, agent, note)
    return {"released": agent, "note": "a person released this agent; it is recorded in the append-only revocation file"}


def canary_drill(config_path: Path) -> dict:
    """Prove the detection path works without touching real state: a synthetic canary in a temp registry, in-process."""
    cfg = canary_cfg(config_path)
    try:
        key = canary.hmac_key(cfg)
    except canary.CanaryError as exc:
        raise OpsError(str(exc)) from None
    value = DECOY_KINDS["cloud_key"]()
    with tempfile.TemporaryDirectory() as tmp:
        reg = Path(tmp) / "canaries.jsonl"
        reg.write_text(json.dumps(canary.make_entry(key, value, "drill-synthetic", "cloud_key")) + "\n", encoding="utf-8")
        drill_cfg = {"canary": {"enabled": True, "registry_file": str(reg), "revoked_file": str(Path(tmp) / "rev.jsonl")}}
        shapes = {"plain": value, "env_assignment": f"AWS_ACCESS_KEY_ID={value}", "url": f"https://x.invalid/?k={value}",
                  "nested_json": {"a": [{"b": f"Bearer {value}"}]}}
        results = {name: bool(canary.find(drill_cfg, shape)) for name, shape in shapes.items()}
        clean = not canary.find(drill_cfg, "ordinary text without any decoy")
        before = canary.is_revoked(drill_cfg, "drill-agent")
        canary.revoke(drill_cfg, "drill-agent", "drill", ["drill-synthetic"])
        revoked = canary.is_revoked(drill_cfg, "drill-agent")
        canary.release(drill_cfg, "drill-agent", "drill")
        released = not canary.is_revoked(drill_cfg, "drill-agent")
    ok = all(results.values()) and clean and (not before) and revoked and released
    return {"ok": ok, "detects": results, "no_false_positive_on_clean_text": clean, "revoke_then_release": revoked and released,
            "touched_real_state": False}


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

    can = sub.add_parser("canary").add_subparsers(dest="action", required=True)
    for name in ("init", "add", "list", "release", "drill"):
        sp = can.add_parser(name)
        sp.add_argument("--config", type=Path, required=True, help="ASG config.json (reads only the 'canary' section)")
        if name == "add":
            sp.add_argument("--id", required=True)
            sp.add_argument("--kind", required=True)
            sp.add_argument("--out", type=Path, required=True, help="new file that receives the decoy text to plant")
        if name == "release":
            sp.add_argument("--agent", required=True)
            sp.add_argument("--note", default="")

    args = ap.parse_args(argv)
    try:
        if args.group == "canary":
            action = {"init": lambda: canary_init(args.config), "list": lambda: canary_list(args.config),
                      "drill": lambda: canary_drill(args.config),
                      "add": lambda: canary_add(args.config, args.id, args.kind, args.out),
                      "release": lambda: canary_release(args.config, args.agent, args.note)}[args.action]
            report = action()
            emit(report)
            return 0 if report.get("ok", True) else 1
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
