"""Deterministic canary (honeytoken) detection for Agent Security Gateway.

A canary is a fake secret planted where a real one could be (a decoy credentials file, a decoy wallet, a decoy
bank shortcut). Nothing legitimate ever sends it through ASG, so its appearance anywhere in a request, a backend
response or an artifact means something touched the decoy and tried to move it.

Design rules:
  * Only an HMAC of each canary value is stored (key from an environment variable). Reading the registry reveals nothing
    usable, and ASG never has to hold the decoy text.
  * Matching is exact and deterministic: candidate tokens are extracted from text, HMAC'd and looked up. No LLM.
  * Audit events and responses carry the canary *id*, never the value or the matched text.
  * Responses to a trip are one-way: revoke the calling agent (and optionally raise the global kill switch). Release is a
    separate human action and is never available to agents.
Standard library only.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import threading
import time
from pathlib import Path
from typing import Any, Iterable

CANDIDATE_RE = re.compile(r"[A-Za-z0-9_\-./+=:@~%]{12,512}")
SPLIT_RE = re.compile(r"[/:=@%]+")
MAX_CANDIDATES = 20_000
MAX_STRINGS = 5_000
MAX_DEPTH = 24
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,63}$")
KIND_RE = re.compile(r"^[a-z0-9_]{1,32}$")
KEY_MIN_CHARS = 32

_lock = threading.Lock()
_cache: dict[str, tuple[float, dict[str, dict[str, str]]]] = {}


class CanaryError(Exception):
    """Misconfiguration (missing/short key, unreadable registry). Callers must fail closed."""


def settings(cfg: dict[str, Any]) -> dict[str, Any]:
    value = cfg.get("canary")
    return value if isinstance(value, dict) else {}


def enabled(cfg: dict[str, Any]) -> bool:
    return bool(settings(cfg).get("enabled"))


def _expand(path: str) -> Path:
    return Path(os.path.expandvars(os.path.expanduser(path)))


def registry_path(cfg: dict[str, Any]) -> Path:
    return _expand(str(settings(cfg).get("registry_file", "~/.agent-security-gateway/canaries.jsonl")))


def revoked_path(cfg: dict[str, Any]) -> Path:
    default = str(registry_path(cfg).with_name("revoked-agents.jsonl"))
    return _expand(str(settings(cfg).get("revoked_file", default)))


def hmac_key(cfg: dict[str, Any]) -> bytes:
    env_name = str(settings(cfg).get("hmac_key_env", "ASG_CANARY_HMAC_KEY"))
    key = os.environ.get(env_name, "")
    if len(key) < KEY_MIN_CHARS or re.search(r"\s", key):
        raise CanaryError(f"environment variable {env_name} must hold a key of at least {KEY_MIN_CHARS} characters without whitespace")
    return key.encode("utf-8")


def canary_hmac(key: bytes, value: str) -> str:
    return hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()


def make_entry(key: bytes, value: str, canary_id: str, kind: str) -> dict[str, str]:
    """The record to append to the registry. The value itself is not stored."""
    if not ID_RE.match(canary_id) or not KIND_RE.match(kind):
        raise CanaryError("bad canary id or kind")
    if len(value) < 12:
        raise CanaryError("a canary value must be at least 12 characters")
    return {"id": canary_id, "kind": kind, "hmac": canary_hmac(key, value)}


def load_registry(cfg: dict[str, Any]) -> dict[str, dict[str, str]]:
    path = registry_path(cfg)
    try:
        mtime = path.stat().st_mtime
    except OSError:
        raise CanaryError("canary registry file is not readable") from None
    with _lock:
        cached = _cache.get(str(path))
        if cached and cached[0] == mtime:
            return cached[1]
        entries: dict[str, dict[str, str]] = {}
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                raise CanaryError("canary registry contains an invalid line") from None
            if isinstance(item, dict) and re.fullmatch(r"[0-9a-f]{64}", str(item.get("hmac", ""))) and ID_RE.match(str(item.get("id", ""))):
                entries[item["hmac"]] = {"id": item["id"], "kind": str(item.get("kind", "unknown"))}
        _cache[str(path)] = (mtime, entries)
        return entries


def candidates(text: str) -> Iterable[str]:
    """Plausible token spans: each long run of token characters, and its pieces split on separators."""
    count = 0
    for match in CANDIDATE_RE.finditer(text):
        token = match.group(0).strip(".,;:")
        yield token
        count += 1
        for part in SPLIT_RE.split(token):
            if len(part) >= 12:
                yield part
                count += 1
        if count > MAX_CANDIDATES:
            return


def strings_in(node: Any, depth: int = 0, budget: list[int] | None = None) -> Iterable[str]:
    budget = budget if budget is not None else [MAX_STRINGS]
    if depth > MAX_DEPTH or budget[0] <= 0:
        return
    if isinstance(node, str):
        budget[0] -= 1
        yield node
    elif isinstance(node, dict):
        for key, value in node.items():
            yield from strings_in(str(key), depth + 1, budget)
            yield from strings_in(value, depth + 1, budget)
    elif isinstance(node, (list, tuple)):
        for item in node:
            yield from strings_in(item, depth + 1, budget)


def find(cfg: dict[str, Any], node: Any) -> list[dict[str, str]]:
    """Canaries present anywhere in `node` (a string or nested JSON). Returns [{'id', 'kind'}]. Raises CanaryError if misconfigured."""
    if not enabled(cfg):
        return []
    key = hmac_key(cfg)
    registry = load_registry(cfg)
    if not registry:
        return []
    hits: dict[str, dict[str, str]] = {}
    for text in strings_in(node):
        for token in candidates(text):
            entry = registry.get(canary_hmac(key, token))
            if entry:
                hits[entry["id"]] = entry
    return [hits[k] for k in sorted(hits)]


# ----- revocation (one-way for agents; release is a human action) -------------------------------------------

def _revocations(cfg: dict[str, Any]) -> dict[str, dict[str, Any]]:
    path = revoked_path(cfg)
    state: dict[str, dict[str, Any]] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return state
    for line in lines:
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        agent = item.get("agent_id") if isinstance(item, dict) else None
        if isinstance(agent, str):
            state[agent] = item
    return state


def is_revoked(cfg: dict[str, Any], agent_id: str) -> bool:
    if not enabled(cfg):
        return False
    return _revocations(cfg).get(agent_id, {}).get("action") == "revoke"


def _append(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with _lock, open(path, "a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")


def revoke(cfg: dict[str, Any], agent_id: str, reason: str, canary_ids: list[str]) -> None:
    _append(revoked_path(cfg), {"action": "revoke", "agent_id": agent_id, "reason": reason, "canary_ids": canary_ids,
                                "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})


def release(cfg: dict[str, Any], agent_id: str, note: str = "") -> None:
    """Human-only: the gateway never calls this."""
    _append(revoked_path(cfg), {"action": "release", "agent_id": agent_id, "note": note,
                                "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})


def apply_trip(cfg: dict[str, Any], agent_id: str | None, canary_ids: list[str], source: str, kill_switch_file: Path) -> dict[str, Any]:
    """Actions after a trip, per config `canary.on_trip` (revoke_agent defaults to true, kill_switch to false)."""
    on_trip = settings(cfg).get("on_trip") if isinstance(settings(cfg).get("on_trip"), dict) else {}
    taken: dict[str, Any] = {"revoked_agent": None, "kill_switch": False}
    if agent_id and on_trip.get("revoke_agent", True):
        revoke(cfg, agent_id, f"canary:{source}", canary_ids)
        taken["revoked_agent"] = agent_id
    if on_trip.get("kill_switch", False):
        kill_switch_file.parent.mkdir(parents=True, exist_ok=True)
        kill_switch_file.write_text("canary trip\n", encoding="utf-8")
        taken["kill_switch"] = True
    return taken
