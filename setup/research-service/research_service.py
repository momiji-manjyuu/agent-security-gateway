#!/usr/bin/env python3
"""ASG research service: the only internet-facing component of a `researcher` worker run (stdlib only).

Runs on the worker host. The ASG hub reaches it through http_json routes fc.search / fc.fetch; workers never
talk to it directly. Requests from the hub are HMAC-signed (same canonical string the hub uses for every
backend). The orchestrator registers each run (/register, separate key) before the VM boots.

  POST /search    {query}  -> filtered results from a local SearXNG (URL fixed in config, never from a request)
  POST /fetch     {url}    -> page text + links, only for URLs that are eligible for this run
  POST /repo      {repo, action, ...} -> list_tree / read_file / grep over a read-only snapshot of a repository the
                  orchestrator registered for this run (repo_auditor profile; archive from a configured forge only)
  POST /register  {run_id, seed_urls, limits, repos}   (orchestrator only)
  GET  /healthz

A URL is eligible when it is a registered seed, was returned by this run's search, or was linked from a page
this run already fetched. Everything is deterministic: no model decides anything here.

Repositories are never chosen by the worker: the orchestrator registers {forge, owner, repo, ref} per run, the archive
URL comes from the operator's `repo_forges` templates, and the tarball is held in memory (never extracted to disk;
links, devices and unsafe paths are not kept) and served read-only.
"""
import datetime as dt
import hashlib
import hmac
import html
import html.parser
import http.client
import http.server
import io
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import tarfile
import threading
import time
import urllib.parse
import zlib

DEFAULTS = {
    "listen_host": "127.0.0.1", "listen_port": 8790,
    "searxng_url": "http://127.0.0.1:8080",
    "backend_hmac_key_env": "ASG_BACKEND_HMAC_KEY", "register_key_env": "ASG_RESEARCH_REGISTER_KEY",
    "allowed_agents": ["fc_worker"], "route_ids": {"/search": "fc.search", "/fetch": "fc.fetch", "/repo": "fc.repo"},
    "blocked_hosts": [], "blocked_suffixes": [".onion", ".local", ".internal", ".lan", ".localhost"],
    "blocked_url_regex": [],
    "max_results": 8, "snippet_chars": 300, "title_chars": 160, "query_chars": 300,
    "limits": {"searches": 25, "fetches": 60, "bytes": 8 * 1024 * 1024, "hosts": 25, "page_chars": 12000, "links": 40, "repo_calls": 150},
    "limit_caps": {"searches": 60, "fetches": 150, "bytes": 32 * 1024 * 1024, "hosts": 60, "page_chars": 20000, "links": 80, "repo_calls": 400},
    # repo_auditor: forge name -> archive URL template ({owner}, {repo}, {ref}); a null value removes a default forge
    "repo_forges": {"github.com": "https://codeload.github.com/{owner}/{repo}/tar.gz/{ref}"},
    "repo_max_archive_bytes": 25 * 1024 * 1024, "repo_max_uncompressed_bytes": 60 * 1024 * 1024, "repo_max_members": 20000,
    "repo_max_files": 5000, "repo_max_file_bytes": 512 * 1024, "repo_list_entries": 200, "repo_grep_matches": 50, "repo_max_repos": 3,
    "run_ttl_seconds": 4500, "fetch_timeout": 20, "max_page_bytes": 1024 * 1024, "max_redirects": 3,
    "allowed_content_types": ["text/html", "text/plain", "text/markdown", "application/xhtml+xml"],
}
RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,95}$")
CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f  ‪-‮⁦-⁩]")


class Denied(Exception):
    def __init__(self, status, code):
        super().__init__(code)
        self.status, self.code = status, code


def load_config(path=None):
    cfg = json.loads(json.dumps(DEFAULTS))
    if path:
        with open(path, encoding="utf-8-sig") as fh:
            user = json.load(fh)
        for k, v in user.items():
            if k not in cfg:
                raise ValueError("unknown config key: " + k)
            cfg[k] = {**cfg[k], **v} if isinstance(cfg[k], dict) and isinstance(v, dict) else v
    su = urllib.parse.urlsplit(cfg["searxng_url"])
    if su.scheme not in ("http", "https") or not su.hostname:
        raise ValueError("searxng_url invalid")
    cfg["repo_forges"] = {k: v for k, v in cfg["repo_forges"].items() if v is not None}
    for name, tmpl in cfg["repo_forges"].items():
        if not isinstance(tmpl, str) or set(re.findall(r"\{(\w*)\}", tmpl)) - {"owner", "repo", "ref"}:
            raise ValueError("repo_forges template invalid: " + name)
        fu = urllib.parse.urlsplit(tmpl.format(owner="o", repo="r", ref="x"))
        if fu.scheme != "https" or not fu.hostname or fu.username or fu.port not in (None, 443):
            raise ValueError("repo_forges template must be a plain https URL: " + name)
    for rx in cfg["blocked_url_regex"]:
        re.compile(rx)
    return cfg


# Private/loopback/link-local/metadata addresses in page text are replaced before the text leaves this service: the hub's
# guards block a whole request that mentions one, and the worker cannot reach them anyway (fetches go through this service).
# 127.0.0.1 and "localhost" stay: the hub route lists them in input_policy.allowed_private_instruction_hosts.
KEEP_ADDRESSES = frozenset({"127.0.0.1"})
REDACTED_V4 = "private-address.invalid"
REDACTED_V6 = "ipv6-address.invalid"
V4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\w|\.\d)")
V6_BRACKET_RE = re.compile(r"\[([0-9A-Fa-f:.%\w]*:[0-9A-Fa-f:.%\w]*)\]")
V6_BARE_RE = re.compile(r"(?<![0-9A-Za-z:])[0-9A-Fa-f:]{2,45}(?![0-9A-Za-z:])")


def _non_global(ip):
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified


def redact_addresses(text):
    def v4(m):
        try:
            ip = ipaddress.ip_address(m.group(0))
        except ValueError:
            return m.group(0)
        return REDACTED_V4 if _non_global(ip) and str(ip) not in KEEP_ADDRESSES else m.group(0)

    def v6_bracket(m):  # any bracketed IPv6 literal: the hub's URL pattern cannot parse it, and it is never needed in text
        try:
            ipaddress.IPv6Address(m.group(1).split("%", 1)[0])
        except ValueError:
            return m.group(0)
        return REDACTED_V6

    def v6_bare(m):
        if m.group(0).count(":") < 2 or (len(m.group(0)) < 5 and m.group(0) != "::1"):  # skip short look-alikes such as C::D
            return m.group(0)
        try:
            ip = ipaddress.IPv6Address(m.group(0))
        except ValueError:
            return m.group(0)
        mapped = ip.ipv4_mapped
        return REDACTED_V6 if _non_global(ip) or (mapped is not None and _non_global(mapped)) else m.group(0)

    return V6_BARE_RE.sub(v6_bare, V4_RE.sub(v4, V6_BRACKET_RE.sub(v6_bracket, text)))


def clean_text(value, limit):
    return redact_addresses(CTRL_RE.sub("", html.unescape(str(value or "")))).strip()[:limit]


def norm_url(url):
    """Canonical form used for eligibility: no fragment, lower-case host, default port dropped."""
    u = urllib.parse.urlsplit(url)
    host = (u.hostname or "").lower().rstrip(".")
    return urllib.parse.urlunsplit(("https", host, u.path or "/", u.query, ""))


def url_problem(url, cfg):
    """Syntactic/policy check only (no DNS). Returns a short reason string or None when acceptable."""
    if not isinstance(url, str) or len(url) > 1000 or CTRL_RE.search(url) or re.search(r"\s", url):
        return "malformed"
    try:
        u = urllib.parse.urlsplit(url)
        port = u.port
    except ValueError:
        return "malformed"
    host = (u.hostname or "").lower().rstrip(".")
    if u.scheme != "https" or not host:
        return "scheme"
    if u.username is not None or u.password is not None:
        return "userinfo"
    if port not in (None, 443):
        return "port"
    try:
        ipaddress.ip_address(host)
        return "ip_literal"
    except ValueError:
        pass
    if not re.fullmatch(r"[a-z0-9-]+(\.[a-z0-9-]+)+", host):
        return "host"
    if host in {h.lower() for h in cfg["blocked_hosts"]} or any(host.endswith(s) for s in cfg["blocked_suffixes"]):
        return "blocked_host"
    if any(re.search(rx, url) for rx in cfg["blocked_url_regex"]):
        return "blocked_url"
    return None


def public_addresses(host, resolver=None):
    """All A/AAAA answers must be globally routable; any private/special answer rejects the host."""
    try:
        infos = (resolver or socket.getaddrinfo)(host, 443, type=socket.SOCK_STREAM)
    except OSError:
        raise Denied(502, "dns_failed") from None
    addrs = []
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global or ip.is_multicast:
            raise Denied(403, "non_public_address")
        if str(ip) not in addrs:
            addrs.append(str(ip))
    if not addrs:
        raise Denied(502, "dns_failed")
    return addrs


def filter_results(raw, cfg):
    """Drop obviously bad search hits and normalize the rest. Never raises on odd input."""
    out, seen = [], set()
    for item in (raw.get("results") if isinstance(raw, dict) else None) or []:
        if not isinstance(item, dict):
            continue
        url = item.get("url")
        if url_problem(url, cfg):
            continue
        key = norm_url(url)
        if key in seen:
            continue
        seen.add(key)
        out.append({"url": key, "title": clean_text(item.get("title"), cfg["title_chars"]),
                    "snippet": clean_text(item.get("content"), cfg["snippet_chars"])})
        if len(out) >= cfg["max_results"]:
            break
    return out


class LinkParser(html.parser.HTMLParser):
    SKIP = {"script", "style", "noscript", "svg", "head", "template"}

    def __init__(self, base):
        super().__init__(convert_charrefs=True)
        self.base, self.parts, self.links, self.title, self._skip, self._in_title = base, [], [], [], 0, False

    def handle_starttag(self, tag, attrs):
        if tag == "title":
            self._in_title = True
        if tag in self.SKIP:
            self._skip += 1
        if tag == "a":
            href = dict(attrs).get("href")
            if href and len(self.links) < 400:
                self.links.append(urllib.parse.urljoin(self.base, href))

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
        if tag in self.SKIP and self._skip:
            self._skip -= 1

    def handle_data(self, data):
        if self._in_title:
            self.title.append(data)
            return
        if not self._skip:
            self.parts.append(data)


def extract_page(body, base_url, content_type):
    if content_type in ("text/plain", "text/markdown"):
        return "", re.sub(r"\s+", " ", body).strip(), []
    p = LinkParser(base_url)
    try:
        p.feed(body)
        p.close()
    except Exception:  # noqa: BLE001  malformed markup must not kill the request
        pass
    return " ".join(p.title), re.sub(r"\s+", " ", " ".join(p.parts)).strip(), p.links


class RunState:
    def __init__(self, limits, ttl, seeds, repos=None):
        self.limits, self.expires = limits, time.time() + ttl
        self.eligible = {norm_url(s) for s in seeds}
        self.hosts = {urllib.parse.urlsplit(s).hostname for s in seeds}
        self.searches = self.fetches = self.bytes = self.repo_calls = 0
        self.repos = {r["name"]: dict(r, lock=threading.Lock(), snapshot=None) for r in (repos or [])}
        self.lock = threading.Lock()


class Registry:
    def __init__(self, cfg):
        self.cfg, self.runs, self.lock = cfg, {}, threading.Lock()

    def register(self, run_id, seeds, limits, repos=None):
        caps, base = self.cfg["limit_caps"], self.cfg["limits"]
        merged = dict(base)
        for k, v in (limits or {}).items():
            if k in caps and isinstance(v, int) and not isinstance(v, bool) and v > 0:
                merged[k] = min(v, caps[k])
        seeds = [s for s in (seeds or [])[:10] if isinstance(s, str) and not url_problem(s, self.cfg)]
        specs = []
        for raw in (repos or [])[:self.cfg["repo_max_repos"]]:
            spec = repo_spec(raw, self.cfg)
            if spec and spec["name"] not in {x["name"] for x in specs}:
                specs.append(spec)
        with self.lock:
            self._gc()
            self.runs[run_id] = RunState(merged, self.cfg["run_ttl_seconds"], seeds, specs)
        return {"run_id": run_id, "seeds": len(seeds), "repos": len(specs), "limits": merged}

    def _gc(self):
        now = time.time()
        for k in [k for k, r in self.runs.items() if r.expires < now]:
            del self.runs[k]

    def get(self, run_id):
        with self.lock:
            self._gc()
            run = self.runs.get(run_id)
        if run is None:
            raise Denied(403, "run_not_registered")
        return run


def check_eligible(run, url, cfg, strict_host_cap=True):
    reason = url_problem(url, cfg)
    if reason:
        raise Denied(403, "url_" + reason)
    if norm_url(url) not in run.eligible:
        raise Denied(403, "url_not_eligible")
    host = urllib.parse.urlsplit(url).hostname.lower().rstrip(".")
    if strict_host_cap and host not in run.hosts and len(run.hosts) >= run.limits["hosts"]:
        raise Denied(429, "host_quota_exceeded")
    return host


def http_get_pinned(url, addrs, cfg, ctx=None, max_bytes=None, accept="text/html,text/plain;q=0.9"):
    """One GET to a pre-validated IP with TLS verification against the real hostname. No redirect following.
    At most max_bytes + 1 bytes are returned so the caller can tell "too large" from "exactly the cap"."""
    custom_cap, max_bytes = max_bytes is not None, max_bytes or cfg["max_page_bytes"]
    u = urllib.parse.urlsplit(url)
    host = u.hostname
    ctx = ctx or ssl.create_default_context()
    sock = socket.create_connection((addrs[0], 443), timeout=cfg["fetch_timeout"])
    try:
        tls = ctx.wrap_socket(sock, server_hostname=host)
    except Exception:
        sock.close()
        raise
    conn = http.client.HTTPSConnection(host, 443, timeout=cfg["fetch_timeout"])
    conn.sock = tls
    try:
        path = (u.path or "/") + ("?" + u.query if u.query else "")
        conn.request("GET", path, headers={"Host": host, "User-Agent": "asg-research-service/1", "Accept": accept,
                                           "Accept-Encoding": "identity", "Connection": "close"})
        r = conn.getresponse()
        data = r.read(max_bytes + 1)
        return r.status, {k.lower(): v for k, v in r.getheaders()}, data if custom_cap else data[:max_bytes]
    finally:
        conn.close()


def do_fetch(run, url, cfg, getter=None, resolver=None):
    getter = getter or http_get_pinned
    with run.lock:
        if run.fetches >= run.limits["fetches"]:
            raise Denied(429, "fetch_quota_exceeded")
        if run.bytes >= run.limits["bytes"]:
            raise Denied(429, "byte_quota_exceeded")
        host = check_eligible(run, url, cfg)
        run.hosts.add(host)
        run.fetches += 1
    current, hops = url, 0
    while True:
        addrs = public_addresses(urllib.parse.urlsplit(current).hostname, resolver)
        try:
            status, headers, body = getter(current, addrs, cfg)
        except (OSError, ssl.SSLError, http.client.HTTPException):
            raise Denied(502, "fetch_failed") from None
        if status in (301, 302, 303, 307, 308) and headers.get("location"):
            hops += 1
            if hops > cfg["max_redirects"]:
                raise Denied(502, "too_many_redirects")
            nxt = urllib.parse.urljoin(current, headers["location"])
            # a redirect must stay on the same host or go to a URL that is itself eligible for this run
            same_host = (urllib.parse.urlsplit(nxt).hostname or "").lower() == (urllib.parse.urlsplit(current).hostname or "").lower()
            if url_problem(nxt, cfg) or not (same_host or norm_url(nxt) in run.eligible):
                raise Denied(403, "redirect_not_allowed")
            current = nxt
            continue
        break
    ctype = headers.get("content-type", "").split(";")[0].strip().lower()
    if ctype not in cfg["allowed_content_types"]:
        raise Denied(415, "content_type_not_allowed")
    with run.lock:
        run.bytes += len(body)
    charset = re.search(r"charset=([\w-]+)", headers.get("content-type", ""))
    try:
        text_body = body.decode(charset.group(1) if charset else "utf-8", "replace")
    except LookupError:
        text_body = body.decode("utf-8", "replace")
    title, text, raw_links = extract_page(text_body, current, ctype)
    links, seen = [], set()
    for link in raw_links:
        if url_problem(link, cfg):
            continue
        key = norm_url(link)
        if key not in seen:
            seen.add(key)
            links.append(key)
        if len(links) >= run.limits["links"]:
            break
    with run.lock:
        run.eligible.update(links)
        run.eligible.add(norm_url(current))
    return {"url": norm_url(url), "final_url": norm_url(current), "status": status, "title": clean_text(title, 200),
            "text": clean_text(text, run.limits["page_chars"]), "links": links}


# ---- repo_auditor: read-only snapshots of registered repositories -------------------------------------------------------
REPO_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$")
REPO_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_./-]{0,99}$")
FORGE_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{0,60}$")
CODE_CTRL_RE = re.compile("[\x00-\x08\x0b-\x1f\x7f​-‏‪-‮⁦-⁩]")


def clean_code(value, limit):
    """Control/bidi characters removed and non-public addresses redacted; unlike clean_text no HTML unescaping (source code)."""
    return redact_addresses(CODE_CTRL_RE.sub("", str(value or ""))).strip("\n")[:limit]


def repo_spec(raw, cfg):
    """Validate one orchestrator-registered repository ({forge, owner, repo, ref}); None when it is not acceptable."""
    if not isinstance(raw, dict) or set(raw) - {"forge", "owner", "repo", "ref"}:
        return None
    forge, owner, repo, ref = raw.get("forge", "github.com"), raw.get("owner"), raw.get("repo"), raw.get("ref")
    if not all(isinstance(x, str) for x in (forge, owner, repo, ref)) or forge not in cfg["repo_forges"] or not FORGE_RE.match(forge):
        return None
    if not (REPO_NAME_RE.match(owner) and REPO_NAME_RE.match(repo) and REPO_REF_RE.match(ref)) or repo.endswith(".git"):
        return None
    if owner in (".", "..") or repo in (".", "..") or ".." in ref or "//" in ref or ref.endswith(("/", ".")):
        return None
    return {"forge": forge, "owner": owner, "repo": repo, "ref": ref, "name": (owner + "/" + repo).lower()}


def repo_path(value, allow_empty=True):
    """Repository-relative path used only as a dictionary key (never touches the filesystem); hygiene check."""
    if value is None or value == "":
        if allow_empty:
            return ""
        raise Denied(400, "bad_path")
    if not isinstance(value, str) or len(value) > 300 or CODE_CTRL_RE.search(value) or "\\" in value or value.startswith("/"):
        raise Denied(400, "bad_path")
    parts = value.rstrip("/").split("/")
    if any(p in ("", ".", "..") for p in parts) or len(parts) > 30:
        raise Denied(400, "bad_path")
    return "/".join(parts)


class Snapshot:
    def __init__(self):
        self.files = {}     # path -> bytes (text files only)
        self.meta = {}      # path -> (size, kind) for every file: kind text | binary | large
        self.skipped = 0    # links, devices and other non-regular members (never kept)

    def children(self, prefix):
        base = prefix + "/" if prefix else ""
        out = {}
        for path, (size, kind) in self.meta.items():
            if not path.startswith(base):
                continue
            head, sep, _ = path[len(base):].partition("/")
            if sep:
                out.setdefault(head, {"name": head, "type": "dir"})
            else:
                out[head] = {"name": head, "type": "file", "size": size, **({} if kind == "text" else {"kind": kind})}
        return sorted(out.values(), key=lambda e: (e["type"] != "dir", e["name"]))


def load_archive(data, cfg):
    """Read a .tar.gz fully in memory. Unsafe member names reject the archive; links/devices are skipped, never created."""
    snap, declared, members = Snapshot(), 0, 0
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
            for m in tf:
                members += 1
                declared += max(0, m.size)
                if members > cfg["repo_max_members"] or declared > cfg["repo_max_uncompressed_bytes"]:
                    raise Denied(502, "archive_too_large")
                name = m.name
                parts = name.split("/")
                if (name.startswith("/") or "\\" in name or CODE_CTRL_RE.search(name) or len(name) > 400 or len(parts) > 40
                        or any(p in (".", "..") for p in parts) or parts[0] == ""):
                    raise Denied(502, "archive_unsafe_path")
                if m.isdir():
                    continue
                if not m.isreg():
                    snap.skipped += 1
                    continue
                rel = "/".join(p for p in parts[1:] if p)  # the archive's single top-level directory is dropped
                if not rel:
                    continue
                if len(snap.meta) >= cfg["repo_max_files"] and rel not in snap.meta:
                    raise Denied(502, "archive_too_many_files")
                if m.size > cfg["repo_max_file_bytes"]:
                    snap.meta[rel] = (m.size, "large")
                    snap.files.pop(rel, None)
                    continue
                blob = tf.extractfile(m).read(m.size)
                if b"\x00" in blob[:4096]:
                    snap.meta[rel] = (len(blob), "binary")
                    snap.files.pop(rel, None)
                    continue
                snap.files[rel], snap.meta[rel] = blob, (len(blob), "text")
    except Denied:
        raise
    except (tarfile.TarError, EOFError, OSError, zlib.error, ValueError):
        raise Denied(502, "archive_invalid") from None
    if not snap.meta:
        raise Denied(502, "archive_empty")
    return snap


def download_archive(spec, cfg, getter=None, resolver=None):
    getter = getter or http_get_pinned
    url = cfg["repo_forges"][spec["forge"]].format(owner=urllib.parse.quote(spec["owner"], safe=""), repo=urllib.parse.quote(spec["repo"], safe=""),
                                                   ref=urllib.parse.quote(spec["ref"], safe="/"))
    addrs = public_addresses(urllib.parse.urlsplit(url).hostname, resolver)
    try:
        status, _, body = getter(url, addrs, cfg, max_bytes=cfg["repo_max_archive_bytes"], accept="application/gzip, application/x-gzip;q=0.9")
    except (OSError, ssl.SSLError, http.client.HTTPException):
        raise Denied(502, "archive_fetch_failed") from None
    if status == 404:
        raise Denied(404, "repo_not_found")
    if status != 200:
        raise Denied(502, "archive_fetch_failed")
    if len(body) > cfg["repo_max_archive_bytes"]:
        raise Denied(502, "archive_too_large")
    return body


def get_snapshot(spec, cfg, getter=None, resolver=None):
    with spec["lock"]:
        if spec["snapshot"] is None:
            spec["snapshot"] = load_archive(download_archive(spec, cfg, getter, resolver), cfg)
        return spec["snapshot"]


def do_repo(run, payload, cfg, getter=None, resolver=None):
    op = payload.get("op")
    if op not in ("list_tree", "read_file", "grep"):
        raise Denied(400, "bad_op")
    name = payload.get("repo")
    spec = run.repos.get(name.strip().lower()) if isinstance(name, str) else None
    if spec is None:
        raise Denied(403, "repo_not_registered")
    with run.lock:
        if run.repo_calls >= run.limits["repo_calls"]:
            raise Denied(429, "repo_quota_exceeded")
        run.repo_calls += 1
    snap = get_snapshot(spec, cfg, getter, resolver)
    ident = {"repo": spec["owner"] + "/" + spec["repo"], "ref": spec["ref"]}
    if op == "list_tree":
        path = repo_path(payload.get("path"))
        if path in snap.meta:
            raise Denied(400, "not_a_directory")
        entries = snap.children(path)
        if not entries and path:
            raise Denied(404, "path_not_found")
        cap = cfg["repo_list_entries"]
        shown = [dict(e, name=clean_code(e["name"], 200)) for e in entries[:cap]]
        return {**ident, "path": path, "entries": shown, "total_entries": len(entries), "truncated": len(entries) > cap}
    if op == "read_file":
        path = repo_path(payload.get("path"), allow_empty=False)
        if path not in snap.meta:
            raise Denied(404, "path_not_found")
        _, kind = snap.meta[path]
        if kind == "large":
            raise Denied(413, "file_too_large")
        if kind == "binary":
            raise Denied(415, "not_text_file")
        start = payload.get("start_line", 1)
        if isinstance(start, bool) or not isinstance(start, int) or start < 1:
            raise Denied(400, "bad_start_line")
        lines = snap.files[path].decode("utf-8", "replace").split("\n")
        budget, out, n = run.limits["page_chars"], [], start
        while n <= len(lines) and budget > 0:
            line = clean_code(lines[n - 1].rstrip("\r"), 500)
            out.append("%d: %s" % (n, line))
            budget -= len(line) + 8
            n += 1
        return {**ident, "path": path, "start_line": start, "end_line": n - 1 if out else start - 1, "total_lines": len(lines),
                "truncated": n <= len(lines), "next_start_line": n if n <= len(lines) else None, "text": "\n".join(out)}
    pattern = payload.get("pattern")
    if not isinstance(pattern, str) or not 1 <= len(pattern.strip()) <= 200:
        raise Denied(400, "bad_pattern")
    prefix = repo_path(payload.get("path"))
    fold = payload.get("ignore_case", True) is not False
    needle = pattern.lower() if fold else pattern
    base = prefix + "/" if prefix else ""
    matches, scanned, truncated = [], 0, False
    for path in sorted(snap.files):
        if prefix and path != prefix and not path.startswith(base):
            continue
        scanned += 1
        for i, line in enumerate(snap.files[path].decode("utf-8", "replace").split("\n"), 1):
            if needle in (line.lower() if fold else line):
                if len(matches) >= cfg["repo_grep_matches"]:
                    truncated = True
                    break
                matches.append({"path": clean_code(path, 300), "line": i, "text": clean_code(line.rstrip("\r").strip(), 200)})
        if truncated:
            break
    return {**ident, "pattern": clean_text(pattern, 200), "matches": matches, "files_scanned": scanned, "truncated": truncated}


def do_search(run, query, cfg, fetcher=None):
    query = clean_text(query, cfg["query_chars"])
    if not query:
        raise Denied(400, "empty_query")
    with run.lock:
        if run.searches >= run.limits["searches"]:
            raise Denied(429, "search_quota_exceeded")
        run.searches += 1
    raw = (fetcher or searx_query)(query, cfg)
    results = filter_results(raw, cfg)
    with run.lock:
        run.eligible.update(r["url"] for r in results)
    return {"query": query, "results": results}


def searx_query(query, cfg):
    su = urllib.parse.urlsplit(cfg["searxng_url"])
    conn_cls = http.client.HTTPSConnection if su.scheme == "https" else http.client.HTTPConnection
    conn = conn_cls(su.hostname, su.port or (443 if su.scheme == "https" else 80), timeout=cfg["fetch_timeout"])
    try:
        conn.request("GET", (su.path.rstrip("/") or "") + "/search?" + urllib.parse.urlencode({"q": query, "format": "json", "safesearch": "1"}),
                     headers={"Accept": "application/json", "User-Agent": "asg-research-service/1"})
        r = conn.getresponse()
        data = r.read(2 << 20)
        if r.status != 200:
            raise Denied(502, "search_backend_error")
        return json.loads(data.decode("utf-8", "replace"))
    except (OSError, http.client.HTTPException, ValueError):
        raise Denied(502, "search_backend_error") from None
    finally:
        conn.close()


def canonical(method, path, body_sha, agent, route, run_id, task_id, timestamp):
    return "\n".join([method.upper(), path, body_sha, agent, route, run_id, task_id, timestamp])


def agent_allowed(agent, run_id, cfg):
    """Run-scoped workers authenticate as <template>@<run_id>: accept the template name itself, or the template bound to
    exactly the run id the hub put in X-ASG-Run-Id (so one run's identity cannot be replayed for another run)."""
    allowed = set(cfg["allowed_agents"])
    if agent in allowed:
        return True
    base, sep, suffix = agent.partition("@")
    return bool(sep) and base in allowed and suffix == run_id


def verify_hub_request(headers, raw, path, cfg, now=None):
    """Verify the ASG hub's signature. Returns (run_id, task_id). Raises Denied on any mismatch."""
    key = os.environ.get(cfg["backend_hmac_key_env"], "")
    if len(key) < 32:
        raise Denied(500, "service_not_configured")
    body_sha = hashlib.sha256(raw).hexdigest()
    if not hmac.compare_digest(headers.get("X-ASG-Request-SHA256", ""), body_sha):
        raise Denied(401, "bad_body_hash")
    agent, route = headers.get("X-ASG-Agent-Id", ""), headers.get("X-ASG-Route-Id", "")
    run_id, task_id, ts = headers.get("X-ASG-Run-Id", ""), headers.get("X-ASG-Task-Id", ""), headers.get("X-ASG-Timestamp", "")
    if not agent_allowed(agent, run_id, cfg) or route != cfg["route_ids"].get(path) or not RUN_ID_RE.match(run_id):
        raise Denied(403, "caller_not_allowed")
    try:
        when = dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))
        ok_time = when.tzinfo is not None and abs(((now or dt.datetime.now(dt.timezone.utc)) - when).total_seconds()) <= 120
    except ValueError:
        ok_time = False
    if not ok_time:
        raise Denied(401, "bad_timestamp")
    expected = "sha256=" + hmac.new(key.encode(), canonical("POST", path, body_sha, agent, route, run_id, task_id, ts).encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(headers.get("X-ASG-Signature", ""), expected):
        raise Denied(401, "bad_signature")
    return run_id, task_id


def verify_register(headers, raw, cfg, now=None):
    key = os.environ.get(cfg["register_key_env"], "")
    if len(key) < 32:
        raise Denied(500, "service_not_configured")
    ts = headers.get("X-Register-Timestamp", "")
    try:
        when = dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))
        ok_time = when.tzinfo is not None and abs(((now or dt.datetime.now(dt.timezone.utc)) - when).total_seconds()) <= 120
    except ValueError:
        ok_time = False
    if not ok_time:
        raise Denied(401, "bad_timestamp")
    expected = "sha256=" + hmac.new(key.encode(), ts.encode() + b"\n" + raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(headers.get("X-Register-Signature", ""), expected):
        raise Denied(401, "bad_signature")


def make_handler(cfg, registry):
    class Handler(http.server.BaseHTTPRequestHandler):
        server_version = "asg-research/1"
        timeout = 30  # socket timeout for reading the request: a stalled client cannot hold a thread forever

        def log_message(self, fmt, *args):  # no query/URL content in logs
            sys.stderr.write("%s %s\n" % (self.command, urllib.parse.urlsplit(self.path).path))

        def _send(self, status, obj):
            data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            self._send(200, {"ok": True}) if self.path == "/healthz" else self._send(404, {"error": {"code": "not_found"}})

        def do_POST(self):
            try:
                path = urllib.parse.urlsplit(self.path).path
                length = int(self.headers.get("Content-Length", "0"))
                if length < 0 or length > 65536:
                    raise Denied(413, "body_too_large")
                raw = self.rfile.read(length)
                try:
                    payload = json.loads(raw.decode("utf-8")) if raw else {}
                except ValueError:
                    raise Denied(400, "bad_json") from None
                if not isinstance(payload, dict):
                    raise Denied(400, "bad_json")
                hdrs = self.headers  # HTTPMessage: case-insensitive lookups (clients re-case header names, e.g. X-Asg-Run-Id)
                if path == "/register":
                    verify_register(hdrs, raw, cfg)
                    run_id = payload.get("run_id")
                    if not isinstance(run_id, str) or not RUN_ID_RE.match(run_id):
                        raise Denied(400, "bad_run_id")
                    return self._send(200, registry.register(run_id, payload.get("seed_urls"), payload.get("limits"), payload.get("repos")))
                if path not in cfg["route_ids"]:
                    raise Denied(404, "not_found")
                run_id, _ = verify_hub_request(hdrs, raw, path, cfg)
                run = registry.get(run_id)
                if path == "/search":
                    return self._send(200, do_search(run, payload.get("query"), cfg))
                if path == "/repo":
                    return self._send(200, do_repo(run, payload, cfg))
                url = payload.get("url")
                if not isinstance(url, str):
                    raise Denied(400, "bad_url")
                return self._send(200, do_fetch(run, url, cfg))
            except Denied as d:
                sys.stderr.write("  -> %d %s\n" % (d.status, d.code))
                self._send(d.status, {"error": {"code": d.code}})
            except Exception as exc:  # noqa: BLE001  fail closed, no detail to the caller
                sys.stderr.write("  -> 500 %s\n" % type(exc).__name__)
                self._send(500, {"error": {"code": "internal_error"}})
    return Handler


def main(argv):
    cfg = load_config(argv[1] if len(argv) > 1 else os.environ.get("ASG_RESEARCH_CONFIG"))
    if cfg["listen_host"] in ("0.0.0.0", "::", ""):
        raise SystemExit("listen_host must be a specific address (bind to the LAN address the hub uses)")
    srv = http.server.ThreadingHTTPServer((cfg["listen_host"], cfg["listen_port"]), make_handler(cfg, Registry(cfg)))
    srv.daemon_threads = True
    srv.serve_forever()


if __name__ == "__main__":
    main(sys.argv)
