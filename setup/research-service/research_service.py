#!/usr/bin/env python3
"""ASG research service: the only internet-facing component of a `researcher` worker run (stdlib only).

Runs on the worker host. The ASG hub reaches it through http_json routes fc.search / fc.fetch; workers never
talk to it directly. Requests from the hub are HMAC-signed (same canonical string the hub uses for every
backend). The orchestrator registers each run (/register, separate key) before the VM boots.

  POST /search    {query}  -> filtered results from a local SearXNG (URL fixed in config, never from a request)
  POST /fetch     {url}    -> page text + links, only for URLs that are eligible for this run
  POST /register  {run_id, seed_urls, limits}   (orchestrator only)
  GET  /healthz

A URL is eligible when it is a registered seed, was returned by this run's search, or was linked from a page
this run already fetched. Everything is deterministic: no model decides anything here.
"""
import datetime as dt
import hashlib
import hmac
import html
import html.parser
import http.client
import http.server
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import threading
import time
import urllib.parse

DEFAULTS = {
    "listen_host": "127.0.0.1", "listen_port": 8790,
    "searxng_url": "http://127.0.0.1:8080",
    "backend_hmac_key_env": "ASG_BACKEND_HMAC_KEY", "register_key_env": "ASG_RESEARCH_REGISTER_KEY",
    "allowed_agents": ["fc_worker"], "route_ids": {"/search": "fc.search", "/fetch": "fc.fetch"},
    "blocked_hosts": [], "blocked_suffixes": [".onion", ".local", ".internal", ".lan", ".localhost"],
    "blocked_url_regex": [],
    "max_results": 8, "snippet_chars": 300, "title_chars": 160, "query_chars": 300,
    "limits": {"searches": 25, "fetches": 60, "bytes": 8 * 1024 * 1024, "hosts": 25, "page_chars": 12000, "links": 40},
    "limit_caps": {"searches": 60, "fetches": 150, "bytes": 32 * 1024 * 1024, "hosts": 60, "page_chars": 20000, "links": 80},
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
    for rx in cfg["blocked_url_regex"]:
        re.compile(rx)
    return cfg


def clean_text(value, limit):
    return CTRL_RE.sub("", html.unescape(str(value or ""))).strip()[:limit]


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
    def __init__(self, limits, ttl, seeds):
        self.limits, self.expires = limits, time.time() + ttl
        self.eligible = {norm_url(s) for s in seeds}
        self.hosts = {urllib.parse.urlsplit(s).hostname for s in seeds}
        self.searches = self.fetches = self.bytes = 0
        self.lock = threading.Lock()


class Registry:
    def __init__(self, cfg):
        self.cfg, self.runs, self.lock = cfg, {}, threading.Lock()

    def register(self, run_id, seeds, limits):
        caps, base = self.cfg["limit_caps"], self.cfg["limits"]
        merged = dict(base)
        for k, v in (limits or {}).items():
            if k in caps and isinstance(v, int) and not isinstance(v, bool) and v > 0:
                merged[k] = min(v, caps[k])
        seeds = [s for s in (seeds or [])[:10] if not url_problem(s, self.cfg)]
        with self.lock:
            self._gc()
            self.runs[run_id] = RunState(merged, self.cfg["run_ttl_seconds"], seeds)
        return {"run_id": run_id, "seeds": len(seeds), "limits": merged}

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


def http_get_pinned(url, addrs, cfg, ctx=None):
    """One GET to a pre-validated IP with TLS verification against the real hostname. No redirect following."""
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
        conn.request("GET", path, headers={"Host": host, "User-Agent": "asg-research-service/1", "Accept": "text/html,text/plain;q=0.9",
                                           "Accept-Encoding": "identity", "Connection": "close"})
        r = conn.getresponse()
        data = r.read(cfg["max_page_bytes"] + 1)
        return r.status, {k.lower(): v for k, v in r.getheaders()}, data[:cfg["max_page_bytes"]]
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
                    return self._send(200, registry.register(run_id, payload.get("seed_urls"), payload.get("limits")))
                if path not in cfg["route_ids"]:
                    raise Denied(404, "not_found")
                run_id, _ = verify_hub_request(hdrs, raw, path, cfg)
                run = registry.get(run_id)
                if path == "/search":
                    return self._send(200, do_search(run, payload.get("query"), cfg))
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
