"""Fixed-function public HTTPS collector. No LLM, shell, callbacks or tools.

Runs as a bounded host subprocess, BEFORE the untrusted worker starts.
Private-address rejection is complemented by pinning the validated IP to TLS.
"""
import http.client
import ipaddress
import os
import re
import socket
import ssl
import sys
from pathlib import Path
from urllib.parse import quote, urlencode, urlsplit, urlunsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
from contract import (MAX_DOCUMENT_CHARS, MAX_WIRE_BYTES, encode, load_json,
                      require, validate_task)

MAX_BODY = 262_144


def parse_public_url(url, allowed_hosts=()):
    require(type(url) is str and 0 < len(url) <= 2048)
    require(not any(ord(c) < 33 or ord(c) == 127 for c in url) and "\\" not in url)
    parsed = urlsplit(url)
    require(parsed.scheme == "https" and parsed.port in (None, 443))
    require(parsed.username is None and parsed.password is None and parsed.hostname)
    host = parsed.hostname.encode("idna").decode("ascii").lower()
    require(len(host) <= 253 and not host.endswith("."))
    require(re.fullmatch(r"[a-z0-9]+(?:[.-][a-z0-9-]+)+", host) is not None)
    require(not allowed_hosts or host in allowed_hosts)  # Exact host, no suffix match.
    target = quote(parsed.path or "/", safe="/%:@!$&'()*+,;=-._~")
    if parsed.query:
        target += "?" + quote(parsed.query, safe="%=&/:?@!$'()*+,;~-._")
    return host, target, urlunsplit(("https", host, target, "", ""))


def public_addresses(host):
    records = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    require(bool(records))
    addresses = []
    for family, socktype, proto, _, addr in records:
        ip = ipaddress.ip_address(addr[0])
        require(ip.is_global and not ip.is_multicast)
        require(not isinstance(ip, ipaddress.IPv6Address) or
                (ip.ipv4_mapped is None and ip.sixtofour is None and ip.teredo is None))
        if isinstance(ip, ipaddress.IPv6Address):
            require(ip not in ipaddress.ip_network("64:ff9b::/96") and
                    ip not in ipaddress.ip_network("64:ff9b:1::/48"))
        # Reject all answers if even one points into a private/special network.
        addresses.append((family, socktype, proto, addr))
    return sorted(addresses, key=lambda item: item[0] != socket.AF_INET)


class PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, address):
        super().__init__(host, timeout=8, context=ssl.create_default_context())
        self.address = address

    def connect(self):
        family, socktype, proto, addr = self.address
        raw = socket.socket(family, socktype, proto)
        raw.settimeout(self.timeout)
        try:
            raw.connect(addr)  # Numeric sockaddr; no second DNS resolution.
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


def get_public(url, allowed_hosts=(), search_token=None):
    host, target, normalized = parse_public_url(url, allowed_hosts)
    addresses = public_addresses(host)
    conn = PinnedHTTPS(host, addresses[0])
    headers = {"User-Agent": "DisposableResearchTemplate/1.0",
               "Accept-Encoding": "identity", "Accept": "text/html, text/plain"}
    if search_token:
        require(host == "api.search.brave.com" and target.startswith("/res/v1/web/search?"))
        headers["X-Subscription-Token"] = search_token
        headers["Accept"] = "application/json"
    try:
        conn.request("GET", target, headers=headers)
        response = conn.getresponse()
        # Redirects are never followed, including on the credentialed endpoint.
        require(response.status == 200)
        require(response.getheader("Content-Encoding", "identity").lower() == "identity")
        data = response.read(MAX_BODY + 1)
        require(len(data) <= MAX_BODY)
        kind = response.getheader("Content-Type", "").split(";", 1)[0].lower().strip()
        require(kind in ({"application/json"} if search_token else {"text/html", "text/plain", "text/markdown"}))
        return normalized, kind, data
    finally:
        conn.close()


def collect(task):
    validate_task(task)
    urls = list(task.get("urls", []))
    if task.get("search", False):
        key = os.environ.get("BRAVE_API_KEY", "")
        require(bool(key))
        query = urlencode({"q": task["question"], "count": task.get("max_sources", 5)})
        _, _, raw = get_public("https://api.search.brave.com/res/v1/web/search?" + query,
                               search_token=key)
        data = load_json(raw)
        results = data.get("web", {}).get("results", [])
        require(type(results) is list)
        for result in results[:5]:
            if type(result) is dict and type(result.get("url")) is str:
                urls.append(result["url"])
    documents, failures, seen = [], 0, set()
    for url in urls[:10]:
        if url in seen:
            continue
        seen.add(url)
        if len(documents) >= task.get("max_sources", 5):
            break
        try:
            normalized, kind, raw = get_public(url, task.get("allowed_hosts", []))
            documents.append({"source_id": f"s{len(documents) + 1}", "url": normalized,
                              "content_type": kind,
                              "content": raw.decode("utf-8", errors="replace")[:MAX_DOCUMENT_CHARS]})
        except Exception:
            failures += 1
    return {"version": 1, "question": task["question"], "documents": documents,
            "fetch_failures": failures}


if __name__ == "__main__":
    try:
        sys.stdout.buffer.write(encode(collect(load_json(sys.stdin.buffer.read(MAX_WIRE_BYTES + 1)))))
    except Exception:
        sys.stderr.write("collection_failed\n")
        raise SystemExit(1)
