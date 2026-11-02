"""research_service: result filtering, URL eligibility, SSRF guards, quotas, signature checks."""
import datetime as dt
import hashlib
import hmac
import json
import os
import socket
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "setup" / "research-service"))
import research_service as rs  # noqa: E402

KEY = "k" * 40


def cfg(**over):
    c = rs.load_config()
    c.update(over)
    return c


def addrinfo(*ips):
    return lambda host, port, type=0: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port)) for ip in ips]


class UrlPolicyTests(unittest.TestCase):
    def test_rejects_bad_urls(self):
        c = cfg(blocked_hosts=["evil.example"], blocked_url_regex=[r"/exploit-kit/"])
        bad = ["http://a.example/", "https://user:pw@a.example/", "https://a.example:8443/", "https://127.0.0.1/",
               "https://[::1]/", "https://localhost/", "https://a.local/", "https://x.onion/", "https://evil.example/",
               "https://a.example/exploit-kit/x", "ftp://a.example/", "https://a.example/ x", "https://a.example/\x00",
               "https://" + "a" * 2000 + ".example/", None, 5]
        for u in bad:
            self.assertIsNotNone(rs.url_problem(u, c), u)

    def test_accepts_plain_https(self):
        for u in ("https://docs.python.org/3/", "https://A.Example:443/x?y=1", "https://xn--r8jz45g.jp/"):
            self.assertIsNone(rs.url_problem(u, cfg()), u)

    def test_norm_url_drops_fragment_and_default_port(self):
        self.assertEqual(rs.norm_url("https://A.Example:443/p?q=1#frag"), "https://a.example/p?q=1")


class DnsGuardTests(unittest.TestCase):
    def test_private_answer_rejects_whole_host(self):
        for ip in ("10.0.0.5", "192.168.1.80", "127.0.0.1", "169.254.169.254", "100.64.0.1", "::1"):
            with self.assertRaises(rs.Denied) as ctx:
                rs.public_addresses("a.example", addrinfo(ip))
            self.assertEqual(ctx.exception.code, "non_public_address", ip)

    def test_mixed_answers_reject(self):
        with self.assertRaises(rs.Denied):
            rs.public_addresses("a.example", addrinfo("93.184.216.34", "10.0.0.1"))

    def test_public_answer_ok(self):
        self.assertEqual(rs.public_addresses("a.example", addrinfo("93.184.216.34")), ["93.184.216.34"])


class SearchFilterTests(unittest.TestCase):
    def test_filters_dedups_and_cleans(self):
        raw = {"results": [
            {"url": "https://ok.example/a#x", "title": "T\x00itle", "content": "snippet‮"},
            {"url": "https://ok.example/a", "title": "dup"},
            {"url": "http://plain.example/", "title": "http"},
            {"url": "https://127.0.0.1/", "title": "ip"},
            {"url": "https://evil.example/", "title": "blocked"},
            "junk", {"title": "no url"}]}
        out = rs.filter_results(raw, cfg(blocked_hosts=["evil.example"]))
        self.assertEqual([r["url"] for r in out], ["https://ok.example/a"])
        self.assertEqual(out[0]["title"], "Title")
        self.assertNotIn("‮", out[0]["snippet"])

    def test_result_cap_and_garbage_input(self):
        raw = {"results": [{"url": "https://h%d.example/" % i, "title": "t"} for i in range(30)]}
        self.assertEqual(len(rs.filter_results(raw, cfg(max_results=5))), 5)
        self.assertEqual(rs.filter_results(None, cfg()), [])
        self.assertEqual(rs.filter_results({"results": "x"}, cfg()), [])


class RunFlowTests(unittest.TestCase):
    def setUp(self):
        self.cfg = cfg()
        self.reg = rs.Registry(self.cfg)
        self.reg.register("run-1", ["https://seed.example/start"], {"fetches": 3, "hosts": 2})
        self.run = self.reg.get("run-1")

    def page(self, body, status=200, ctype="text/html; charset=utf-8", location=None):
        headers = {"content-type": ctype}
        if location:
            headers["location"] = location
        return lambda url, addrs, cfg: (status, headers, body.encode())

    def fetch(self, url, getter, ips=("93.184.216.34",)):
        return rs.do_fetch(self.run, url, self.cfg, getter=getter, resolver=addrinfo(*ips))

    def test_unregistered_run_denied(self):
        with self.assertRaises(rs.Denied) as ctx:
            self.reg.get("nope")
        self.assertEqual(ctx.exception.code, "run_not_registered")

    def test_fetch_requires_eligible_url(self):
        with self.assertRaises(rs.Denied) as ctx:
            self.fetch("https://random.example/", self.page("x"))
        self.assertEqual(ctx.exception.code, "url_not_eligible")

    def test_seed_fetch_and_link_becomes_eligible(self):
        r = self.fetch("https://seed.example/start", self.page('<title>Hi</title><p>text</p><a href="/next">n</a><a href="http://bad/">b</a>'))
        self.assertEqual(r["title"], "Hi")
        self.assertEqual(r["links"], ["https://seed.example/next"])
        r2 = self.fetch("https://seed.example/next", self.page("<p>second</p>"))
        self.assertIn("second", r2["text"])

    def test_search_results_become_eligible(self):
        out = rs.do_search(self.run, "q", self.cfg, fetcher=lambda q, c: {"results": [{"url": "https://found.example/x", "title": "t"}]})
        self.assertEqual(out["results"][0]["url"], "https://found.example/x")
        self.fetch("https://found.example/x", self.page("ok"))

    def test_private_dns_blocks_fetch(self):
        with self.assertRaises(rs.Denied) as ctx:
            self.fetch("https://seed.example/start", self.page("x"), ips=("10.1.2.3",))
        self.assertEqual(ctx.exception.code, "non_public_address")

    def test_redirect_to_ineligible_host_denied(self):
        with self.assertRaises(rs.Denied) as ctx:
            self.fetch("https://seed.example/start", self.page("", 302, location="https://other.example/"))
        self.assertEqual(ctx.exception.code, "redirect_not_allowed")

    def test_redirect_to_private_ip_literal_denied(self):
        with self.assertRaises(rs.Denied):
            self.fetch("https://seed.example/start", self.page("", 302, location="https://169.254.169.254/latest"))

    def test_same_host_redirect_followed(self):
        calls = []

        def getter(url, addrs, cfg):
            calls.append(url)
            return (302, {"location": "/moved"}, b"") if len(calls) == 1 else (200, {"content-type": "text/plain"}, b"done")
        r = self.fetch("https://seed.example/start", getter)
        self.assertEqual(r["text"], "done")
        self.assertEqual(calls[1], "https://seed.example/moved")

    def test_content_type_denied(self):
        with self.assertRaises(rs.Denied) as ctx:
            self.fetch("https://seed.example/start", self.page("bin", ctype="application/octet-stream"))
        self.assertEqual(ctx.exception.code, "content_type_not_allowed")

    def test_fetch_quota(self):
        for _ in range(3):
            self.fetch("https://seed.example/start", self.page("x"))
        with self.assertRaises(rs.Denied) as ctx:
            self.fetch("https://seed.example/start", self.page("x"))
        self.assertEqual(ctx.exception.code, "fetch_quota_exceeded")

    def test_host_quota(self):
        self.run.eligible.update({"https://b.example/", "https://c.example/"})
        self.fetch("https://b.example/", self.page("x"))  # seed host + b = 2 (limit)
        with self.assertRaises(rs.Denied) as ctx:
            self.fetch("https://c.example/", self.page("x"))
        self.assertEqual(ctx.exception.code, "host_quota_exceeded")

    def test_register_caps_limits_and_drops_bad_seeds(self):
        out = self.reg.register("run-2", ["http://bad/", "https://ok.example/"], {"fetches": 10**9, "unknown": 5, "hosts": True})
        self.assertEqual(out["seeds"], 1)
        self.assertEqual(out["limits"]["fetches"], self.cfg["limit_caps"]["fetches"])
        self.assertEqual(out["limits"]["hosts"], self.cfg["limits"]["hosts"])
        self.assertNotIn("unknown", out["limits"])

    def test_search_quota_and_empty_query(self):
        run = self.reg.get("run-1")
        run.limits["searches"] = 1
        f = lambda q, c: {"results": []}  # noqa: E731
        rs.do_search(run, "a", self.cfg, fetcher=f)
        with self.assertRaises(rs.Denied) as ctx:
            rs.do_search(run, "b", self.cfg, fetcher=f)
        self.assertEqual(ctx.exception.code, "search_quota_exceeded")
        with self.assertRaises(rs.Denied):
            rs.do_search(self.reg.get("run-1"), "\x00 ", self.cfg, fetcher=f)


class AddressRedactionTests(unittest.TestCase):
    def test_non_global_addresses_are_replaced_and_loopback_names_kept(self):
        text = ("http://192.168.1.10:8080/admin http://10.0.0.5/x 172.16.0.1 169.254.169.254 0.0.0.0 "
                "http://[::1]:8080/x [fe80::1%25eth0] [2001:db8::1] fe80::1 ::1 ::ffff:10.0.0.1")
        out = rs.clean_text(text, 1000)
        for leaked in ("192.168", "10.0.0", "172.16", "169.254", "0.0.0.0", "[::1]", "fe80", "2001:db8", "::1 "):
            self.assertNotIn(leaked, out)
        self.assertIn("http://private-address.invalid:8080/admin", out)
        self.assertIn("http://ipv6-address.invalid:8080/x", out)
        kept = rs.clean_text("http://127.0.0.1:3000/ and http://localhost:8080/", 200)
        self.assertEqual(kept, "http://127.0.0.1:3000/ and http://localhost:8080/")

    def test_ordinary_text_is_untouched(self):
        text = "public 8.8.8.8 and 1.2.3.4 version 2.0.1.5 time 12:30:45 std::vector C::D a::b 999.1.1.1 10.0.0.256"
        self.assertEqual(rs.clean_text(text, 500), text)

    def test_replacement_applies_to_titles_snippets_and_page_text(self):
        raw = {"results": [{"url": "https://docs.example.org/a", "title": "Setup on 192.168.0.2", "content": "connect to 10.1.1.1:22"}]}
        hit = rs.filter_results(raw, rs.DEFAULTS)[0]
        self.assertNotRegex(hit["title"] + hit["snippet"], r"192\.168|10\.1\.1")
        title, text, _links = rs.extract_page("<title>host 10.2.3.4</title><p>see http://[::1]:80/</p>", "https://docs.example.org/", "text/html")
        self.assertNotRegex(rs.clean_text(title, 100) + rs.clean_text(text, 100), r"10\.2\.3|\[::1\]")


class SignatureTests(unittest.TestCase):
    def hub_headers(self, raw, path="/fetch", route="fc.fetch", agent="fc_worker@run-1", run="run-1", ts=None, key=KEY):
        ts = ts or dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
        sha = hashlib.sha256(raw).hexdigest()
        sig = hmac.new(key.encode(), rs.canonical("POST", path, sha, agent, route, run, "t1", ts).encode(), hashlib.sha256).hexdigest()
        return {"X-ASG-Request-SHA256": sha, "X-ASG-Agent-Id": agent, "X-ASG-Route-Id": route, "X-ASG-Run-Id": run,
                "X-ASG-Task-Id": "t1", "X-ASG-Timestamp": ts, "X-ASG-Signature": "sha256=" + sig}

    def setUp(self):
        self.c = cfg(allowed_agents=["fc_worker@run-1"])
        p = patch.dict(os.environ, {"ASG_BACKEND_HMAC_KEY": KEY, "ASG_RESEARCH_REGISTER_KEY": "r" * 40})
        p.start()
        self.addCleanup(p.stop)

    def test_run_scoped_identity_with_template_allowlist(self):
        # the hub sends the run-scoped agent id fc_worker@<run_id>; the config lists only the template name
        c = cfg(allowed_agents=["fc_worker"])
        raw = b"{}"
        self.assertEqual(rs.verify_hub_request(self.hub_headers(raw, agent="fc_worker@run-1"), raw, "/fetch", c), ("run-1", "t1"))
        for agent in ("fc_worker@run-2", "fc_worker@", "fc_workerX@run-1", "other@run-1", "@run-1"):
            with self.assertRaises(rs.Denied, msg=agent) as ctx:
                rs.verify_hub_request(self.hub_headers(raw, agent=agent), raw, "/fetch", c)
            self.assertEqual(ctx.exception.code, "caller_not_allowed", agent)

    def test_valid_signature(self):
        raw = b'{"url":"https://a.example/"}'
        self.assertEqual(rs.verify_hub_request(self.hub_headers(raw), raw, "/fetch", self.c), ("run-1", "t1"))

    def test_rejections(self):
        raw = b"{}"
        good = self.hub_headers(raw)
        cases = {
            "tampered body": (good, b'{"x":1}'),
            "wrong key": (self.hub_headers(raw, key="z" * 40), raw),
            "wrong route": (self.hub_headers(raw, route="fc.search"), raw),
            "unlisted agent": (self.hub_headers(raw, agent="intruder"), raw),
            "stale": (self.hub_headers(raw, ts=(dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=10)).isoformat(timespec="seconds")), raw),
            "bad ts": (self.hub_headers(raw, ts="garbage"), raw),
        }
        for name, (h, body) in cases.items():
            with self.assertRaises(rs.Denied, msg=name):
                rs.verify_hub_request(h, body, "/fetch", self.c)

    def test_missing_key_fails_closed(self):
        with patch.dict(os.environ, {"ASG_BACKEND_HMAC_KEY": "short"}):
            with self.assertRaises(rs.Denied) as ctx:
                rs.verify_hub_request(self.hub_headers(b"{}"), b"{}", "/fetch", self.c)
        self.assertEqual(ctx.exception.status, 500)

    def test_register_signature(self):
        raw = b'{"run_id":"run-1"}'
        ts = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
        sig = "sha256=" + hmac.new(b"r" * 40, ts.encode() + b"\n" + raw, hashlib.sha256).hexdigest()
        rs.verify_register({"X-Register-Timestamp": ts, "X-Register-Signature": sig}, raw, self.c)
        with self.assertRaises(rs.Denied):
            rs.verify_register({"X-Register-Timestamp": ts, "X-Register-Signature": "sha256=00"}, raw, self.c)


class HttpLayerTests(unittest.TestCase):
    """Real HTTP server on loopback with a stub SearXNG: signatures, registration, search, fetch, bad input."""

    def setUp(self):
        import http.server
        import threading
        import urllib.request
        self.urllib = urllib.request
        results = {"results": [{"url": "https://found.example/doc", "title": "Doc", "content": "c"},
                               {"url": "http://insecure.example/", "title": "x"}]}

        class Stub(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                data = json.dumps(results).encode()
                self.send_response(200); self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)

            def log_message(self, *a):
                pass
        self.stub = http.server.HTTPServer(("127.0.0.1", 0), Stub)
        threading.Thread(target=self.stub.serve_forever, daemon=True).start()
        self.cfg = cfg(searxng_url="http://127.0.0.1:%d" % self.stub.server_address[1], allowed_agents=["fc_worker"])
        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), rs.make_handler(self.cfg, rs.Registry(self.cfg)))
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.base = "http://127.0.0.1:%d" % self.srv.server_address[1]
        p = patch.dict(os.environ, {"ASG_BACKEND_HMAC_KEY": KEY, "ASG_RESEARCH_REGISTER_KEY": "r" * 40})
        p.start()
        self.addCleanup(p.stop)
        self.addCleanup(self.stub.shutdown)
        self.addCleanup(self.srv.shutdown)

    def call(self, path, payload, signed=True, run="run-1", register=False):
        raw = json.dumps(payload).encode()
        if register:
            ts = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
            headers = {"X-Register-Timestamp": ts, "X-Register-Signature": "sha256=" + hmac.new(b"r" * 40, ts.encode() + b"\n" + raw, hashlib.sha256).hexdigest()}
        elif signed:
            headers = SignatureTests.hub_headers(self, raw, path=path, route={"/search": "fc.search", "/fetch": "fc.fetch"}[path], agent="fc_worker@" + run, run=run)
        else:
            headers = {}
        req = self.urllib.Request(self.base + path, data=raw, method="POST", headers={"Content-Type": "application/json", **headers})
        try:
            with self.urllib.urlopen(req, timeout=10) as r:
                return r.status, json.loads(r.read())
        except Exception as e:  # noqa: BLE001
            return e.code, json.loads(e.read())

    def test_register_search_fetch_roundtrip(self):
        st, out = self.call("/register", {"run_id": "run-1", "seed_urls": ["https://seed.example/"]}, register=True)
        self.assertEqual((st, out["seeds"]), (200, 1))
        st, out = self.call("/search", {"query": "docs"})
        self.assertEqual(st, 200)
        self.assertEqual([r["url"] for r in out["results"]], ["https://found.example/doc"])  # http:// hit filtered out
        with patch.object(rs, "http_get_pinned", lambda url, addrs, cfg: (200, {"content-type": "text/html"}, b"<title>D</title>hello")),                 patch.object(rs, "public_addresses", lambda host, resolver=None: ["93.184.216.34"]):
            st, out = self.call("/fetch", {"url": "https://found.example/doc"})
            self.assertEqual((st, out["text"], out["title"]), (200, "hello", "D"))
            st, out = self.call("/fetch", {"url": "https://never-seen.example/"})
            self.assertEqual((st, out["error"]["code"]), (403, "url_not_eligible"))

    def test_unsigned_and_unregistered_are_denied(self):
        self.assertEqual(self.call("/search", {"query": "q"}, signed=False)[0], 401)
        st, out = self.call("/search", {"query": "q"})  # signed but run never registered
        self.assertEqual((st, out["error"]["code"]), (403, "run_not_registered"))
        self.assertEqual(self.call("/register", {"run_id": "run-1"}, signed=False)[0], 401)

    def test_bad_input_fails_closed(self):
        self.call("/register", {"run_id": "run-1"}, register=True)
        self.assertEqual(self.call("/fetch", {"url": 5})[0], 400)
        self.assertEqual(self.call("/search", {"query": ""})[0], 400)
        self.assertEqual(self.call("/register", {"run_id": "../x"}, register=True)[0], 400)


class ConfigTests(unittest.TestCase):
    def test_unknown_key_rejected(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "c.json"
            p.write_text(json.dumps({"searxng_urll": "x"}), encoding="utf-8")
            with self.assertRaises(ValueError):
                rs.load_config(str(p))


if __name__ == "__main__":
    unittest.main()
