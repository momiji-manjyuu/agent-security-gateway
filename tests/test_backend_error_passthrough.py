"""backend.passthrough_error_codes: opt-in, allowlisted surfacing of http_json backend rejection codes."""
import copy
import http.server
import json
import sys
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import gateway  # noqa: E402


class Backend(http.server.BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        status, raw = self.server.reply
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, fmt, *args):
        return


class PassthroughTests(unittest.TestCase):
    def setUp(self):
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Backend)
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 2)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.base = "http://%s:%d" % self.server.server_address

    def call(self, status, body, allowed=("url_not_eligible", "fetch_quota_exceeded")):
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.server.reply = (status, raw)
        backend = {"mode": "http", "base_url": self.base, "path": "/fetch", "timeout_seconds": 5}
        if allowed is not None:
            backend["passthrough_error_codes"] = list(allowed)
        route = {"kind": "http_json", "backend": backend}
        decision = gateway.RouteDecision("fc.fetch", route, "worker_fetch", "run-1", "t", [], [])
        try:
            gateway.forward_http_json(copy.deepcopy(gateway.DEFAULT_CONFIG), {"url": "https://x.example/"}, decision,
                                      SimpleNamespace(agent_id="fc_worker@run-1"))
        except gateway.GatewayError as exc:
            return exc
        self.fail("expected GatewayError")

    def test_listed_code_is_surfaced_with_prefix_and_status(self):
        exc = self.call(403, {"error": {"code": "url_not_eligible"}})
        self.assertEqual((exc.status, exc.code), (403, "backend_url_not_eligible"))
        self.assertEqual(exc.audit_extra, {"backend_status": 403, "backend_code": "url_not_eligible"})
        exc = self.call(429, {"error": {"code": "fetch_quota_exceeded"}})
        self.assertEqual((exc.status, exc.code), (429, "backend_fetch_quota_exceeded"))

    def test_default_stays_opaque(self):
        exc = self.call(403, {"error": {"code": "url_not_eligible"}}, allowed=None)
        self.assertEqual((exc.status, exc.code), (502, "backend_error"))

    def test_only_message_text_is_gateway_authored(self):
        exc = self.call(403, {"error": {"code": "url_not_eligible", "message": "SECRET internal detail", "trace": "x"}})
        self.assertNotIn("SECRET", exc.message)
        self.assertNotIn("SECRET", json.dumps(exc.audit_extra))

    def test_unlisted_malformed_or_oversized_stay_opaque(self):
        cases = {
            "unlisted code": (403, {"error": {"code": "non_public_address"}}),
            "code not a string": (403, {"error": {"code": ["url_not_eligible"]}}),
            "no error object": (403, {"code": "url_not_eligible"}),
            "not json": (403, b"<html>nope</html>"),
            "oversized body": (403, json.dumps({"error": {"code": "url_not_eligible"}, "pad": "x" * 6000}).encode()),
            "5xx": (500, {"error": {"code": "url_not_eligible"}}),
            "auth status": (401, {"error": {"code": "url_not_eligible"}}),
        }
        for name, (status, body) in cases.items():
            exc = self.call(status, body)
            self.assertEqual((exc.status, exc.code), (502, "backend_error"), name)

    def test_case_and_shape_of_code_must_match_allowlist_exactly(self):
        exc = self.call(403, {"error": {"code": "URL_NOT_ELIGIBLE"}}, allowed=("URL_NOT_ELIGIBLE",))
        self.assertEqual(exc.code, "backend_error")  # uppercase is never a valid code shape

    def test_config_validation(self):
        base = {"kind": "http_json", "backend": {"mode": "http", "base_url": "http://127.0.0.1:9", "method": "POST"},
                "allowed_callers": ["a"], "required_capability": "c"}

        def errors(codes, kind="http_json"):
            cfg = copy.deepcopy(gateway.DEFAULT_CONFIG)
            route = copy.deepcopy(base)
            route["kind"] = kind
            route["backend"]["passthrough_error_codes"] = codes
            cfg["routes"]["x.tool"] = route
            try:
                gateway.validate_config(cfg)
            except ValueError as exc:
                return str(exc)
            return ""

        self.assertEqual(errors(["url_not_eligible"]), "")
        for bad in ([], "url_not_eligible", ["Bad"], ["x"], [1], ["a b c"], ["a" * 41]):
            self.assertIn("passthrough_error_codes must be", errors(bad), bad)
        self.assertIn("only valid on http_json", errors(["url_not_eligible"], kind="openai_chat_completions"))


if __name__ == "__main__":
    unittest.main()
