"""Regressions for the remaining 2026-10-24 Lofron review findings (run scope fail-closed, multipart inspection limit)."""
import copy
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import gateway  # noqa: E402
import proxy as security  # noqa: E402


def route_decision(run_id="run-1"):
    route = {"kind": "openai_chat_completions", "required_capability": "chat"}
    return gateway.RouteDecision("r.chat", route, "chat", run_id, "t", [], [])


class RunScopeFailClosedTests(unittest.TestCase):
    def test_unknown_run_id_denied_by_default(self):
        cfg = copy.deepcopy(gateway.DEFAULT_CONFIG)
        self.assertIs(cfg["require_known_run_id"], True)
        with patch.object(gateway, "resolve_run_scope_record", return_value=(None, None)):
            with self.assertRaises(gateway.GatewayError) as ctx:
                gateway.enforce_run_scope(route_decision(), cfg, "agent")
        self.assertEqual(ctx.exception.code, "run_scope_denied")

    def test_malformed_expires_at_is_a_403_not_a_crash(self):
        cfg = copy.deepcopy(gateway.DEFAULT_CONFIG)
        for bad in ("not-a-date", None, 12345):
            with patch.object(gateway, "resolve_run_scope_record", return_value=({"expires_at": bad, "allowed_routes": ["r.chat"]}, "static")):
                with self.assertRaises(gateway.GatewayError) as ctx:
                    gateway.enforce_run_scope(route_decision(), cfg, "agent")
            self.assertEqual(ctx.exception.status, 403, bad)

    def test_naive_expires_at_in_the_past_is_expired(self):
        cfg = copy.deepcopy(gateway.DEFAULT_CONFIG)
        with patch.object(gateway, "resolve_run_scope_record", return_value=({"expires_at": "2000-01-01T00:00:00", "allowed_routes": ["r.chat"]}, "static")):
            with self.assertRaises(gateway.GatewayError) as ctx:
                gateway.enforce_run_scope(route_decision(), cfg, "agent")
        self.assertEqual(ctx.exception.code, "run_expired")


class MultipartInspectionLimitTests(unittest.TestCase):
    def test_truncated_multipart_text_is_an_inspection_limit_finding(self):
        cfg = copy.deepcopy(gateway.DEFAULT_CONFIG)
        cfg.setdefault("normalize", {})["max_content_chars"] = 200
        payload = {"messages": [{"role": "user", "content": [{"type": "text", "text": "a" * 150}, {"type": "text", "text": "b" * 150}]}]}
        with patch.object(security, "extract_content", return_value="short"):  # isolate the multipart path
            result = gateway.action_guard({}, payload, cfg)
        self.assertIn("action_guard:inspection_limit", [f.category for f in result.findings])

    def test_small_multipart_is_not_flagged(self):
        cfg = copy.deepcopy(gateway.DEFAULT_CONFIG)
        payload = {"messages": [{"role": "user", "content": [{"type": "text", "text": "hello "}, {"type": "text", "text": "world"}]}]}
        result = gateway.action_guard({}, payload, cfg)
        self.assertNotIn("action_guard:inspection_limit", [f.category for f in result.findings])


if __name__ == "__main__":
    unittest.main()
