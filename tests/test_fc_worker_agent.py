"""Firecracker worker agent helpers: truncation handling (finish_reason=length) and orchestrator limit caps."""
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "setup" / "firecracker-worker"


def load_agent():
    source = (ROOT / "worker_agent.py").read_text(encoding="utf-8").split("\ntry:\n    main()")[0]
    namespace = {"__name__": "worker_agent_under_test"}
    exec(compile(source, "worker_agent.py", "exec"), namespace)  # noqa: S102 - repo file, helpers only (main() not run)
    return namespace


class WorkerAgentTruncationTests(unittest.TestCase):
    def setUp(self):
        self.agent = load_agent()

    def test_complete_action_only_when_json_is_whole(self):
        pc = self.agent["parse_complete_action"]
        self.assertEqual(pc('{"action":"final","answer":"x"}'), {"action": "final", "answer": "x"})
        self.assertEqual(pc('<think>a</think>{"action":"fetch","url":"https://example.com/"}')["action"], "fetch")
        for cut in ('{"action":"final","answer":"abc', "", "<think>still thinking", "plain prose"):
            self.assertIsNone(pc(cut), cut)

    def test_partial_answer_recovers_text(self):
        pa = self.agent["partial_answer"]
        self.assertEqual(pa('{"action":"final","answer":"Rust first appeared\\nin 20'), "Rust first appeared\nin 20")
        self.assertEqual(pa("<think>only reasoning, cut"), "")
        self.assertEqual(pa('{"action":"fetch","url":"https://'), "")
        self.assertEqual(pa("A plain answer that was cut"), "A plain answer that was cut")

    def test_llm_timeout_bounded_by_budget(self):
        t = self.agent["llm_timeout"]
        self.assertEqual(t(5000), 1000)
        self.assertEqual(t(100), 115)
        self.assertEqual(t(-50), 30)

    def test_spawn_worker_timeouts_cover_the_run(self):
        src = (ROOT / "spawn_worker.py").read_text(encoding="utf-8")
        ttl = int(re.search(r"def register\(run_id=None, ttl=(\d+)", src).group(1))
        tmo = int(re.search(r"probe_lan=False, timeout=(\d+)", src).group(1))
        vm = int(re.search(r"ASG_FC_TIMEOUT=(\d+)", (ROOT / "asg-fc-worker").read_text(encoding="utf-8")).group(1))
        self.assertGreater(tmo, vm)
        self.assertGreater(ttl, tmo)

    def test_condense_prompt_and_main_handle_length(self):
        source = (ROOT / "worker_agent.py").read_text(encoding="utf-8")
        self.assertIn('choice.get("finish_reason") == "length"', source)
        self.assertIn("[TRUNCATED:", source)
        self.assertIn("truncated=1", source)
        self.assertIn('"action":"final"', self.agent["CONDENSE"])

    def test_orchestrator_caps(self):
        text = (ROOT / "asg-fc-worker").read_text(encoding="utf-8")
        caps = dict((m[0], (int(m[1]), int(m[2]))) for m in re.findall(r'cap\("(\w+)", (\d+), (\d+)\)', text))
        self.assertEqual(caps["max_tokens"], (32768, 32768))
        self.assertEqual(caps["max_seconds"], (1200, 1800))
        vm = int(re.search(r"ASG_FC_TIMEOUT=(\d+)", text).group(1))
        self.assertGreater(vm, caps["max_seconds"][1])  # VM outlives the longest run
        self.assertLessEqual(caps["max_llm_calls"][1], 6)


class OrchestratorHardeningTests(unittest.TestCase):
    """The orchestrator must load /etc/asg/fc-worker.env as data (never source it as root shell code)
    and must validate the per-run spec with explicit checks (never assert, which python -O drops)."""

    def test_env_file_is_parsed_not_sourced(self):
        text = (ROOT / "asg-fc-worker").read_text(encoding="utf-8")
        self.assertNotIn(". /etc/asg/fc-worker.env", text)
        self.assertIn("load_fc_worker_env", text)
        self.assertIn("env_file_writable_by_others", text)   # root must be the only writer
        self.assertIn("env_dir_writable_by_others", text)    # parent dir must not be writable by others

    def test_spec_validation_uses_explicit_checks(self):
        text = (ROOT / "asg-fc-worker").read_text(encoding="utf-8")
        marker = text.index('ASG_CRED=$CRED python3 - "$RUN/metadata.json"')
        end = text.index("\nP\n", marker)
        segment = text[marker:end]
        self.assertNotRegex(segment, r"(?m)^\s*assert\b")
        self.assertIn("bad(", segment)
        self.assertIn("SystemExit", segment)

    def test_fc_worker_env_example_is_parseable_data(self):
        known = {"ASG_FC_GOLDEN", "ASG_FC_BIN", "ASG_FC_USER", "ASG_FC_GROUP", "ASG_FC_BRIDGE", "ASG_FC_TAP",
                 "ASG_FC_HOST_IP", "ASG_FC_GUEST_IP", "ASG_FC_ASG_PORT", "ASG_FC_RUN_ROOT", "ASG_FC_LOG_DIR",
                 "ASG_FC_KVM_PERMS", "ASG_FC_AGENT", "ASG_FC_MEM_MIB", "ASG_FC_VCPUS", "ASG_FC_TIMEOUT"}
        numeric = {"ASG_FC_ASG_PORT", "ASG_FC_MEM_MIB", "ASG_FC_VCPUS", "ASG_FC_TIMEOUT"}
        seen = set()
        for n, raw in enumerate((ROOT / "fc-worker.env.example").read_text(encoding="utf-8").splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            key, sep, value = line.partition("=")
            self.assertTrue(sep, f"line {n}: no '='")
            self.assertRegex(key, r"^ASG_FC_[A-Z0-9_]+$")
            self.assertIn(key, known, f"line {n}: unknown key {key}")
            value = re.sub(r"\s+#.*$", "", value).strip()
            value = value[1:-1] if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'" else value
            if key in numeric:
                self.assertRegex(value, r"^[0-9]+$", f"line {n}: {key} must be numeric")
            else:
                self.assertRegex(value, r"^[A-Za-z0-9_./:+@%=-]+$", f"line {n}: unsafe value")
            seen.add(key)
        self.assertTrue(seen)


class WorkerAgentRedirectTests(unittest.TestCase):
    """Redirects must be allowlist-checked BEFORE any request is sent (the old post-hoc geturl() check
    still contacted the disallowed host)."""

    def setUp(self):
        self.agent = load_agent()
        self.hosts = {"www.moltbook.com"}

    def handler(self):
        return self.agent["AllowlistRedirectHandler"](self.hosts)

    def test_url_allowed_rules(self):
        ua = self.agent["url_allowed"]
        split = self.agent["urllib"].parse.urlsplit
        self.assertTrue(ua(split("https://www.moltbook.com/a?b=1"), self.hosts))
        self.assertTrue(ua(split("https://www.moltbook.com:443/"), self.hosts))
        self.assertFalse(ua(split("http://www.moltbook.com/"), self.hosts))            # scheme
        self.assertFalse(ua(split("https://evil.example.net/"), self.hosts))          # host
        self.assertFalse(ua(split("https://u:p@www.moltbook.com/"), self.hosts))      # userinfo
        self.assertFalse(ua(split("https://www.moltbook.com:8443/"), self.hosts))     # port
        self.assertFalse(ua(split("https://www.moltbook.com:abc/"), self.hosts))      # malformed port

    def test_disallowed_redirect_target_rejected_before_sending(self):
        import urllib.request
        self.assertRaises(self.agent["RedirectNotAllowed"], self.handler().redirect_request,
                          urllib.request.Request("https://www.moltbook.com/x"), None, 302, "Found",
                          {"location": "http://169.254.169.254/"}, "http://169.254.169.254/")
        self.assertRaises(self.agent["RedirectNotAllowed"], self.handler().redirect_request,
                          urllib.request.Request("https://www.moltbook.com/x"), None, 302, "Found",
                          {"location": "https://evil.example.net:8443/"}, "https://evil.example.net:8443/")

    def test_allowed_redirect_target_is_followed(self):
        import urllib.request
        new = self.handler().redirect_request(
            urllib.request.Request("https://www.moltbook.com/x"), None, 302, "Found",
            {"location": "https://www.moltbook.com/y"}, "https://www.moltbook.com/y")
        self.assertIsNotNone(new)
        self.assertEqual(new.full_url, "https://www.moltbook.com/y")

    def test_fetch_reports_redirect_not_allowed_without_following(self):
        class FakeOpener:
            def __init__(self):
                self.opened = 0

            def open(self, req, timeout):
                self.opened += 1
                raise self.agent_ns["RedirectNotAllowed"]("http://169.254.169.254/")

        opener = FakeOpener()
        opener.agent_ns = self.agent
        original = self.agent["fetch_opener"]
        self.agent["fetch_opener"] = lambda hosts: opener
        try:
            result = self.agent["fetch"]("https://www.moltbook.com/x", self.hosts, 100)
        finally:
            self.agent["fetch_opener"] = original
        self.assertEqual(result["error"], "redirect_not_allowed")

    def test_fetch_rejects_disallowed_initial_url_before_any_request(self):
        class NoOpener:
            def __init__(self):
                self.opened = 0

            def open(self, req, timeout):
                self.opened += 1

        opener = NoOpener()
        original = self.agent["fetch_opener"]
        self.agent["fetch_opener"] = lambda hosts: opener
        try:
            result = self.agent["fetch"]("http://evil.example.net/x", self.hosts, 100)
        finally:
            self.agent["fetch_opener"] = original
        self.assertEqual(result["error"], "not_allowed")
        self.assertEqual(opener.opened, 0)


class SpawnWorkerMcpArgumentTests(unittest.TestCase):
    def test_operator_only_arguments_are_rejected(self):
        import importlib.util
        import io
        import sys
        from unittest import mock
        spec = importlib.util.spec_from_file_location("spawn_worker_under_test", ROOT / "spawn_worker.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        calls = []
        for extra in ({"decoy_file": "/etc/passwd"}, {"test_mode": "input_guard_log_only"}, {"timeout": 1}):
            msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                   "params": {"name": "spawn_worker", "arguments": {"task": "t", **extra}}}
            out = io.StringIO()
            with mock.patch.object(mod, "spawn_worker", side_effect=lambda **kw: calls.append(kw)), \
                    mock.patch.object(sys, "stdin", io.StringIO(json.dumps(msg) + "\n")), mock.patch.object(sys, "stdout", out):
                mod.mcp()
            res = json.loads(out.getvalue())["result"]
            self.assertTrue(res["isError"])
            self.assertIn("unknown_arguments", res["content"][0]["text"])
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
