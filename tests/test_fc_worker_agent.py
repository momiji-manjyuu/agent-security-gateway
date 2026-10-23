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

    def test_condense_prompt_and_main_handle_length(self):
        source = (ROOT / "worker_agent.py").read_text(encoding="utf-8")
        self.assertIn('choice.get("finish_reason") == "length"', source)
        self.assertIn("[TRUNCATED:", source)
        self.assertIn("truncated=1", source)
        self.assertIn('"action":"final"', self.agent["CONDENSE"])

    def test_orchestrator_caps(self):
        text = (ROOT / "asg-fc-worker").read_text(encoding="utf-8")
        caps = dict((m[0], (int(m[1]), int(m[2]))) for m in re.findall(r'cap\("(\w+)", (\d+), (\d+)\)', text))
        self.assertEqual(caps["max_tokens"], (3000, 4096))
        self.assertLessEqual(caps["max_seconds"][1], 240)
        self.assertLessEqual(caps["max_llm_calls"][1], 6)


if __name__ == "__main__":
    unittest.main()
